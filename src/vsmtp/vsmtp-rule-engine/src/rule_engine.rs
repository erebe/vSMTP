/*
 * vSMTP mail transfer agent
 * Copyright (C) 2022 viridIT SAS
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 *
 */
use crate::api::Server;
use crate::api::{rule_state::deny, EngineResult, StandardVSLPackage};
use crate::dsl::cmd::plugin::Cmd;
use crate::dsl::directives::{Directive, Directives};
use crate::dsl::smtp::{plugin, service};
use crate::rule_state::RuleState;
use crate::server_api::ServerAPI;
use crate::sub_domain_hierarchy::{Builder, DomainDirectives, Script, SubDomainHierarchy};
use anyhow::Context;
use rhai::{module_resolvers::FileModuleResolver, packages::Package, Engine, Scope};
use vqueue::{GenericQueueManager, QueueID};
use vsmtp_common::mail_context::{Empty, MailContext, MailContextAPI, StateSMTP, TransactionType};
use vsmtp_common::{state::State, status::Status};
use vsmtp_common::{CodeID, Domain, ReplyOrCodeID};
use vsmtp_config::{Config, DnsResolvers};
use vsmtp_mail_parser::MessageBody;
use vsmtp_plugin_vsl::plugin::Objects;
use vsmtp_plugins::managers::native::NativeVSL;
use vsmtp_plugins::managers::PluginManager;
use vsmtp_plugins::rhai;

macro_rules! block_on {
    ($future:expr) => {
        tokio::task::block_in_place(move || tokio::runtime::Handle::current().block_on($future))
    };
}

/// a sharable rhai engine.
/// contains an ast representation of the user's parsed .vsl script files,
/// and modules / packages to create a cheap rhai runtime.
#[derive(Debug)]
pub struct RuleEngine {
    /// vSMTP global modules.
    pub(super) global_modules: Vec<rhai::Shared<rhai::Module>>,
    /// vSMTP static modules with their associated names.
    pub(super) static_modules: Vec<(String, rhai::Shared<rhai::Module>)>,
    /// Handle to vSL plugins.
    pub(super) vsl_service_plugin_manager: rhai::Shared<NativeVSL>,
    /// Readonly server API to inject into the context of Rhai.
    pub(super) server: Server,

    /// rules split by domain and transaction types.
    pub(super) rules: SubDomainHierarchy,
}

type RuleEngineInput = either::Either<
    Option<std::path::PathBuf>,
    Box<dyn Fn(Builder<'_>) -> anyhow::Result<SubDomainHierarchy>>,
>;

impl RuleEngine {
    /// creates a new instance of the rule engine, reading all files in the
    /// `script_path` parameter.
    /// if `script_path` is `None`, a warning is emitted and a deny-all script
    /// is loaded.
    ///
    /// # Errors
    /// * failed to register `script_path` as a valid module folder.
    /// * failed to compile or load any script located at `script_path`.
    pub fn new(
        config: std::sync::Arc<Config>,
        input: Option<std::path::PathBuf>,
        resolvers: std::sync::Arc<DnsResolvers>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    ) -> anyhow::Result<Self> {
        Self::new_inner(either::Left(input), config, resolvers, queue_manager)
    }

    // NOTE: since a single engine instance is created for each postq emails
    //       no instrument attribute are placed here.
    /// create a rule engine instance using a callback that creates a sub domain hierarchy.
    ///
    /// # Errors
    ///
    /// * failed to compile scripts.
    pub fn with_hierarchy(
        config: std::sync::Arc<Config>,
        input: impl Fn(Builder<'_>) -> anyhow::Result<SubDomainHierarchy> + 'static,
        resolvers: std::sync::Arc<DnsResolvers>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    ) -> anyhow::Result<Self> {
        Self::new_inner(
            either::Right(Box::new(input)),
            config,
            resolvers,
            queue_manager,
        )
    }

    #[tracing::instrument(name = "building-rules", skip_all)]
    fn new_inner(
        input: RuleEngineInput,
        config: std::sync::Arc<Config>,
        resolvers: std::sync::Arc<DnsResolvers>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    ) -> anyhow::Result<Self> {
        tracing::debug!("Building rhai engine ...");

        let mut engine = Self::new_rhai_engine();

        tracing::debug!("Loading plugins ...");

        let vsl_service_plugin_manager = Self::load_plugins(&config, &mut engine)?;

        tracing::debug!("Building static modules ...");

        let static_modules = Self::build_static_modules(&mut engine, &config)?;

        tracing::debug!("Building global modules ...");

        let global_modules = Self::build_global_modules(&mut engine)?;

        engine.set_module_resolver(match &input {
            // TODO: handle canonicalization.
            either::Either::Left(Some(path)) => FileModuleResolver::new_with_path_and_extension(
                path.parent().ok_or_else(|| {
                    anyhow::anyhow!(
                        "file '{}' does not have a valid parent directory for rules",
                        path.display()
                    )
                })?,
                "vsl",
            ),
            either::Either::Left(None) | either::Either::Right(_) => {
                FileModuleResolver::new_with_extension("vsl")
            }
        });

        let rules = match input {
            either::Either::Left(Some(path)) => {
                tracing::info!("Analyzing vSL rules at {path:?}");

                SubDomainHierarchy::new(&engine, &path)?
            }
            either::Either::Left(None) => {
                tracing::warn!(
                    "No 'main.vsl' provided in the config, the server will deny any incoming transaction by default."
                );

                SubDomainHierarchy::new_empty(&engine)?
            }
            // NOTE: could be marked as debug.
            either::Either::Right(builder) => builder(Builder::new(&engine)?)?,
        };

        tracing::info!("Rule engine initialized.");

        Ok(Self {
            global_modules,
            static_modules,
            vsl_service_plugin_manager,
            server: std::sync::Arc::new(ServerAPI {
                config,
                resolvers,
                queue_manager,
            }),
            rules,
        })
    }

    pub(crate) fn spawn(&self) -> RuleState {
        self.spawn_with(
            MailContextAPI::Empty(MailContext::<Empty>::empty()),
            MessageBody::default(),
        )
    }

    /// build a cheap rhai engine with vsl's api.
    pub(crate) fn spawn_with(
        &self,
        mail_context: MailContextAPI,
        message: MessageBody,
    ) -> RuleState {
        let (mail_context, message) = (
            std::sync::Arc::new(std::sync::RwLock::new(mail_context)),
            std::sync::Arc::new(std::sync::RwLock::new(message)),
        );

        let (mail_context_cpy, server_cpy, message_cpy) =
            (mail_context.clone(), self.server.clone(), message.clone());

        let mut engine = rhai::Engine::new_raw();

        // NOTE: on_var is not deprecated, just subject to change in future releases.
        #[allow(deprecated)]
        engine
            // NOTE: why do we have to clone the arc instead of just moving it here ?
            // injecting the state if the current connection into the engine.
            .on_var(move |name, _, _| match name {
                "CTX" => Ok(Some(rhai::Dynamic::from(mail_context_cpy.clone()))),
                "SRV" => Ok(Some(rhai::Dynamic::from(server_cpy.clone()))),
                "MSG" => Ok(Some(rhai::Dynamic::from(message_cpy.clone()))),
                _ => Ok(None),
            });

        #[cfg(debug_assertion)]
        engine
            .on_print(|msg| println!("{msg}"))
            .on_debug(move |s, src, pos| {
                println!("{} @ {:?} > {}", src.unwrap_or("unknown source"), pos, s);
            });

        self.global_modules.iter().for_each(|module| {
            engine.register_global_module(module.clone());
        });

        self.static_modules.iter().for_each(|(namespace, module)| {
            engine.register_static_module(namespace, module.clone());
        });

        // FIXME: the following lines should be remove for performance improvement.
        //        need to check out how to construct directives as a module.
        engine
            .register_custom_syntax_with_state_raw(
                "rule",
                Directive::parse_directive,
                true,
                crate::dsl::directives::rule::create,
            )
            .register_custom_syntax_with_state_raw(
                "action",
                Directive::parse_directive,
                true,
                crate::dsl::directives::action::create,
            );

        #[cfg(feature = "delegation")]
        engine.register_custom_syntax_with_state_raw(
            "delegate",
            Directive::parse_directive,
            true,
            crate::dsl::directives::delegation::create,
        );

        engine.set_fast_operators(false);

        // FIXME: No need to re-apply that.
        vsmtp_plugins::managers::PluginManager::apply(
            &*self.vsl_service_plugin_manager,
            &mut engine,
        )
        .expect("plugins should already have been analyzed by the main engine.");

        RuleState {
            engine,
            server: self.server.clone(),
            mail_context,
            message,
            skip: None,
        }
    }

    /// Runs all rules from a stage using the current transaction state.
    ///
    /// the `server_address` parameter is used to distinguish logs from each other,
    /// printing the address & port associated with this run session, not the current
    /// context. (because the context could have been pulled from the filesystem when
    /// receiving delegation results)
    /// # Panics
    #[tracing::instrument(name = "rule", skip_all, fields(stage = %smtp_state))]
    pub fn run_when(&self, rule_state: &mut RuleState, smtp_state: State) -> Status {
        // Extract the correct set of rules, comparing the domains of the sender and recipients.
        let script = {
            let context = rule_state.context();
            let context = match context.read() {
                Ok(context) => context,
                Err(error) => {
                    tracing::error!(%error, "context mutex poisoned");

                    return Status::Deny(ReplyOrCodeID::Left(CodeID::Denied));
                }
            };

            match self.get_directives_for_smtp_state(&context, smtp_state) {
                Ok(script) => script,
                Err(_) => return Status::Deny(ReplyOrCodeID::Left(CodeID::Denied)),
            }
        };

        let directive_set = if let Some(directive_set) = script.directives.get(&smtp_state) {
            directive_set
        } else {
            tracing::debug!("No rules for the current state, continuing.");
            return Status::Next;
        };

        // check if we need to skip directive execution or resume because of a delegation.
        let directive_set = match rule_state.skipped() {
            #[cfg(feature = "delegation")]
            Some(Status::DelegationResult) if smtp_state.is_email_received() => {
                if let Some(header) = rule_state
                    .message()
                    .read()
                    .expect("Mutex poisoned")
                    .get_header("X-VSMTP-DELEGATION")
                {
                    let header = vsmtp_mail_parser::get_mime_header("X-VSMTP-DELEGATION", &header);

                    let (stage, directive_name, message_id) =
                        if let (Some(stage), Some(directive_name), Some(message_id)) = (
                            header.args.get("stage"),
                            header.args.get("directive"),
                            header.args.get("id"),
                        ) {
                            (stage, directive_name, message_id)
                        } else {
                            return Status::DelegationResult;
                        };

                    if *stage == smtp_state.to_string() {
                        if let Some(d) = directive_set
                            .iter()
                            .position(|directive| directive.name() == directive_name)
                        {
                            // If delegation results are coming in and that this is the correct
                            // directive that has been delegated, we need to pull
                            // the old context because its state has been lost
                            // when the delegation happened.
                            //
                            // There is however no need to discard the old email because it
                            // will be overridden by the results once it's time to write
                            // in the 'mail' queue.

                            // FIXME: this is only useful for preq, the other processes
                            //        already fetch the old context.
                            let mut ctx = rule_state
                                .server
                                .queue_manager
                                .get_ctx(&QueueID::Delegated, message_id);
                            match block_on!(&mut ctx) {
                                Ok(mut context) => {
                                    context.set_skipped(None);
                                    *rule_state.context().write().unwrap() =
                                        MailContextAPI::Finished(context);
                                }
                                Err(error) => {
                                    tracing::error!(%error, "Failed to get old email context from working queue after a delegation");
                                }
                            }

                            tracing::debug!("Resuming rule '{directive_name}' after delegation.",);

                            rule_state.resume();
                            &directive_set[d..]
                        } else {
                            return Status::DelegationResult;
                        }
                    } else {
                        return Status::DelegationResult;
                    }
                } else {
                    return Status::DelegationResult;
                }
            }
            Some(status) => return (*status).clone(),
            None => &directive_set[..],
        };

        match Self::execute_directives(rule_state, &script.ast, directive_set, smtp_state) {
            Ok(status) => {
                tracing::debug!(?status);

                if status.is_finished() {
                    tracing::debug!(
                        "The rule engine will skip all rules because of the previous result."
                    );
                    rule_state.skipping(status.clone());
                }

                status
            }
            Err(error) => {
                tracing::error!(%error, "Rule engine error.");

                #[cfg(debug_assertions)]
                println!("Rule engine error: {error:?}");

                // TODO: keep the error for the `deferred` info.

                // if an error occurs, the engine denies the connection by default.
                rule_state.skipping(deny());
                deny()
            }
        }
    }

    /// Instantiate a [`RuleState`] and run it for the only `state` provided
    ///
    /// # Return
    ///
    /// A tuple with the mail context, body, result status, and skip status.
    #[must_use]
    pub fn just_run_when<S: StateSMTP>(
        &self,
        state: State,
        mail_context: MailContext<S>,
        mail_message: MessageBody,
    ) -> (MailContextAPI, MessageBody, Status, Option<Status>)
    where
        MailContextAPI: From<MailContext<S>>,
    {
        let mut rule_state = RuleState::with_context(self, mail_context.into(), mail_message);

        let result = self.run_when(&mut rule_state, state);

        let (mail_context, mail_message, skipped) = rule_state
            .take()
            .expect("should not have strong reference here");

        (mail_context, mail_message, result, skipped)
    }

    /// Get the desired batch of directives for the current smtp state and transaction context.
    /// The transaction context is whether the email is incoming, outgoing or internal.
    #[allow(clippy::cognitive_complexity)]
    #[allow(clippy::too_many_lines)]
    fn get_directives_for_smtp_state<'a>(
        &'a self,
        context: &MailContextAPI,
        smtp_state: State,
    ) -> anyhow::Result<&'a Script> {
        match smtp_state {
            // running main script, the sender has not been received yet.
            State::Connect | State::Helo | State::Authenticate => Ok(&self.rules.main),

            State::MailFrom => {
                let sender = context.reverse_path();

                #[allow(clippy::option_if_let_else)]
                match sender {
                    // Outgoing email, we execute the outgoing script from the sender's domain.
                    Some(sender) if context.is_outgoing() => self.get_domain_directives(sender.domain()).map_or_else(|| {
                            tracing::error!(%sender, "email is supposed to be outgoing but the sender's domain was not found in your vSL scripts.");

                            Ok(&self.rules.fallback)
                        }, |rules| Ok(&rules.outgoing)),
                    // incoming, execute main "mail from" rules by default.
                    _ => Ok(&self.rules.main)
                }
            }

            // Sender domain handled, running outgoing / internal rules for each recipient which the domain is handled by the configuration,
            // otherwise run the fallback script.
            State::RcptTo if context.is_outgoing() => {
                let sender = context
                    .reverse_path()
                    .ok_or_else(|| anyhow::anyhow!("sender not found in rcpt stage"))?;
                let recipient = context
                    .forward_paths()
                    .ok_or_else(|| anyhow::anyhow!("rcpt not found in rcpt stage"))?
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("could not get the latests recipient"))?;
                let transaction_type = context
                    .transaction_type()
                    .ok_or_else(|| anyhow::anyhow!("could not get the transaction type"))?;

                match (
                    self.get_domain_directives(sender.domain()),
                    transaction_type,
                ) {
                    (Some(rules), TransactionType::Internal) => {
                        tracing::debug!(rcpt = %recipient, %sender, "Internal email for current recipient.");

                        Ok(&rules.internal)
                    }
                    (Some(rules), TransactionType::Outgoing(_)) => {
                        tracing::debug!(rcpt = %recipient, %sender, "Outgoing email for current recipient.");

                        Ok(&rules.outgoing)
                    }

                    // Edge case that should never happen because incoming is never paired with is_outgoing = true.
                    _ => {
                        tracing::error!(rcpt = %recipient, %sender, "email is supposed to be outgoing but the sender's domain was not found in your vSL scripts.");

                        Ok(&self.rules.fallback)
                    }
                }
            }

            // Sender domain unknown, running incoming rules for each recipient which the domain is handled by the configuration,
            // otherwise run the fallback script.
            State::RcptTo => {
                let recipient = context
                    .forward_paths()
                    .ok_or_else(|| anyhow::anyhow!("rcpt not found in rcpt stage"))?
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("could not get the latests recipient"))?;
                let transaction_type = context
                    .transaction_type()
                    .ok_or_else(|| anyhow::anyhow!("could not get the transaction type"))?;

                if let (Some(rules), TransactionType::Incoming(Some(_))) = (
                    self.get_domain_directives(recipient.address.domain()),
                    transaction_type,
                ) {
                    tracing::debug!(rcpt = %recipient, "Incoming recipient.");

                    Ok(&rules.incoming)
                } else {
                    tracing::debug!(rcpt = %recipient, "Recipient unknown in unknown sender context, running fallback script.");

                    Ok(&self.rules.fallback)
                }
            }

            // Sender domain known. Run the outgoing / internal preq rules.
            State::PreQ | State::PostQ | State::Delivery if context.is_outgoing() => {
                let sender = context
                    .reverse_path()
                    .ok_or_else(|| anyhow::anyhow!("sender not found in rcpt stage"))?;
                let transaction_type = context
                    .transaction_type()
                    .ok_or_else(|| anyhow::anyhow!("could not get the transaction type"))?;

                match (
                    self.get_domain_directives(sender.domain()),
                    transaction_type,
                ) {
                    // Current batch of recipients is marked as internal, we execute the internal rules.
                    (Some(rules), TransactionType::Internal) => Ok(&rules.internal),
                    // Otherwise, we call the outgoing rules.
                    (Some(rules), TransactionType::Outgoing(_)) => Ok(&rules.outgoing),
                    // Should never happen.
                    _ => {
                        tracing::error!(%sender, "email is supposed to be outgoing / internal but the sender's domain was not found in your vSL scripts.");

                        Ok(&self.rules.fallback)
                    }
                }
            }

            // Sender domain unknown, running incoming rules for each recipient which the domain is handled by the configuration,
            // otherwise run the fallback script.
            State::PreQ | State::PostQ | State::Delivery => {
                let transaction_type = context
                    .transaction_type()
                    .ok_or_else(|| anyhow::anyhow!("could not get the transaction type"))?;

                match transaction_type {
                    TransactionType::Incoming(Some(domain)) => self
                        .rules
                        .domains
                        .get(domain)
                        .map_or_else(|| Ok(&self.rules.fallback), |rules| Ok(&rules.incoming)),
                    TransactionType::Incoming(None) => {
                        tracing::warn!("No recipient has a domain handled by your configuration, running fallback script");

                        Ok(&self.rules.fallback)
                    }
                    TransactionType::Outgoing(_) | TransactionType::Internal => {
                        tracing::error!("email is supposed to incoming but was marked has outgoing, running fallback scripts.");

                        Ok(&self.rules.fallback)
                    }
                }
            }
        }
    }

    /// Get directives following a domain. If the subdomain cannot be found,
    /// The root domain is used instead.
    ///
    /// Does not check if the domain is a valid domain.
    fn get_domain_directives(&self, domain: &str) -> Option<&DomainDirectives> {
        // NOTE: Rust 1.65 if let else could be used here.
        if let Some(directives) = self.rules.domains.get(domain) {
            return Some(directives);
        }

        Domain::iter(domain).find_map(|parent| self.rules.domains.get(parent))
    }

    fn execute_directives(
        rule_state: &mut RuleState,
        ast: &rhai::AST,
        directives: &[Directive],
        smtp_state: State,
    ) -> EngineResult<Status> {
        let mut status = Status::Next;

        for directive in directives {
            tracing::debug!("Executing {} '{}'", directive.as_ref(), directive.name());
            status = directive.execute(rule_state, ast, smtp_state)?;

            if status != Status::Next {
                break;
            }
        }

        Ok(status)
    }

    /// create a rhai engine to compile all scripts with vsl's configuration.
    #[must_use]
    pub fn new_rhai_engine() -> rhai::Engine {
        let mut engine = Engine::new();

        // NOTE: on_parse_token is not deprecated, just subject to change in future releases.
        #[allow(deprecated)]
        engine.on_parse_token(|token, _, _| {
            match token {
                // remap 'is' operator to '==', it's easier than creating a new operator.
                // NOTE: warning => "is" is a reserved keyword in rhai's tokens, maybe change to "eq" ?
                rhai::Token::Reserved(s) if &*s == "is" => rhai::Token::EqualsTo,
                rhai::Token::Identifier(s) if &*s == "not" => rhai::Token::NotEqualsTo,
                // Pass through all other tokens unchanged
                _ => token,
            }
        });

        #[cfg(debug_assertion)]
        engine
            .on_print(|msg| println!("{msg}"))
            .on_debug(move |s, src, pos| {
                println!("{} @ {:?} > {}", src.unwrap_or("unknown source"), pos, s);
            });

        engine
            .disable_symbol("eval")
            .register_custom_syntax_with_state_raw(
                "rule",
                Directive::parse_directive,
                true,
                crate::dsl::directives::rule::create,
            )
            .register_custom_syntax_with_state_raw(
                "action",
                Directive::parse_directive,
                true,
                crate::dsl::directives::action::create,
            );

        #[cfg(feature = "delegation")]
        engine.register_custom_syntax_with_state_raw(
            "delegate",
            Directive::parse_directive,
            true,
            crate::dsl::directives::delegation::create,
        );

        engine.set_fast_operators(false);

        engine
    }

    ///
    fn build_global_modules(
        engine: &mut rhai::Engine,
    ) -> anyhow::Result<Vec<rhai::Shared<rhai::Module>>> {
        let std_module = rhai::packages::StandardPackage::new().as_shared_module();

        engine.register_global_module(std_module.clone());

        let vsl_rhai_module =
            rhai::Shared::new(Self::compile_api(engine).context("failed to compile vsl's api")?);

        engine.register_global_module(vsl_rhai_module.clone());

        Ok(vec![std_module, vsl_rhai_module])
    }

    ///
    fn build_static_modules(
        engine: &mut rhai::Engine,
        config: &Config,
    ) -> anyhow::Result<Vec<(String, rhai::Shared<rhai::Module>)>> {
        let (server_config, app_config) = (
            serde_json::to_string(&config.server)
                .context("failed to convert the server configuration to json")?,
            serde_json::to_string(&config.app)
                .context("failed to convert the app configuration to json")?,
        );

        let vsl_sys_module = StandardVSLPackage::new().as_shared_module();
        let config_module = {
            let mut config_module = rhai::Module::new();
            config_module
                .set_var("server", engine.parse_json(server_config, true)?)
                .set_var("app", engine.parse_json(app_config, true)?);
            rhai::Shared::new(config_module)
        };

        engine
            .register_static_module("sys", vsl_sys_module.clone())
            .register_static_module("cfg", config_module.clone());

        Ok(vec![
            ("sys".to_owned(), vsl_sys_module),
            ("cfg".to_owned(), config_module),
        ])
    }

    /// compile vsl's api into a module.
    ///
    /// # Errors
    /// * Failed to compile the API.
    /// * Failed to create a module from the API.
    pub fn compile_api(engine: &rhai::Engine) -> anyhow::Result<rhai::Module> {
        let ast = engine.compile_scripts_with_scope(
            &rhai::Scope::new(),
            [
                // objects.
                include_str!("../api/codes.rhai"),
                include_str!("../api/networks.rhai"),
                // functions.
                include_str!("../api/auth.rhai"),
                include_str!("../api/connection.rhai"),
                include_str!("../api/delivery.rhai"),
                include_str!("../api/envelop.rhai"),
                include_str!("../api/getters.rhai"),
                include_str!("../api/internal.rhai"),
                include_str!("../api/message.rhai"),
                include_str!("../api/security.rhai"),
                include_str!("../api/status.rhai"),
                include_str!("../api/transaction.rhai"),
                include_str!("../api/types.rhai"),
                include_str!("../api/utils.rhai"),
            ],
        )?;

        rhai::Module::eval_ast_as_new(rhai::Scope::new(), &ast, engine)
            .context("failed to create a module from vsl's api.")
    }

    // FIXME: could be easily refactored.
    //        every `ok_or_else` could be replaced by an unwrap here.
    /// extract rules & actions from the main vsl script.
    pub(crate) fn extract_directives(
        engine: &rhai::Engine,
        ast: &rhai::AST,
    ) -> anyhow::Result<Directives> {
        let mut scope = Scope::new();
        scope
            .push("date", ())
            .push("time", ())
            .push_constant("CTX", ())
            .push_constant("SRV", ());

        let raw_directives = engine
            .eval_ast_with_scope::<rhai::Map>(&mut scope, ast)
            .context("failed to compile your rules.")?;

        let mut directives = Directives::new();

        for (stage, directive_set) in raw_directives {
            let stage = match State::try_from(stage.as_str()) {
                Ok(stage) => stage,
                Err(_) => anyhow::bail!("the '{stage}' smtp stage does not exist."),
            };

            let directive_set = directive_set
                .try_cast::<rhai::Array>()
                .ok_or_else(|| {
                    anyhow::anyhow!("the stage '{stage}' must be declared using the array syntax")
                })?
                .into_iter()
                .map(|rule| {
                    let map = rule.try_cast::<rhai::Map>().unwrap();
                    let directive_type = map
                        .get("type")
                        .ok_or_else(|| anyhow::anyhow!("a directive in stage '{stage}' does not have a valid type"))?
                        .to_string();

                    let name = map
                        .get("name")
                        .ok_or_else(|| anyhow::anyhow!("a directive in stage '{stage}' does not have a name"))?
                        .to_string();

                    let pointer = map
                        .get("evaluate")
                        .ok_or_else(|| anyhow::anyhow!("the directive '{stage}' in stage '{name}' does not have an evaluation function"))?
                        .clone()
                        .try_cast::<rhai::FnPtr>()
                        .ok_or_else(|| anyhow::anyhow!("the evaluation field for the directive '{stage}' in stage '{name}' must be a function pointer"))?;

                    let directive =
                        match directive_type.as_str() {
                            "rule" => Directive::Rule { name, pointer },
                            "action" => Directive::Action { name, pointer },
                            #[cfg(feature = "delegation")]
                            "delegate" => {

                                if !stage.is_email_received() {
                                    anyhow::bail!("invalid delegation '{name}' in stage '{stage}': delegation directives are available from the 'postq' stage and onwards.");
                                }

                                let service = map
                                    .get("service")
                                    .ok_or_else(|| anyhow::anyhow!("the delegation '{name}' in stage '{stage}' does not have a service to delegate processing to"))?
                                    .clone()
                                    .try_cast::<std::sync::Arc<service::Smtp>>()
                                    .ok_or_else(|| anyhow::anyhow!("the field after the 'delegate' keyword in the directive '{name}' in stage '{stage}' must be a smtp service"))?;

                                Directive::Delegation { name, pointer, service }
                            },
                            unknown => anyhow::bail!("unknown directive type '{unknown}' called '{name}'"),
                        };

                    Ok(directive)
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            directives.insert(stage, directive_set);
        }

        let names = directives
            .iter()
            .flat_map(|(_, d)| d)
            .map(Directive::name)
            .collect::<Vec<_>>();

        // TODO: refactor next loop with templated function 'find_duplicate'.
        for (idx, name) in names.iter().enumerate() {
            for other in &names[idx + 1..] {
                if other == name {
                    anyhow::bail!("found duplicate rule '{name}': a rule must have a unique name",);
                }
            }
        }

        Ok(directives)
    }

    /// Load vsl service plugins from the configuration paths and apply them to the rhai engine.
    fn load_plugins(
        config: &std::sync::Arc<Config>,
        engine: &mut rhai::Engine,
    ) -> anyhow::Result<rhai::Shared<NativeVSL>> {
        let mut vsl_plugin_manager = NativeVSL::default();

        // Registering native service plugins.
        vsl_plugin_manager
            .add_native_plugin("smtp", Box::new(plugin::Smtp {}))
            .add_native_plugin("cmd", Box::new(Cmd {}))
            .add_native_plugin("objects", Box::new(Objects {}));

        for (name, path) in &config.app.vsl.plugins {
            vsl_plugin_manager.load(name, path)?;
            tracing::debug!(%name, ?path, "vSL plugin loaded.");
        }

        vsl_plugin_manager.apply(engine)?;

        tracing::debug!("Plugins applied to vSL.");

        Ok(rhai::Shared::new(vsl_plugin_manager))
    }

    /// Check if the rule engine have configuration available for the domain of the given address.
    ///
    /// NOTE: Check recursivly all parents of the given domain,
    /// return true if any parent domain is handled by the configuration.
    #[must_use]
    pub fn handle_domain(&self, address: &vsmtp_common::Address) -> bool {
        let domain = address.domain();

        if self.rules.domains.contains_key(domain) {
            true
        } else {
            Domain::iter(domain).any(|parent| self.rules.domains.contains_key(parent))
        }
    }

    /// Find the delegate directive that matches the given socket.
    #[cfg(feature = "delegation")]
    #[must_use]
    pub fn get_delegation_directive<'a>(
        &'a self,
        socket: &'a std::net::SocketAddr,
    ) -> Option<&'a Directive> {
        fn get_matching_delegation_inner<'a>(
            directives: &'a Directives,
            socket: &'a std::net::SocketAddr,
        ) -> Option<&'a Directive> {
            directives.iter().flat_map(|(_, d)| d).find(|d| match d {
                Directive::Delegation { service, .. } => service.receiver == *socket,
                _ => false,
            })
        }

        // Search for a matching delegation rule with the same socket from main -> fallback -> domains.
        get_matching_delegation_inner(&self.rules.main.directives, socket).or_else(|| {
            get_matching_delegation_inner(&self.rules.fallback.directives, socket).or_else(|| {
                self.rules.domains.iter().find_map(|(_, directives)| {
                    get_matching_delegation_inner(&directives.incoming.directives, socket).or_else(
                        || {
                            get_matching_delegation_inner(&directives.outgoing.directives, socket)
                                .or_else(|| {
                                    get_matching_delegation_inner(
                                        &directives.internal.directives,
                                        socket,
                                    )
                                })
                        },
                    )
                })
            })
        })
    }
}
