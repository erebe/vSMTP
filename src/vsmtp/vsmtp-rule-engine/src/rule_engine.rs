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
use crate::{
    api::{state::deny, Server},
    domain_hierarchy::tree::Script,
    dsl::{
        directives::{Directive, Directives},
        smtp::service,
    },
    rule_state::RuleState,
    server_api::ServerAPI,
    ExecutionStage, SubDomainHierarchy,
};
use anyhow::Context;
use rhai::{
    module_resolvers::{FileModuleResolver, ModuleResolversCollection},
    packages::Package,
    Engine, Scope,
};
use rhai_dylib::module_resolvers::libloading::DylibModuleResolver;
use vqueue::{GenericQueueManager, QueueID};
use vsmtp_common::{status::Status, CodeID, Domain, Reply, ReplyOrCodeID, TransactionType};
use vsmtp_config::{Config, DnsResolvers};
use vsmtp_mail_parser::MessageBody;

/// a sharable rhai engine.
/// contains an ast representation of the user's parsed .vsl script files,
/// and modules / packages to create a cheap rhai runtime.
#[derive(Debug)]
pub struct RuleEngine {
    pub(super) global_modules: Vec<rhai::Shared<rhai::Module>>,
    pub(super) static_modules: Vec<(String, rhai::Shared<rhai::Module>)>,
    pub(super) server: Server,
    pub(super) rules: SubDomainHierarchy,
}

#[cfg(feature = "builder")]
type BuilderFunctor = Box<dyn Fn(crate::Builder<'_>) -> anyhow::Result<SubDomainHierarchy>>;

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
        resolvers: std::sync::Arc<DnsResolvers>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    ) -> anyhow::Result<Self> {
        Self::new_inner(
            #[cfg(not(feature = "builder"))]
            (),
            #[cfg(feature = "builder")]
            either::Left(()),
            config,
            resolvers,
            queue_manager,
        )
    }

    // NOTE: since a single engine instance is created for each postq emails
    //       no instrument attribute are placed here.
    /// create a rule engine instance using a callback that creates a sub domain hierarchy.
    ///
    /// # Errors
    ///
    /// * failed to compile scripts.
    #[cfg(feature = "builder")]
    pub fn with_hierarchy(
        input: impl Fn(crate::Builder<'_>) -> anyhow::Result<SubDomainHierarchy> + 'static,
        config: std::sync::Arc<Config>,
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

    ///
    #[must_use]
    pub fn srv(&self) -> std::sync::Arc<ServerAPI> {
        self.server.clone()
    }

    #[tracing::instrument(name = "building-rules", skip_all)]
    fn new_inner(
        #[cfg(not(feature = "builder"))] _input: (),
        #[cfg(feature = "builder")] _input: either::Either<(), BuilderFunctor>,
        config: std::sync::Arc<Config>,
        resolvers: std::sync::Arc<DnsResolvers>,
        queue_manager: std::sync::Arc<dyn GenericQueueManager>,
    ) -> anyhow::Result<Self> {
        if rhai::config::hashing::get_ahash_seed().is_none() {
            rhai::config::hashing::set_ahash_seed(Some([1, 2, 3, 4]))
                .map_err(|_| anyhow::anyhow!("Rhai ahash seed has been set before the rule engine as been built. This is a bug, please report it at https://github.com/viridIT/vSMTP/issues."))?;
        }

        tracing::debug!("Building rhai engine ...");

        let mut engine = Self::new_rhai_engine();

        tracing::debug!("Building static modules ...");

        let static_modules = Self::build_static_modules(&mut engine, &config)?;

        tracing::debug!("Building global modules ...");

        let global_modules = Self::build_global_modules(&mut engine)?;

        // Modules can use the configuration on startup. (i.e. when embedded in modules)
        let server = std::sync::Arc::new(ServerAPI {
            config,
            resolvers,
            queue_manager,
        });
        engine.register_fn("srv", {
            let server_cpy = server.clone();
            move || rhai::Dynamic::from(server_cpy.clone())
        });

        engine.set_module_resolver(server.config.path.as_ref().and_then(|path| path.parent()).map_or_else(|| {
                // TODO: replace this code by meta programming to simplify things.
                tracing::warn!("No configuration path found, if you receive this message in production please open an issue.");
                let mut resolvers = ModuleResolversCollection::new();

                resolvers.push(FileModuleResolver::new_with_extension("vsl"));
                resolvers.push(DylibModuleResolver::new());

                resolvers
            }, |path| {
                let mut resolvers = ModuleResolversCollection::new();

                resolvers.push(FileModuleResolver::new_with_path_and_extension(path, "vsl"));
                resolvers.push(DylibModuleResolver::with_path(path));

                resolvers
            }));

        #[cfg(not(feature = "builder"))]
        let rules = SubDomainHierarchy::new(
            &engine,
            &server.config.app.vsl,
            &server.config.server.r#virtual,
        )?;

        #[cfg(feature = "builder")]
        #[allow(clippy::used_underscore_binding)]
        let rules = match _input {
            either::Left(()) => SubDomainHierarchy::new(
                &engine,
                &server.config.app.vsl,
                &server.config.server.r#virtual,
            )?,
            either::Right(builder) => builder(crate::Builder::new(&engine))?,
        };

        tracing::info!("Rule engine initialized.");

        #[cfg(debug_assertions)]
        {
            // Checking if TypeIDs are the same as plugins.
            let type_id = std::any::TypeId::of::<rhai::ImmutableString>();
            tracing::debug!(?type_id);
        }

        Ok(Self {
            global_modules,
            static_modules,
            server,
            rules,
        })
    }

    ///
    #[must_use]
    pub fn spawn(&self) -> std::sync::Arc<RuleState> {
        self.spawn_with(vsmtp_common::Context::Empty, MessageBody::default())
    }

    /// build a cheap rhai engine with vsl's api.
    pub fn spawn_with(
        &self,
        mail_context: vsmtp_common::Context,
        message: MessageBody,
    ) -> std::sync::Arc<RuleState> {
        let (mail_context, message) = (
            std::sync::Arc::new(std::sync::RwLock::new(mail_context)),
            std::sync::Arc::new(std::sync::RwLock::new(message)),
        );

        let (mail_context_cpy, server_cpy, message_cpy) =
            (mail_context.clone(), self.server.clone(), message.clone());

        let mut engine = rhai::Engine::new_raw();

        engine.register_fn("ctx", move || rhai::Dynamic::from(mail_context_cpy.clone()));
        engine.register_fn("msg", move || rhai::Dynamic::from(message_cpy.clone()));
        engine.register_fn("srv", move || rhai::Dynamic::from(server_cpy.clone()));

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

        std::sync::Arc::new(RuleState {
            engine,
            server: self.server.clone(),
            mail_context,
            message,
        })
    }

    /// Get the subset of directive to continue the execution of rules after a delegation.
    /// at this point, any ill formed input will produce an error.
    #[allow(clippy::cognitive_complexity)]
    fn get_delegation_directive_from_header(
        rule_state: &RuleState,
        skipped: &mut Option<Status>,
        smtp_state: ExecutionStage,
        script: &Script,
    ) -> Result<usize, Reply> {
        macro_rules! err {
            ($err:expr) => {{
                tracing::warn!($err);
                $err.parse().expect("valid")
            }};
        }

        let delegation_header = rule_state
            .message()
            .read()
            .expect("Mutex poisoned")
            .get_header("X-VSMTP-DELEGATION");

        let header = delegation_header.ok_or_else(|| err!("500 Delegation header not found"))?;
        let header = vsmtp_mail_parser::get_mime_header("X-VSMTP-DELEGATION", &header);

        tracing::debug!(%header, "Got header for delegation");
        let (directive_name, msg_uuid) = match (
            header.args.get("stage"),
            header.args.get("directive"),
            header.args.get("id"),
        ) {
            (Some(stage), Some(directive_name), Some(msg_uuid)) => {
                match stage.parse::<ExecutionStage>() {
                    Ok(stage) if stage == smtp_state => (),
                    _ => return Err(err!("500 Delegation stage not matching")),
                };
                (
                    directive_name,
                    uuid::Uuid::parse_str(msg_uuid).map_err(|_err| {
                        err!("500 Delegation Failed to parse delegation message id")
                    })?,
                )
            }
            _ => {
                return Err(err!(
                    "500 Delegation header `X-VSMTP-DELEGATION` exists but ill-formed"
                ))
            }
        };
        tracing::debug!(%directive_name, %msg_uuid, "Got header for delegation with attributes");

        let position = script
            .directives_at(smtp_state)
            .ok_or_else(|| err!("500 Delegation No rules at the stages"))?
            .iter()
            .position(|directive| directive.name() == directive_name)
            .ok_or_else(|| err!("500 Delegation directive not found"))?;

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
            .get_ctx(&QueueID::Delegated, &msg_uuid);
        let mut ctx =
            block_on!(&mut ctx).map_err(|_err| err!("500 Delegation Failed to get old context"))?;

        tracing::debug!(
            "delegation changing msg uuid from {} to {}",
            ctx.mail_from.message_uuid,
            msg_uuid
        );

        ctx.connect.skipped = None;
        ctx.mail_from.message_uuid = msg_uuid;
        *rule_state.context().write().unwrap() = vsmtp_common::Context::Finished(ctx);

        tracing::debug!("Resuming rule '{directive_name}' after delegation.",);

        *skipped = None;
        Ok(position)
    }

    /// Runs all rules from a stage using the current transaction state.
    ///
    /// the `server_address` parameter is used to distinguish logs from each other,
    /// printing the address & port associated with this run session, not the current
    /// context. (because the context could have been pulled from the filesystem when
    /// receiving delegation results)
    /// # Panics
    #[tracing::instrument(name = "rule", skip_all, fields(stage = %smtp_state, skipped), ret)]
    pub fn run_when(
        &self,
        rule_state: &RuleState,
        skipped: &mut Option<Status>,
        smtp_state: ExecutionStage,
    ) -> Status {
        let script = {
            let context = rule_state.context();
            let context = context.read().expect("Mutex poisoned");

            match self.get_directives_for_smtp_state(&context, smtp_state) {
                Ok(script) => script,
                Err(_) => return Status::Deny(ReplyOrCodeID::Left(CodeID::Denied)),
            }
        };

        let directive = script.directives_at(smtp_state);

        let directive = match &skipped {
            #[cfg(feature = "delegation")]
            Some(Status::DelegationResult) if !smtp_state.is_email_received() => {
                return Status::DelegationResult;
            }
            #[cfg(feature = "delegation")]
            Some(Status::DelegationResult) => match Self::get_delegation_directive_from_header(
                rule_state, skipped, smtp_state, script,
            ) {
                Ok(position) => match directive {
                    Some(directive) => &directive[position..],
                    None => return deny(),
                },
                Err(e) => {
                    #[cfg(not(debug_assertions))]
                    {
                        // TODO: print a better error message.
                        tracing::warn!(error = ?e, "Failed to get delegation directive from the delegation header. Stopping processing.");
                        return deny();
                    }
                    #[cfg(debug_assertions)]
                    return Status::Deny(either::Right(e));
                }
            },
            Some(status) if status.is_finished() => {
                tracing::debug!(?status, "The status has been skipped before.");
                return status.clone();
            }
            Some(_) | None => {
                if let Some(directive) = directive {
                    directive
                } else {
                    tracing::debug!("No rules for the current state, continuing.");
                    return Status::Next;
                }
            }
        };

        let status = Script::execute(rule_state, script.ast(), directive, smtp_state);

        if status.is_finished() {
            tracing::info!(
                "The rule engine will skip all rules because of the result {:?}",
                status
            );
            *skipped = Some(status.clone());
        }

        status
    }

    /// Instantiate a [`RuleState`] and run it for the only `state` provided
    ///
    /// # Return
    ///
    /// A tuple with the mail context, body, result status, and skip status.
    #[must_use]
    pub fn just_run_when(
        &self,
        skipped: &mut Option<Status>,
        state: ExecutionStage,
        mail_context: vsmtp_common::Context,
        mail_message: MessageBody,
    ) -> (vsmtp_common::Context, MessageBody, Status) {
        let rule_state = self.spawn_with(mail_context, mail_message);
        let result = self.run_when(&rule_state, skipped, state);
        let (mail_context, mail_message) = rule_state.take();
        (mail_context, mail_message, result)
    }

    /// Get the desired batch of directives for the current smtp state and transaction context.
    /// The transaction context is whether the email is incoming, outgoing or internal.
    #[tracing::instrument(skip_all, err)]
    fn get_directives_for_smtp_state<'a>(
        &'a self,
        context: &vsmtp_common::Context,
        smtp_state: ExecutionStage,
    ) -> anyhow::Result<&'a Script> {
        match smtp_state {
            ExecutionStage::Connect | ExecutionStage::Helo | ExecutionStage::Authenticate => {
                Ok(self.rules.root_filter())
            }

            ExecutionStage::MailFrom => Ok(context
                .reverse_path()
                .context("bad state")?
                .as_ref()
                .and_then(|reverse_path| self.rules.get_any(&reverse_path.domain()))
                .map_or_else(
                    || self.rules.root_filter(),
                    |domain| self.rules.outgoing(domain),
                )),

            ExecutionStage::RcptTo => {
                let rcpt = context
                    .forward_paths()
                    .context("rcpt not found in rcpt stage")?
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("could not get the latests recipient"))?;
                let transaction_type = context
                    .transaction_type()
                    .context("could not get the transaction type")?;
                let reverse_path = context
                    .reverse_path()
                    .context("reverse_path not found in rcpt stage")?;

                Ok(reverse_path.as_ref().map_or_else(
                    || self.rules.root_filter(),
                    |reverse_path| self.rules.get_any(&reverse_path.domain()).map_or_else(
                        || if let (Some(rules), TransactionType::Incoming(Some(_))) = (self.rules.get_any(&rcpt.domain()), transaction_type) {
                            tracing::debug!(%rcpt, "Incoming recipient.");
                            self.rules.incoming(rules)
                        } else {
                            tracing::debug!(%rcpt, "Recipient unknown in unknown sender context, running fallback script.");
                            self.rules.root_filter()
                        },
                        |rules| match transaction_type {
                            TransactionType::Internal => {
                                tracing::debug!(%rcpt, %reverse_path, "Internal email for current recipient.");
                                self.rules.internal(rules)
                            }
                            TransactionType::Outgoing { .. } => {
                                tracing::debug!(%rcpt, %reverse_path, "Outgoing email for current recipient.");
                                self.rules.outgoing(rules)
                            }
                            TransactionType::Incoming(_) => {
                                tracing::error!(%rcpt, %reverse_path, "email is supposed to be internal / outgoing but the sender's domain was not found in your vSL scripts.");
                                self.rules.fallback()
                            }
                        })
                ))
            }

            ExecutionStage::PreQ | ExecutionStage::PostQ | ExecutionStage::Delivery => {
                let transaction_type = context
                    .transaction_type()
                    .context("could not get the transaction type")?;
                let reverse_path = context
                    .reverse_path()
                    .context("sender not found in rcpt stage")?;

                Ok(reverse_path.as_ref().map_or_else(
                    || self.rules.root_filter(),
                    |reverse_path| self.rules.get_any(&reverse_path.domain()).map_or_else(
                        || match transaction_type {
                            TransactionType::Incoming(Some(domain)) => {
                                self.rules.get_any(domain).map_or_else(
                                || self.rules.fallback(),
                                |rules| self.rules.incoming(rules))
                            }
                            TransactionType::Incoming(None) => {
                                tracing::info!("No recipient has a domain handled by your configuration, running root incoming script");
                                self.rules.root_filter()
                            }
                            TransactionType::Outgoing { .. } | TransactionType::Internal => {
                                tracing::error!("email is supposed to incoming but was marked has outgoing, running fallback scripts.");
                                self.rules.fallback()
                            }
                        },
                        |rules| match transaction_type {
                            TransactionType::Internal => self.rules.internal(rules),
                            TransactionType::Outgoing { .. } => self.rules.outgoing(rules),
                            TransactionType::Incoming(_) => {
                                tracing::error!(%reverse_path, "email is supposed to be outgoing / internal but the sender's domain was not found in your vSL scripts.");
                                self.rules.fallback()
                            }
                        }
                    )
                ))
            }
        }
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

    /// Build vsl global modules.
    ///
    /// # Errors
    /// * Failed to build modules.
    pub fn build_global_modules(
        engine: &mut rhai::Engine,
    ) -> anyhow::Result<Vec<rhai::Shared<rhai::Module>>> {
        let std_module = rhai::packages::StandardPackage::new().as_shared_module();

        engine.register_global_module(std_module.clone());

        Ok(vec![std_module])
    }

    /// Build vsl static modules.
    ///
    /// # Errors
    /// * Failed to build modules.
    pub fn build_static_modules(
        engine: &mut rhai::Engine,
        config: &Config,
    ) -> anyhow::Result<Vec<(String, rhai::Shared<rhai::Module>)>> {
        let (server_config, app_config) = (
            serde_json::to_string(&config.server)
                .context("failed to convert the server configuration to json")?,
            serde_json::to_string(&config.app)
                .context("failed to convert the app configuration to json")?,
        );

        let mut vsl_modules = crate::api::vsmtp_static_modules()
            .into_iter()
            .map(|(name, module)| (name.to_owned(), rhai::Shared::new(module)))
            .collect::<Vec<_>>();

        vsl_modules.push(("cfg".to_owned(), {
            let mut config_module = rhai::Module::new();
            config_module
                .set_var("server", engine.parse_json(server_config, true)?)
                .set_var("app", engine.parse_json(app_config, true)?);
            rhai::Shared::new(config_module)
        }));

        for (name, module) in &vsl_modules {
            engine.register_static_module(name, module.clone());
        }

        Ok(vsl_modules)
    }

    // FIXME: could be easily refactored.
    //        every `ok_or_else` could be replaced by an unwrap here.
    /// extract rules & actions from the main vsl script.
    pub(crate) fn extract_directives(
        engine: &rhai::Engine,
        ast: &rhai::AST,
    ) -> anyhow::Result<Directives> {
        let mut scope = Scope::new();
        let raw_directives = engine
            .eval_ast_with_scope::<rhai::Map>(&mut scope, ast)
            .context("failed to compile your rules.")?;

        let mut directives = Directives::new();

        for (stage, directive_set) in raw_directives {
            let Ok(stage) = ExecutionStage::try_from(stage.as_str()) else {
                anyhow::bail!("the '{stage}' smtp stage does not exist.")
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

    /// Return `true` if the given domain **or any parent domain** is handled by the configuration.
    #[must_use]
    pub fn is_handled_domain(&self, domain: &Domain) -> bool {
        self.rules.get_any(domain).is_some()
    }

    /// Find the delegate directive that matches the given socket.
    #[must_use]
    #[cfg(feature = "delegation")]
    pub fn get_delegation_directive_bound_to_address(
        &self,
        socket: std::net::SocketAddr,
    ) -> Option<&Directive> {
        let per_domain_scripts = self.rules.get_all().flat_map(|d| {
            [
                self.rules.incoming(d),
                self.rules.internal(d),
                self.rules.outgoing(d),
            ]
            .into_iter()
        });

        std::iter::once(self.rules.root_filter())
            .chain(per_domain_scripts)
            .filter_map(|script| {
                script.directives().find(|d| {
                    matches!(d, Directive::Delegation { service, .. } if service.receiver == socket)
                })
            })
            .take(1)
            .next()
    }
}
