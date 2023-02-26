use crate::{
    field::{FieldServerDNS, ResolverOptsWrapper},
    Config,
};
use trust_dns_resolver::{config::ResolverConfig, error::ResolveError, TokioAsyncResolver};
use vsmtp_common::Domain;

///
#[derive(Debug)]
pub struct DnsResolvers {
    root: std::sync::Arc<TokioAsyncResolver>,
    inner: std::collections::HashMap<Domain, std::sync::Arc<TokioAsyncResolver>>,
}

impl DnsResolvers {
    /// Initialize the DNS resolver from the [`Config`].
    ///
    /// # Errors
    ///
    /// * could not initialize the DNS resolver for the root domain or any of the subdomains
    pub fn from_config(config: &Config) -> Result<Self, ResolveError> {
        Ok(Self {
            root: Self::build_dns_from_config(&config.server.dns).map(std::sync::Arc::new)?,
            inner: config
                .server
                .r#virtual
                .iter()
                .filter_map(|(domain, c)| c.dns.as_ref().map(|c| (domain, c)))
                .map(|(domain, c)| {
                    Self::build_dns_from_config(c).map(|c| (domain.clone(), std::sync::Arc::new(c)))
                })
                .collect::<Result<std::collections::HashMap<_, _>, ResolveError>>()?,
        })
    }

    /// Build the DNS resolver from `/etc/resolv.conf` with no subdomains configured.
    ///
    /// # Errors
    ///
    /// * could not initialize the DNS resolver
    pub fn from_system_conf() -> Result<Self, ResolveError> {
        Ok(Self {
            root: std::sync::Arc::new(TokioAsyncResolver::tokio_from_system_conf()?),
            inner: std::collections::HashMap::new(),
        })
    }

    ///
    #[must_use]
    pub fn get_resolver(&self, domain: &Domain) -> Option<std::sync::Arc<TokioAsyncResolver>> {
        self.inner.get(domain).cloned()
    }

    ///
    #[must_use]
    pub fn get_resolver_root(&self) -> std::sync::Arc<TokioAsyncResolver> {
        self.root.clone()
    }

    ///
    #[must_use]
    pub fn get_resolver_or_root(&self, domain: &Domain) -> std::sync::Arc<TokioAsyncResolver> {
        self.inner
            .get(domain)
            .cloned()
            .unwrap_or_else(|| self.get_resolver_root())
    }

    fn resolver_opts_from_config(
        config: &ResolverOptsWrapper,
    ) -> trust_dns_resolver::config::ResolverOpts {
        let mut opts = trust_dns_resolver::config::ResolverOpts::default();

        opts.timeout = config.timeout;
        opts.attempts = config.attempts;
        opts.rotate = config.rotate;
        opts.validate = config.dnssec;
        opts.ip_strategy = config.ip_strategy;
        opts.cache_size = config.cache_size;
        opts.use_hosts_file = config.use_hosts_file;
        opts.num_concurrent_reqs = config.num_concurrent_reqs;

        opts
    }

    fn build_dns_from_config(config: &FieldServerDNS) -> Result<TokioAsyncResolver, ResolveError> {
        match &config {
            FieldServerDNS::System => TokioAsyncResolver::tokio_from_system_conf(),
            FieldServerDNS::Google { options } => TokioAsyncResolver::tokio(
                ResolverConfig::google(),
                Self::resolver_opts_from_config(options),
            ),
            FieldServerDNS::CloudFlare { options } => TokioAsyncResolver::tokio(
                ResolverConfig::cloudflare(),
                Self::resolver_opts_from_config(options),
            ),
            FieldServerDNS::Custom { config, options } => {
                TokioAsyncResolver::tokio(config.clone(), Self::resolver_opts_from_config(options))
            }
        }
    }
}
