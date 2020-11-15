use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::future::join_all;
use futures::stream::{self, StreamExt};
use futures::{Future, TryFutureExt};
use rand::seq::SliceRandom;
use tokio::task;

pub use error::Error;
pub use lookup::{Lookup, Lookups};
pub use query::{MultiQuery, UniQuery};

use crate::nameserver::{NameServerConfig, NameServerConfigGroup};
use crate::system_config;
use crate::Result;

pub mod error;
pub mod lookup;
pub mod predefined;
pub mod query;

pub type ResolverResult<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct ResolverConfig {
    name_server_config: NameServerConfig,
}

impl ResolverConfig {
    pub fn new(name_server_config: NameServerConfig) -> Self {
        ResolverConfig { name_server_config }
    }
}

impl From<NameServerConfig> for ResolverConfig {
    fn from(ns_config: NameServerConfig) -> Self {
        ResolverConfig {
            name_server_config: ns_config,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolverOpts {
    pub retries: usize,
    /// Maximum number of concurrent queries send with this resolver
    pub max_concurrent_requests: usize,
    pub ndots: usize,
    pub preserve_intermediates: bool,
    /// cf. `trust_dns_resolver::proto::xfer::DnsRequestOptions`
    pub expects_multiple_responses: bool,
    pub timeout: Duration,
    pub abort_on_error: bool,
    pub abort_on_timeout: bool,
}

impl ResolverOpts {
    /// Creates `ResolverOpts` from local system configuration.
    ///
    /// Unix: Parses `/etc/resolv.conf`.
    pub fn from_system_config() -> Result<ResolverOpts> {
        let opts = system_config::load_from_system_config()?;
        Ok(opts)
    }

    pub fn from_system_config_path<P: AsRef<Path>>(path: P) -> Result<ResolverOpts> {
        let opts = system_config::load_from_system_config_path(path)?;
        Ok(opts)
    }
}

impl Default for ResolverOpts {
    fn default() -> Self {
        ResolverOpts {
            retries: 1,
            max_concurrent_requests: 5,
            ndots: 1,
            preserve_intermediates: false,
            expects_multiple_responses: false,
            timeout: Duration::from_secs(5),
            abort_on_error: true,
            abort_on_timeout: true,
        }
    }
}

#[derive(Debug)]
pub struct ResolverConfigGroup {
    configs: Vec<ResolverConfig>,
}

impl ResolverConfigGroup {
    pub fn new(resolver_configs: Vec<ResolverConfig>) -> ResolverConfigGroup {
        ResolverConfigGroup {
            configs: resolver_configs,
        }
    }

    /// Merges this `ResolverConfigGroup` with another
    pub fn merge(&mut self, other: Self) {
        self.configs.extend(other.configs)
    }
}

impl From<NameServerConfigGroup> for ResolverConfigGroup {
    fn from(configs: NameServerConfigGroup) -> Self {
        let resolver_confings: Vec<_> = configs.into_iter().map(From::from).collect();
        ResolverConfigGroup::new(resolver_confings)
    }
}

impl IntoIterator for ResolverConfigGroup {
    type Item = ResolverConfig;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.configs.into_iter()
    }
}

#[derive(Debug, Clone)]
pub struct Resolver {
    pub(crate) inner: Arc<trust_dns_resolver::TokioAsyncResolver>,
    pub(crate) opts: Arc<ResolverOpts>,
    pub(crate) name_server: Arc<NameServerConfig>,
}

impl Resolver {
    /// Creates a new Resolver.
    ///
    /// May panic if underlying tasks panic
    pub async fn new(config: ResolverConfig, opts: ResolverOpts) -> ResolverResult<Self> {
        let name_server = config.name_server_config.clone();
        let tr_opts = opts.clone().into();
        let tr_resolver = task::spawn(async move {
            trust_dns_resolver::TokioAsyncResolver::tokio(config.into(), tr_opts)
                .map_err(Error::from)
                .await
        })
        .await??;

        Ok(Resolver {
            inner: Arc::new(tr_resolver),
            opts: Arc::new(opts),
            name_server: Arc::new(name_server),
        })
    }

    pub async fn lookup<T: Into<MultiQuery>>(&self, query: T) -> ResolverResult<Lookups> {
        lookup::lookup(self.clone(), query).await
    }

    pub fn name(&self) -> String {
        self.name_server.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct ResolverGroupOpts {
    /// Maximum number of concurrent active resolvers
    pub max_concurrent: usize,
    pub limit: Option<usize>,
}

impl Default for ResolverGroupOpts {
    fn default() -> Self {
        ResolverGroupOpts {
            max_concurrent: 10,
            limit: None,
        }
    }
}

#[derive(Debug)]
pub struct ResolverGroup {
    pub(crate) resolvers: Vec<Resolver>,
    pub(crate) opts: ResolverGroupOpts,
}

impl ResolverGroup {
    pub fn new<T: Into<Vec<Resolver>>>(resolvers: T, opts: ResolverGroupOpts) -> Self {
        ResolverGroup {
            resolvers: resolvers.into(),
            opts,
        }
    }

    pub async fn from_configs<T: IntoIterator<Item = ResolverConfig>>(
        configs: T,
        resolver_opts: ResolverOpts,
        opts: ResolverGroupOpts,
    ) -> Result<Self> {
        // Create resolver futures
        let futures: Vec<_> = configs
            .into_iter()
            .map(|config| Resolver::new(config, resolver_opts.clone()))
            .collect();

        // Wait all futures
        let resolvers: ResolverResult<Vec<_>> = join_all(futures).await.drain(..).collect();

        // Check for Err
        let resolvers = resolvers?;

        Ok(Self::new(resolvers, opts))
    }

    pub async fn from_system_config(opts: ResolverGroupOpts) -> Result<Self> {
        let resolver_opts = ResolverOpts::from_system_config()?;
        let configs: ResolverConfigGroup = NameServerConfigGroup::from_system_config()?.into();
        ResolverGroup::from_configs(configs, resolver_opts, opts).await
    }

    pub async fn lookup<T: Into<MultiQuery>>(&self, query: T) -> ResolverResult<Lookups> {
        let multi_query = query.into();
        let mut resolvers = self.resolvers.clone();

        let lookup_futures: Vec<_> = resolvers
            .drain(..)
            .take(self.opts.limit.unwrap_or_else(|| self.resolvers.len()))
            .map(|resolver| lookup::lookup(resolver, multi_query.clone()))
            .collect();
        let lookups = sliding_window_lookups(lookup_futures, self.opts.max_concurrent);
        let lookups = task::spawn(lookups).await?;

        Ok(lookups)
    }

    pub async fn single_server_lookup<T: Into<MultiQuery>>(&self, query: T) -> ResolverResult<Lookups> {
        let mut rng = rand::thread_rng();
        let multi_query = query.into();
        let resolvers = self.resolvers.as_slice();

        let lookup_futures: Vec<_> = multi_query
            .into_uni_queries()
            .drain(..)
            .map(|q| {
                let resolver = resolvers.choose(&mut rng).unwrap(); // Safe unwrap: we know, there are resolvers
                lookup::lookup(resolver.clone(), q)
            })
            .collect();
        let lookups = sliding_window_lookups(lookup_futures, self.opts.max_concurrent);
        let lookups = task::spawn(lookups).await?;

        Ok(lookups)
    }

    /// Merges this `ResolverGroup` with another
    ///
    /// Attention: the `ResolverGroupOpts` of this `ResolverGroup` will apply
    pub fn merge(&mut self, other: Self) {
        self.resolvers.extend(other.resolvers)
    }

    pub fn add(&mut self, resolver: Resolver) {
        self.resolvers.push(resolver)
    }

    pub fn set_opts(&mut self, opts: ResolverGroupOpts) {
        self.opts = opts
    }

    pub fn opts(&self) -> &ResolverGroupOpts {
        &self.opts
    }

    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }
}

async fn sliding_window_lookups(
    futures: Vec<impl Future<Output = ResolverResult<Lookups>>>,
    max_concurrent: usize,
) -> Lookups {
    stream::iter(futures)
        .buffer_unordered(max_concurrent)
        .collect::<Vec<_>>()
        .await
        .drain(..)
        // This map and the consecutive flatten mask JoinErrors which occurred during the lookups. This is a conscious decision!
        // It doesn't make send to panic (library wouldn't be resilient anymore), return _one_ error and abort by collecting the Vec
        // what would be the semantic of that -- why to bother with catching errors in the first place in lookup.
        // So the only reasonable ways are to ignore the errors or return Vec<Result<>>
        .map(|l| l.ok())
        .flatten()
        .flatten()
        .collect::<Vec<_>>()
        .into()
}

#[doc(hidden)]
impl From<resolv_conf::Config> for ResolverOpts {
    fn from(config: resolv_conf::Config) -> Self {
        ResolverOpts {
            retries: config.attempts as usize,
            ndots: config.ndots as usize,
            timeout: Duration::from_secs(config.timeout as u64),
            ..Default::default()
        }
    }
}

#[doc(hidden)]
impl From<ResolverOpts> for trust_dns_resolver::config::ResolverOpts {
    fn from(opts: ResolverOpts) -> Self {
        trust_dns_resolver::config::ResolverOpts {
            attempts: opts.retries,
            ndots: opts.ndots,
            num_concurrent_reqs: opts.max_concurrent_requests,
            preserve_intermediates: opts.preserve_intermediates,
            timeout: opts.timeout,
            ..Default::default()
        }
    }
}

#[doc(hidden)]
impl From<ResolverConfig> for trust_dns_resolver::config::ResolverConfig {
    fn from(rc: ResolverConfig) -> Self {
        let mut config = Self::new();
        config.add_name_server(rc.name_server_config.into());

        config
    }
}
