use crate::error::Error;
use crate::lookup::LookupResult;
use crate::nameserver::NameServerConfig;
use crate::{MultiQuery, Query, Result};

use futures::future::join_all;
use futures::stream::{self, StreamExt};
use futures::TryFutureExt;
use std::sync::Arc;

pub struct ResolverConfig {
    name_server_config: NameServerConfig,
}

impl ResolverConfig {
    pub fn new(name_server_config: NameServerConfig) -> Self {
        ResolverConfig { name_server_config }
    }
}

#[derive(Clone)]
pub struct ResolverOpts {
    /// Maximum number of concurrent queries send with this resolver
    pub max_concurrent: usize,
}

impl Default for ResolverOpts {
    fn default() -> Self {
        ResolverOpts { max_concurrent: 2 }
    }
}

#[derive(Clone)]
pub struct Resolver {
    pub(crate) inner: Arc<trust_dns_resolver::TokioAsyncResolver>,
    pub(crate) opts: Arc<ResolverOpts>,
    pub(crate) name_server: Arc<NameServerConfig>,
}

impl Resolver {
    pub async fn new(config: ResolverConfig, opts: ResolverOpts) -> Result<Self> {
        let name_server = config.name_server_config.clone();
        let tr_opts = trust_dns_resolver::config::ResolverOpts::default();
        let tr_resolver = trust_dns_resolver::TokioAsyncResolver::tokio(config.into(), tr_opts)
            .map_err(Error::from)
            .await?;

        Ok(Resolver {
            inner: Arc::new(tr_resolver),
            opts: Arc::new(opts),
            name_server: Arc::new(name_server),
        })
    }

    pub async fn lookup(&self, query: Query) -> LookupResult {
        LookupResult::lookup(self.clone(), query).await
    }

    pub async fn multi_lookup(&self, multi_query: MultiQuery) -> Vec<LookupResult> {
        LookupResult::multi_lookups(self.clone(), multi_query).await
    }

    pub fn name(&self) -> String {
        self.name_server.to_string()
    }
}

#[derive(Clone)]
pub struct ResolverGroupOpts {
    /// Maximum number of concurrent active resolvers
    pub max_concurrent: usize,
}

impl Default for ResolverGroupOpts {
    fn default() -> Self {
        ResolverGroupOpts { max_concurrent: 10 }
    }
}

pub struct ResolverGroup {
    resolvers: Vec<Resolver>,
    opts: ResolverGroupOpts,
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
        let resolvers: Result<Vec<_>> = join_all(futures).await.into_iter().collect();

        // Check for Err
        let resolvers = resolvers?;

        Ok(Self::new(resolvers, opts))
    }

    pub async fn lookup(&self, query: Query) -> Vec<LookupResult> {
        let futures: Vec<_> = self
            .resolvers
            .iter()
            .map(|resolver| resolver.lookup(query.clone()))
            .collect();

        let lookups: Vec<_> = stream::iter(futures)
            .buffer_unordered(self.opts.max_concurrent)
            .collect()
            .await;

        lookups
    }

    pub async fn multi_lookup(&self, multi_query: MultiQuery) -> Vec<LookupResult> {
        let futures: Vec<_> = self
            .resolvers
            .iter()
            .map(|resolver| resolver.multi_lookup(multi_query.clone()))
            .collect();

        let lookups: Vec<_> = stream::iter(futures)
            .buffer_unordered(self.opts.max_concurrent)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect();

        lookups
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
}

#[doc(hidden)]
impl From<ResolverConfig> for trust_dns_resolver::config::ResolverConfig {
    fn from(rc: ResolverConfig) -> Self {
        let mut config = Self::new();
        config.add_name_server(rc.name_server_config.into());

        config
    }
}
