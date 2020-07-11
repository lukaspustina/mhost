use crate::error::Error;
use crate::lookup::Lookup;
use crate::nameserver::NameServerConfig;
use crate::{MultiQuery, Query, Result};

use futures::TryFutureExt;
use futures::future::join_all;
use futures::stream::{self, StreamExt};
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
    pub(crate) name: Arc<Option<String>>,
    pub(crate) opts: Arc<ResolverOpts>,
}

impl Resolver {
    pub async fn new(config: ResolverConfig, opts: ResolverOpts) -> Result<Self> {
        let tr_opts = trust_dns_resolver::config::ResolverOpts::default();
        let tr_resolver = trust_dns_resolver::TokioAsyncResolver::tokio(config.into(), tr_opts)
            .map_err(Error::from)
            .await?;

        Ok(Resolver {
            inner: Arc::new(tr_resolver),
            name: Arc::new(None),
            opts: Arc::new(opts),
        })
    }

    pub async fn lookup(&self, q: Query) -> Lookup {
        Lookup::lookup(self.clone(), q).await
    }

    pub async fn multi_lookup(&self, mq: MultiQuery) -> Vec<Lookup> {
        Lookup::multi_lookups(self.clone(), mq).await
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

    pub async fn from_configs<T: IntoIterator<Item=ResolverConfig>>(configs: T, resolver_opts: ResolverOpts, opts: ResolverGroupOpts) -> Result<Self> {
        // Create resolver futures
        let futures: Vec<_> = configs.into_iter()
            .map(|config|
                Resolver::new(config, resolver_opts.clone())
            )
            .collect();

        // Wait all futures
        let resolvers: Result<Vec<_>> = join_all(futures)
            .await
            .into_iter()
            .collect();

        // Check for Err
        let resolvers = resolvers?;

        Ok(Self::new(resolvers, opts))
    }

    pub async fn lookup(&self, q: Query) -> Vec<Lookup> {
        // TODO: q.clone should be cheap -> Use Arc
        let futures: Vec<_> = self.resolvers.iter().map(|resolver| resolver.lookup(q.clone())).collect();

        let lookups: Vec<_> = stream::iter(futures)
            .buffer_unordered(self.opts.max_concurrent)
            .collect()
            .await;

        lookups
    }

    pub async fn multi_lookup(&self, mq: MultiQuery) -> Vec<Lookup> {
        // TODO: q.clone should be cheap -> Use Arc
        let futures: Vec<_> = self.resolvers.iter().map(|resolver| resolver.multi_lookup(mq.clone())).collect();

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


mod internal {
    use super::ResolverConfig;

    impl From<ResolverConfig> for trust_dns_resolver::config::ResolverConfig {
        fn from(rc: ResolverConfig) -> Self {
            let mut config = Self::new();
            config.add_name_server(rc.name_server_config.into());

            config
        }
    }
}
