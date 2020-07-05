use crate::error::Error;
use crate::lookup::Lookup;
use crate::nameserver::NameServerConfig;
use crate::Result;

use futures::TryFutureExt;
use std::sync::Arc;
use trust_dns_resolver::proto::rr::RecordType;
use trust_dns_resolver::IntoName;

pub struct ResolverConfig {
    name_server_config: NameServerConfig,
}

impl ResolverConfig {
    pub fn new(name_server_config: NameServerConfig) -> Self {
        ResolverConfig { name_server_config }
    }
}

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

    pub async fn lookup<N: IntoName>(&self, name: N, record_type: RecordType) -> Result<Lookup> {
        let name = name.into_name().map_err(Error::from)?;
        let lookup = Lookup::lookup(self.clone(), name, record_type).await;

        Ok(lookup)
    }

    pub async fn multi_lookups<N: IntoName, T: Into<Vec<RecordType>>>(
        &self,
        name: N,
        record_types: T,
    ) -> Result<Vec<Lookup>> {
        let name = name.into_name().map_err(Error::from)?;
        let record_types = record_types.into();
        let lookups = Lookup::multi_lookups(self.clone(), name, record_types).await;

        Ok(lookups)
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
