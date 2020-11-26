use crate as mhost;
use crate::app::GlobalConfig;
use crate::nameserver::{predefined, NameServerConfig, NameServerConfigGroup, Protocol};
use crate::resolver::{
    Lookups, MultiQuery, ResolverConfig, ResolverConfigGroup, ResolverGroup, ResolverGroupOpts, ResolverOpts,
};
use crate::{IpNetwork, RecordType};
use anyhow::{anyhow, Context, Result};
use futures::future::join_all;
use log::info;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

pub struct AppQuery {}

impl AppQuery {
    pub fn query(domain_name: &str, record_types: &[RecordType]) -> Result<MultiQuery> {
        if let Ok(ip_network) = IpNetwork::from_str(domain_name) {
            Self::ptr_query(ip_network)
        } else {
            Self::name_query(domain_name, record_types)
        }
    }

    fn ptr_query(ip_network: IpNetwork) -> Result<MultiQuery> {
        let q = MultiQuery::multi_name(ip_network.iter(), RecordType::PTR).context("Failed to create query")?;
        info!("Prepared query for reverse lookups.");
        Ok(q)
    }

    fn name_query(name: &str, record_types: &[RecordType]) -> Result<MultiQuery> {
        let record_types_len = record_types.len();
        let q = MultiQuery::multi_record(name, record_types.to_vec()).context("Failed to build query")?;
        info!("Prepared query for name lookup for {} record types.", record_types_len);
        Ok(q)
    }
}

pub struct AppResolver {
    resolvers: Arc<ResolverGroup>,
    single_server_lookup: bool,
}

impl AppResolver {
    pub async fn from_configs<T: IntoIterator<Item = ResolverConfig>>(
        configs: T,
        global_config: &GlobalConfig,
    ) -> Result<AppResolver> {
        let resolver_group_opts = load_resolver_group_opts(&global_config)?;
        let resolver_opts = load_resolver_opts(&global_config)?;

        let resolvers = ResolverGroup::from_configs(configs, resolver_opts, resolver_group_opts).await?;
        if resolvers.is_empty() {
            return Err(anyhow!("empty resolver group"));
        }
        Ok(AppResolver {
            resolvers: Arc::new(resolvers),
            single_server_lookup: false,
        })
    }

    pub async fn create_resolvers(config: &GlobalConfig) -> Result<AppResolver> {
        let resolver_group_opts = load_resolver_group_opts(&config)?;
        let resolver_opts = load_resolver_opts(&config)?;

        let system_resolver_group: ResolverConfigGroup = load_system_nameservers(config)?.into();
        let mut system_resolvers = ResolverGroup::from_configs(
            system_resolver_group,
            resolver_opts.clone(),
            resolver_group_opts.clone(),
        )
        .await
        .context("Failed to create system resolvers")?;
        info!("Created {} system resolvers.", system_resolvers.len());

        let resolver_group: ResolverConfigGroup = load_nameservers(config, &mut system_resolvers).await?.into();
        let mut resolvers = ResolverGroup::from_configs(resolver_group, resolver_opts, resolver_group_opts)
            .await
            .context("Failed to load resolvers")?;
        info!("Created {} resolvers.", resolvers.len());

        resolvers.merge(system_resolvers);

        Ok(AppResolver {
            resolvers: Arc::new(resolvers),
            single_server_lookup: false,
        })
    }

    pub fn with_single_server_lookup(self, single_server_lookup: bool) -> AppResolver {
        AppResolver {
            resolvers: self.resolvers,
            single_server_lookup,
        }
    }

    pub async fn lookup(&self, query: MultiQuery) -> Result<Lookups> {
        if self.single_server_lookup {
            info!("Running in single server lookup mode");
            self.resolvers.clone().single_server_lookup(query).await
        } else {
            info!("Running in normal mode");
            self.resolvers.clone().lookup(query).await
        }
        .context("Failed to execute lookups")
    }

    pub fn resolvers(&self) -> &ResolverGroup {
        &self.resolvers
    }

    pub fn resolver_group_opts(&self) -> &ResolverGroupOpts {
        &self.resolvers.opts()
    }

    pub fn resolver_opts(&self) -> &ResolverOpts {
        &self.resolvers.resolvers()[0].opts.as_ref() // Safe, because we created resolver
    }
}

async fn load_nameservers(
    config: &GlobalConfig,
    system_resolvers: &mut ResolverGroup,
) -> Result<NameServerConfigGroup> {
    let mut nameservers_group = NameServerConfigGroup::new(Vec::new());
    if let Some(configs) = &config.nameservers {
        let configs: Vec<_> = configs
            .iter()
            .map(|str| NameServerConfig::from_str_with_resolution(&system_resolvers, str))
            .collect();
        let configs: mhost::Result<Vec<_>> = join_all(configs).await.into_iter().collect();
        let nameservers: Vec<_> = configs.context("Failed to parse IP address for system nameserver")?;
        let nameservers = NameServerConfigGroup::new(nameservers);
        info!("Loaded {} nameservers.", nameservers.len());
        nameservers_group.merge(nameservers);
    }
    if config.predefined {
        let filter: HashSet<Protocol> = config
            .predefined_filter
            .as_ref()
            .unwrap() // safe unwrap, because set by default by clap
            .iter()
            .map(|x| Protocol::from_str(x.as_str()))
            .flatten()
            .collect();
        let nameservers: Vec<_> = predefined::nameserver_configs()
            .into_iter()
            .filter(|x| filter.contains(&x.protocol()))
            .collect();
        let nameservers = NameServerConfigGroup::new(nameservers);
        info!("Loaded {} nameservers.", nameservers.len());
        nameservers_group.merge(nameservers);
    }
    if let Some(path) = config.nameserver_file_path.as_ref() {
        let nameservers = NameServerConfigGroup::from_file(&system_resolvers, path)
            .await
            .context("Failed to load nameservers from file")?;
        info!("Loaded {} nameservers from file.", nameservers.len());
        nameservers_group.merge(nameservers);
    }

    Ok(nameservers_group)
}

pub fn load_resolver_group_opts(config: &GlobalConfig) -> Result<ResolverGroupOpts> {
    let resolver_group_opts = ResolverGroupOpts {
        max_concurrent: config.max_concurrent_servers,
        limit: Some(config.limit),
    };
    info!("Loaded resolver group opts.");

    Ok(resolver_group_opts)
}

pub fn load_resolver_opts(config: &GlobalConfig) -> Result<ResolverOpts> {
    let default_opts = if config.ignore_system_resolv_opt {
        Default::default()
    } else {
        ResolverOpts::from_system_config_path(&config.resolv_conf_path)
            .context("Failed to load system resolver options")?
    };
    let resolver_opts = config.resolver_opts(default_opts);
    info!("Loaded resolver opts.");

    Ok(resolver_opts)
}

pub fn load_system_nameservers(config: &GlobalConfig) -> Result<NameServerConfigGroup> {
    let mut system_nameserver_group = NameServerConfigGroup::new(Vec::new());

    if !config.ignore_system_nameservers {
        let resolv_conf_path = &config.resolv_conf_path;
        let nameservers = NameServerConfigGroup::from_system_config_path(resolv_conf_path)
            .context("Failed to load system name servers")?;
        info!(
            "Loaded {} system nameservers from '{}'.",
            nameservers.len(),
            resolv_conf_path
        );
        system_nameserver_group.merge(nameservers);
    };

    if let Some(configs) = config.system_nameservers.as_ref() {
        let configs: Vec<_> = configs.iter().map(|x| NameServerConfig::from_str(x.as_str())).collect();
        let configs: std::result::Result<Vec<_>, _> = configs.into_iter().collect();
        let nameservers: Vec<_> = configs.context("Failed to parse IP address for system nameserver")?;
        let nameservers = NameServerConfigGroup::new(nameservers);
        info!("Loaded {} additional system nameservers.", nameservers.len());
        system_nameserver_group.merge(nameservers);
    };

    Ok(system_nameserver_group)
}
