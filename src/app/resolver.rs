use crate as mhost;
use crate::app::AppConfig;
use crate::nameserver::{predefined, NameServerConfig, NameServerConfigGroup, Protocol};
use crate::resolver::{
    Lookups, MultiQuery, ResolverConfig, ResolverConfigGroup, ResolverGroup, ResolverGroupOpts, ResolverOpts,
};
use crate::{IntoName, Name};
use anyhow::{anyhow, Context, Result};
use futures::future::join_all;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use tracing::info;

/** NameBuilder offers a safe way to transform a string into a `Name``
 *
 * `NameBuilder` takes `AppConfig` into account. For examples `ndots` is used to qualify a name a FQDN or not.
 */
pub struct NameBuilder {
    ndots: u8,
}

impl NameBuilder {
    pub fn new(app_config: &AppConfig) -> NameBuilder {
        NameBuilder {
            ndots: app_config.ndots,
        }
    }

    pub fn from_str(&self, str: &str) -> Result<Name> {
        let mut domain_name: Name = str.into_name().context("failed to parse domain name")?;
        if domain_name.num_labels() > self.ndots {
            domain_name.set_fqdn(true)
        }

        Ok(domain_name)
    }
}

pub struct AppResolver {
    resolvers: Arc<ResolverGroup>,
    single_server_lookup: bool,
}

impl AppResolver {
    pub async fn from_configs<T: IntoIterator<Item = ResolverConfig>>(
        configs: T,
        app_config: &AppConfig,
    ) -> Result<AppResolver> {
        let resolver_group_opts = load_resolver_group_opts(&app_config)?;
        let resolver_opts = load_resolver_opts(&app_config)?;

        let resolvers = ResolverGroup::from_configs(configs, resolver_opts, resolver_group_opts).await?;
        if resolvers.is_empty() {
            return Err(anyhow!("empty resolver group"));
        }
        Ok(AppResolver {
            resolvers: Arc::new(resolvers),
            single_server_lookup: false,
        })
    }

    pub async fn create_resolvers(app_config: &AppConfig) -> Result<AppResolver> {
        let resolver_group_opts = load_resolver_group_opts(&app_config)?;
        let resolver_opts = load_resolver_opts(&app_config)?;

        let system_resolver_group: ResolverConfigGroup = load_system_nameservers(app_config)?.into();
        let mut system_resolvers = ResolverGroup::from_configs(
            system_resolver_group,
            resolver_opts.clone(),
            resolver_group_opts.clone(),
        )
        .await
        .context("Failed to create system resolvers")?;
        info!("Created {} system resolvers.", system_resolvers.len());

        let resolver_group: ResolverConfigGroup = load_nameservers(app_config, &mut system_resolvers).await?.into();
        let mut resolvers = ResolverGroup::from_configs(resolver_group, resolver_opts, resolver_group_opts)
            .await
            .context("Failed to load resolvers")?;
        info!("Created {} resolvers.", resolvers.len());

        if !app_config.no_system_lookups {
            resolvers.merge(system_resolvers);
        }

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

async fn load_nameservers(config: &AppConfig, system_resolvers: &mut ResolverGroup) -> Result<NameServerConfigGroup> {
    let mut nameservers_group = NameServerConfigGroup::new(Vec::new());
    if let Some(configs) = &config.nameservers {
        let configs: Vec<_> = configs
            .iter()
            .map(|str| NameServerConfig::from_str_with_resolution(&system_resolvers, str))
            .collect();
        let configs: mhost::Result<Vec<_>> = join_all(configs).await.into_iter().collect();
        let nameservers: Vec<_> = configs.context("Failed to parse IP address for nameserver")?;
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

pub fn load_resolver_group_opts(config: &AppConfig) -> Result<ResolverGroupOpts> {
    let resolver_group_opts = ResolverGroupOpts {
        max_concurrent: config.max_concurrent_servers,
        limit: Some(config.limit),
    };
    info!("Loaded resolver group opts.");

    Ok(resolver_group_opts)
}

pub fn load_resolver_opts(config: &AppConfig) -> Result<ResolverOpts> {
    let default_opts = if config.ignore_system_resolv_opt {
        ResolverOpts {
            ndots: config.ndots as usize,
            ..Default::default()
        }
    } else {
        ResolverOpts {
            // TODO: This is not correct. We should take the value from resolv.conf and only apply app_config.ndots if given
            ndots: config.ndots as usize,
            ..ResolverOpts::from_system_config_path(&config.resolv_conf_path)
                .context("Failed to load system resolver options")?
        }
    };
    let resolver_opts = config.resolver_opts(default_opts);
    info!("Loaded resolver opts.");

    Ok(resolver_opts)
}

pub fn load_system_nameservers(config: &AppConfig) -> Result<NameServerConfigGroup> {
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
