// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

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
use tracing::{debug, info};

pub struct NameBuilderOpts {
    ndots: u8,
    search_domain: Name,
}

impl NameBuilderOpts {
    pub fn new<T: IntoName>(ndots: u8, search_domain: T) -> Result<Self> {
        let search_domain = search_domain
            .into_name()
            .context("failed to parse search domain name")?;
        Ok(NameBuilderOpts { ndots, search_domain })
    }

    /// Creates a new `NameBuilderOpts` by using the domain name from the local host's hostname as search domain.
    pub fn from_hostname(ndots: u8) -> Result<Self> {
        let hostname = hostname::get()
            .context("failed to get local hostname")?
            .to_string_lossy()
            .to_string();
        let name = Name::from_str(&hostname)
            .context("failed to parse local hostname")?;
        let search_domain = name.base_name();
        NameBuilderOpts::new(ndots, search_domain)
    }
}

impl Default for NameBuilderOpts {
    fn default() -> Self {
        NameBuilderOpts::new(1, Name::root()).unwrap()
    }
}

/** NameBuilder offers a safe way to transform a string into a `Name`.
 *
 * `NameBuilder` takes the search domain into account by checking `ndots` to qualify a name as FQDN or not.
 */
pub struct NameBuilder {
    config: NameBuilderOpts,
}

impl NameBuilder {
    pub fn new(config: NameBuilderOpts) -> NameBuilder {
        NameBuilder { config }
    }

    /// Creates a `Name` from a &str.
    ///
    /// In case the given name has less or equal lables (dots) as configures by `NameBuilderConfig::ndots` the search
    /// domain `NameBuilderConfig::search_domain` is added to resulting `Name`.
    ///
    /// Example:
    /// ```
    /// # use mhost::app::resolver::{NameBuilderOpts, NameBuilder};
    /// # use mhost::Name;
    /// let config = NameBuilderOpts::new(1, "example.com").unwrap();
    /// let builder = NameBuilder::new(config);
    /// let name = builder.from_str("www").unwrap();
    /// assert_eq!(name, Name::from_ascii("www.example.com.").unwrap())
    /// ```
    pub fn from_str(&self, name: &str) -> Result<Name> {
        let mut domain_name: Name = name.into_name().context("failed to parse domain name")?;
        let domain_name = if domain_name.num_labels() > self.config.ndots {
            domain_name.set_fqdn(true);
            domain_name
        } else {
            domain_name.append_domain(&self.config.search_domain)
        };

        Ok(domain_name)
    }
}

pub struct AppResolver {
    resolvers: Arc<ResolverGroup>,
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
        })
    }

    pub async fn lookup(&self, query: MultiQuery) -> Result<Lookups> {
        self.resolvers
            .clone()
            .lookup(query)
            .await
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
        let configs: crate::Result<Vec<_>> = join_all(configs).await.into_iter().collect();
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
        mode: config.resolvers_mode,
    };
    info!("Loaded resolver group opts.");

    Ok(resolver_group_opts)
}

pub fn load_resolver_opts(config: &AppConfig) -> Result<ResolverOpts> {
    let app_config_opts = ResolverOpts {
        ndots: config.ndots as usize,
        // cf. trust_dns_resolver::config::ResolverOpts: Preserve all intermediate records in the lookup response, suchas CNAME records
        preserve_intermediates: true,
        expects_multiple_responses: config.expects_multiple_responses,
        timeout: config.timeout,
        abort_on_error: config.abort_on_error,
        retries: config.retries,
        max_concurrent_requests: config.max_concurrent_requests,
        abort_on_timeout: config.abort_on_timeout,
    };
    let opts = if config.use_system_resolv_opt {
        let sys_opts = ResolverOpts::from_system_config_path(&config.resolv_conf_path)
            .context("Failed to load system resolver options")?;
        ResolverOpts {
            retries: sys_opts.retries,
            ndots: sys_opts.ndots,
            timeout: sys_opts.timeout,
            ..app_config_opts
        }
    } else {
        app_config_opts
    };

    info!("Loaded resolver opts.");
    debug!("Resolver opts: {:?}", &opts);

    Ok(opts)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_builder_1ndots_0dot() {
        let config = NameBuilderOpts::new(1, "example.com").unwrap();
        let builder = NameBuilder::new(config);
        let name = builder.from_str("www").unwrap();

        assert_eq!(name, Name::from_ascii("www.example.com.").unwrap())
    }

    #[test]
    fn name_builder_1ndots_1dot() {
        let config = NameBuilderOpts::new(1, "example.com").unwrap();
        let builder = NameBuilder::new(config);
        let name = builder.from_str("www.").unwrap();

        assert_eq!(name, Name::from_ascii("www.example.com.").unwrap())
    }

    #[test]
    fn name_builder_1ndots_1dot_2lables() {
        let config = NameBuilderOpts::new(1, "example.com").unwrap();
        let builder = NameBuilder::new(config);
        let name = builder.from_str("www.test").unwrap();

        assert_eq!(name, Name::from_ascii("www.test.").unwrap())
    }

    #[test]
    fn name_builder_1ndots_1dot_3lables() {
        let config = NameBuilderOpts::new(1, "example.com").unwrap();
        let builder = NameBuilder::new(config);
        let name = builder.from_str("www.test.com").unwrap();

        assert_eq!(name, Name::from_ascii("www.test.com.").unwrap())
    }
}
