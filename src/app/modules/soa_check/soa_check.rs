use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;

use anyhow::Result;
use indexmap::set::IndexSet;
use log::info;

use crate::app::cli::{print_estimates_lookups, print_opts, print_statistics, ExitStatus};
use crate::app::modules::soa_check::config::SoaCheckConfig;
use crate::app::resolver::AppResolver;
use crate::app::{output, GlobalConfig, ModuleStep};
use crate::diff::SetDiffer;
use crate::nameserver::NameServerConfig;
use crate::output::styles::{self, ATTENTION_PREFIX, CAPTION_PREFIX, ERROR_PREFIX, OK_PREFIX};
use crate::resolver::lookup::Uniquify;
use crate::resolver::{MultiQuery, ResolverConfig};
use crate::resources::rdata::SOA;
use crate::{Name, RecordType};

pub struct SoaCheck<'a> {
    global_config: &'a GlobalConfig,
    config: &'a SoaCheckConfig,
    app_resolver: AppResolver,
}

impl<'a> SoaCheck<'a> {
    pub async fn new(global_config: &'a GlobalConfig, config: &'a SoaCheckConfig) -> Result<SoaCheck<'a>> {
        let app_resolver = AppResolver::create_resolvers(global_config).await?;
        Ok(SoaCheck {
            global_config,
            config,
            app_resolver,
        })
    }

    pub async fn lookup_authoritative_name_servers(self) -> Result<ModuleStep<AuthoritativeNameServers<'a>>> {
        AuthoritativeNameServers::lookup(self).await
    }
}

pub struct AuthoritativeNameServers<'a> {
    global_config: &'a GlobalConfig,
    config: &'a SoaCheckConfig,
    app_resolver: AppResolver,
    name_servers: HashSet<Name>,
}

impl<'a> AuthoritativeNameServers<'a> {
    async fn lookup(soa_check: SoaCheck<'a>) -> Result<ModuleStep<AuthoritativeNameServers<'a>>> {
        let global_config = soa_check.global_config;
        let config = soa_check.config;
        let app_resolver = soa_check.app_resolver;

        // NS
        let query = MultiQuery::single(config.domain_name.as_str(), RecordType::NS)?;

        if !global_config.quiet && config.partial_results {
            print_opts(app_resolver.resolver_group_opts(), &app_resolver.resolver_opts());
            if config.partial_results {
                println!(
                    "{}",
                    styles::EMPH.paint(format!("{} Running DNS lookups of name servers.", &*CAPTION_PREFIX))
                );
                print_estimates_lookups(&app_resolver.resolvers(), &query);
            }
        }

        info!("Running lookups for authoritative name servers");
        let start_time = Instant::now();
        let lookups = app_resolver.lookup(query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        if !global_config.quiet && config.partial_results {
            print_statistics(&lookups, total_run_time);
        }
        if config.partial_results {
            output::output(global_config, &lookups)?;
        }
        if !lookups.has_records() {
            println!(
                "{} No authoritative nameservers found. Aborting.",
                styles::ATTENTION.paint(&*ERROR_PREFIX)
            );
            return Ok(ModuleStep::ExitStatus(ExitStatus::Abort));
        }

        let name_servers = lookups.ns().unique().to_owned();

        Ok(ModuleStep::Next(AuthoritativeNameServers {
            global_config,
            config,
            app_resolver,
            name_servers,
        }))
    }
}

impl<'a> ModuleStep<AuthoritativeNameServers<'a>> {
    pub async fn lookup_name_server_ips(self) -> Result<ModuleStep<NameServerIps<'a>>> {
        match self {
            ModuleStep::Next(ans) => NameServerIps::lookup(ans).await,
            ModuleStep::ExitStatus(e) => Ok(ModuleStep::ExitStatus(e)),
        }
    }
}

pub struct NameServerIps<'a> {
    global_config: &'a GlobalConfig,
    config: &'a SoaCheckConfig,
    ips: Vec<IpAddr>,
}

impl<'a> NameServerIps<'a> {
    async fn lookup(
        authoritative_name_server_names: AuthoritativeNameServers<'a>,
    ) -> Result<ModuleStep<NameServerIps<'a>>> {
        let global_config = authoritative_name_server_names.global_config;
        let config = authoritative_name_server_names.config;
        let app_resolver = authoritative_name_server_names.app_resolver;

        let query = MultiQuery::new(
            authoritative_name_server_names.name_servers,
            vec![RecordType::A, RecordType::AAAA],
        )?;
        if !global_config.quiet && config.partial_results {
            println!(
                "{}",
                styles::EMPH.paint(format!(
                    "{} Running DNS lookups of IPv4 and IPv6 addresses of name servers.",
                    &*CAPTION_PREFIX
                ))
            );
            print_estimates_lookups(&app_resolver.resolvers(), &query);
        }

        info!("Running lookups for IP addresses of authoritative name servers");
        let start_time = Instant::now();
        let lookups = app_resolver.lookup(query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        if !global_config.quiet && config.partial_results {
            print_statistics(&lookups, total_run_time);
        }
        if config.partial_results {
            output::output(global_config, &lookups)?;
        }
        if !lookups.has_records() {
            println!(
                "{} No IP addresses for authoritative nameservers found. Aborting.",
                styles::ATTENTION.paint(&*ERROR_PREFIX)
            );
            return Ok(ModuleStep::ExitStatus(ExitStatus::Abort));
        }

        let name_server_ips = lookups
            .a()
            .unique()
            .to_owned()
            .into_iter()
            .map(IpAddr::from)
            .chain(lookups.aaaa().unique().to_owned().into_iter().map(IpAddr::from))
            .collect();

        Ok(ModuleStep::Next(NameServerIps {
            global_config,
            config,
            ips: name_server_ips,
        }))
    }
}

impl<'a> ModuleStep<NameServerIps<'a>> {
    pub async fn lookup_soa_records(self) -> Result<ModuleStep<SoaRecords>> {
        match self {
            ModuleStep::Next(ans) => SoaRecords::lookup(ans).await,
            ModuleStep::ExitStatus(e) => Ok(ModuleStep::ExitStatus(e)),
        }
    }
}

pub struct SoaRecords {
    records: IndexSet<SOA>,
}

impl SoaRecords {
    async fn lookup(name_server_ips: NameServerIps<'_>) -> Result<ModuleStep<SoaRecords>> {
        let global_config = name_server_ips.global_config;
        let config = name_server_ips.config;

        let authoritative_name_servers = name_server_ips
            .ips
            .into_iter()
            .map(|ip| NameServerConfig::udp((ip, 53)))
            .map(ResolverConfig::new);
        let resolvers = AppResolver::from_configs(authoritative_name_servers, &global_config).await?;

        let query = MultiQuery::single(config.domain_name.as_str(), RecordType::SOA)?;
        if !global_config.quiet {
            println!(
                "{}",
                styles::EMPH.paint(format!("{} Running DNS lookups for SOA records.", &*CAPTION_PREFIX))
            );
            print_estimates_lookups(&resolvers.resolvers(), &query);
        }

        info!("Running lookups for SOA records of authoritative name servers");
        let start_time = Instant::now();
        let lookups = resolvers.lookup(query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        if !global_config.quiet {
            print_statistics(&lookups, total_run_time);
        }
        output::output(global_config, &lookups)?;
        if !lookups.has_records() {
            println!(
                "{} No SOA records from authoritative nameservers found. Aborting.",
                styles::ATTENTION.paint(&*ERROR_PREFIX)
            );
            return Ok(ModuleStep::ExitStatus(ExitStatus::Abort));
        }

        let soa_records: IndexSet<_> = lookups.soa().unique().to_owned().into_iter().collect();

        Ok(ModuleStep::Next(SoaRecords { records: soa_records }))
    }
}

impl<'a> ModuleStep<SoaRecords> {
    pub fn diff(self) -> Result<ExitStatus> {
        match self {
            ModuleStep::Next(soa_records) => SoaDiff::diff(soa_records),
            ModuleStep::ExitStatus(e) => Ok(e),
        }
    }
}

pub struct SoaDiff {}

impl SoaDiff {
    fn diff(soa_records: SoaRecords) -> Result<ExitStatus> {
        let diffs = soa_records.records.differences();

        if let Some(diffs) = diffs {
            println!(
                "{} Found deviations in SOA records: ",
                styles::ATTENTION.paint(&*ATTENTION_PREFIX),
            );
            println!("{:?}", diffs);
            Ok(ExitStatus::CheckFailed)
        } else {
            println!("{} All SOA records in sync.", styles::OK.paint(&*OK_PREFIX),);
            Ok(ExitStatus::Ok)
        }
    }
}
