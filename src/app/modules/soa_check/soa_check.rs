use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;

use anyhow::Result;
use indexmap::set::IndexSet;
use log::info;

use crate::app::cli::{print_estimates_lookups, print_opts, print_statistics, ExitStatus};
use crate::app::modules::soa_check::config::SoaCheckConfig;
use crate::app::resolver::AppResolver;
use crate::app::{output, GlobalConfig, Partial};
use crate::diff::SetDiffer;
use crate::nameserver::NameServerConfig;
use crate::output::styles::{self, ATTENTION_PREFIX, CAPTION_PREFIX, ERROR_PREFIX, OK_PREFIX};
use crate::resolver::lookup::Uniquify;
use crate::resolver::{MultiQuery, ResolverConfig};
use crate::resources::rdata::SOA;
use crate::{Name, RecordType};

pub struct SoaCheck {}

impl SoaCheck {
    pub async fn init<'a>(
        global_config: &'a GlobalConfig,
        config: &'a SoaCheckConfig,
    ) -> Result<AuthoritativeNameServers<'a>> {
        let query = MultiQuery::single(config.domain_name.as_str(), RecordType::NS)?;
        let app_resolver = AppResolver::create_resolvers(global_config).await?;

        Ok(AuthoritativeNameServers {
            global_config,
            config,
            query,
            app_resolver,
        })
    }
}

pub struct AuthoritativeNameServers<'a> {
    global_config: &'a GlobalConfig,
    config: &'a SoaCheckConfig,
    query: MultiQuery,
    app_resolver: AppResolver,
}

impl<'a> AuthoritativeNameServers<'a> {
    pub async fn lookup_authoritative_name_servers(self) -> Result<Partial<NameServerIps<'a>>> {
        if !self.global_config.quiet && self.config.partial_results {
            print_opts(
                self.app_resolver.resolver_group_opts(),
                &self.app_resolver.resolver_opts(),
            );
            if self.config.partial_results {
                println!(
                    "{}",
                    styles::EMPH.paint(format!("{} Running DNS lookups of name servers.", &*CAPTION_PREFIX))
                );
                print_estimates_lookups(&self.app_resolver.resolvers(), &self.query);
            }
        }

        info!("Running lookups for authoritative name servers");
        let start_time = Instant::now();
        let lookups = self.app_resolver.lookup(self.query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        if !self.global_config.quiet && self.config.partial_results {
            print_statistics(&lookups, total_run_time);
        }
        if self.config.partial_results {
            output::output(&self.global_config.output_config, &lookups)?;
        }
        if !lookups.has_records() {
            println!(
                "{} No authoritative nameservers found. Aborting.",
                styles::ATTENTION.paint(&*ERROR_PREFIX)
            );
            return Ok(Partial::ExitStatus(ExitStatus::Abort));
        }

        let name_servers = lookups.ns().unique().to_owned();

        Ok(Partial::Next(NameServerIps {
            global_config: self.global_config,
            config: self.config,
            app_resolver: self.app_resolver,
            name_servers,
        }))
    }
}

impl<'a> Partial<NameServerIps<'a>> {
    pub async fn lookup_name_server_ips(self) -> Result<Partial<SoaRecords<'a>>> {
        match self {
            Partial::Next(next) => next.lookup_name_server_ips().await,
            Partial::ExitStatus(e) => Ok(Partial::ExitStatus(e)),
        }
    }
}

pub struct NameServerIps<'a> {
    global_config: &'a GlobalConfig,
    config: &'a SoaCheckConfig,
    app_resolver: AppResolver,
    name_servers: HashSet<Name>,
}

impl<'a> NameServerIps<'a> {
    async fn lookup_name_server_ips(self) -> Result<Partial<SoaRecords<'a>>> {
        let query = MultiQuery::new(self.name_servers, vec![RecordType::A, RecordType::AAAA])?;
        if !self.global_config.quiet && self.config.partial_results {
            println!(
                "{}",
                styles::EMPH.paint(format!(
                    "{} Running DNS lookups of IPv4 and IPv6 addresses of name servers.",
                    &*CAPTION_PREFIX
                ))
            );
            print_estimates_lookups(&self.app_resolver.resolvers(), &query);
        }

        info!("Running lookups for IP addresses of authoritative name servers");
        let start_time = Instant::now();
        let lookups = self.app_resolver.lookup(query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        if !self.global_config.quiet && self.config.partial_results {
            print_statistics(&lookups, total_run_time);
        }
        if self.config.partial_results {
            output::output(&self.global_config.output_config, &lookups)?;
        }
        if !lookups.has_records() {
            println!(
                "{} No IP addresses for authoritative nameservers found. Aborting.",
                styles::ATTENTION.paint(&*ERROR_PREFIX)
            );
            return Ok(Partial::ExitStatus(ExitStatus::Abort));
        }

        let name_server_ips = lookups
            .a()
            .unique()
            .to_owned()
            .into_iter()
            .map(IpAddr::from)
            .chain(lookups.aaaa().unique().to_owned().into_iter().map(IpAddr::from))
            .collect();

        Ok(Partial::Next(SoaRecords {
            global_config: self.global_config,
            config: self.config,
            name_server_ips,
        }))
    }
}

impl<'a> Partial<SoaRecords<'a>> {
    pub async fn lookup_soa_records(self) -> Result<Partial<SoaDiff>> {
        match self {
            Partial::Next(next) => next.lookup_soa_records().await,
            Partial::ExitStatus(e) => Ok(Partial::ExitStatus(e)),
        }
    }
}

pub struct SoaRecords<'a> {
    global_config: &'a GlobalConfig,
    config: &'a SoaCheckConfig,
    name_server_ips: Vec<IpAddr>,
}

impl<'a> SoaRecords<'a> {
    async fn lookup_soa_records(self) -> Result<Partial<SoaDiff>> {
        let authoritative_name_servers = self
            .name_server_ips
            .into_iter()
            .map(|ip| NameServerConfig::udp((ip, 53)))
            .map(ResolverConfig::new);
        let resolvers = AppResolver::from_configs(authoritative_name_servers, &self.global_config).await?;

        let query = MultiQuery::single(self.config.domain_name.as_str(), RecordType::SOA)?;
        if !self.global_config.quiet {
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

        if !self.global_config.quiet {
            print_statistics(&lookups, total_run_time);
        }
        output::output(&self.global_config.output_config, &lookups)?;
        if !lookups.has_records() {
            println!(
                "{} No SOA records from authoritative nameservers found. Aborting.",
                styles::ATTENTION.paint(&*ERROR_PREFIX)
            );
            return Ok(Partial::ExitStatus(ExitStatus::Abort));
        }

        let soa_records: IndexSet<_> = lookups.soa().unique().to_owned().into_iter().collect();

        Ok(Partial::Next(SoaDiff { records: soa_records }))
    }
}

impl<'a> Partial<SoaDiff> {
    pub fn diff(self) -> Result<ExitStatus> {
        match self {
            Partial::Next(next) => next.diff(),
            Partial::ExitStatus(e) => Ok(e),
        }
    }
}

pub struct SoaDiff {
    records: IndexSet<SOA>,
}

impl SoaDiff {
    pub fn diff(self) -> Result<ExitStatus> {
        let diffs = self.records.differences();

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
