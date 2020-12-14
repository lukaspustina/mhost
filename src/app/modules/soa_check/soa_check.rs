use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Instant;

use anyhow::{anyhow, Result};
use indexmap::set::IndexSet;
use log::info;

use crate::app::console::Console;
use crate::app::modules::soa_check::config::SoaCheckConfig;
use crate::app::modules::{Environment, Partial};
use crate::app::output::OutputType;
use crate::app::resolver::AppResolver;
use crate::app::{console, AppConfig, ExitStatus};
use crate::diff::SetDiffer;
use crate::nameserver::NameServerConfig;
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookups, MultiQuery, ResolverConfig};
use crate::{Name, RecordType};

pub struct SoaCheck {}

impl SoaCheck {
    pub async fn init<'a>(
        app_config: &'a AppConfig,
        config: &'a SoaCheckConfig,
    ) -> Result<AuthoritativeNameServers<'a>> {
        if app_config.output == OutputType::Json && config.partial_results {
            return Err(anyhow!("JSON output is incompatible with partial result output"));
        }
        let console = Console::with_partial_results(app_config, config.partial_results);
        let env = Environment::new(app_config, config, console);

        let query = MultiQuery::single(config.domain_name.as_str(), RecordType::NS)?;
        let app_resolver = AppResolver::create_resolvers(app_config).await?;

        if env.console.not_quiet() {
            env.console
                .print_opts(app_resolver.resolver_group_opts(), &app_resolver.resolver_opts());
        }

        Ok(AuthoritativeNameServers {
            env,
            query,
            app_resolver,
        })
    }
}

pub struct AuthoritativeNameServers<'a> {
    env: Environment<'a, SoaCheckConfig>,
    query: MultiQuery,
    app_resolver: AppResolver,
}

impl<'a> AuthoritativeNameServers<'a> {
    pub async fn lookup_authoritative_name_servers(self) -> Result<Partial<NameServerIps<'a>>> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Running DNS lookups of name servers.");
            self.env
                .console
                .print_estimates_lookups(&self.app_resolver.resolvers(), &self.query);
        }

        info!("Running lookups for authoritative name servers");
        let start_time = Instant::now();
        let lookups = self.app_resolver.lookup(self.query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        console::print_partial_results(
            &self.env.console,
            &self.env.app_config.output_config,
            &lookups,
            total_run_time,
        )?;

        if !lookups.has_records() {
            self.env.console.failed("No authoritative nameservers found. Aborting.");
            return Ok(Partial::ExitStatus(ExitStatus::Abort));
        }

        let name_servers = lookups.ns().unique().to_owned();

        Ok(Partial::Next(NameServerIps {
            env: self.env,
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
    env: Environment<'a, SoaCheckConfig>,
    app_resolver: AppResolver,
    name_servers: HashSet<Name>,
}

impl<'a> NameServerIps<'a> {
    async fn lookup_name_server_ips(self) -> Result<Partial<SoaRecords<'a>>> {
        let query = MultiQuery::new(self.name_servers, vec![RecordType::A, RecordType::AAAA])?;

        if self.env.console.show_partial_headers() {
            self.env
                .console
                .caption("Running DNS lookups of IPv4 and IPv6 addresses of name servers.");
            self.env
                .console
                .print_estimates_lookups(&self.app_resolver.resolvers(), &query);
        }

        info!("Running lookups for IP addresses of authoritative name servers");
        let start_time = Instant::now();
        let lookups = self.app_resolver.lookup(query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        console::print_partial_results(
            &self.env.console,
            &self.env.app_config.output_config,
            &lookups,
            total_run_time,
        )?;

        if !lookups.has_records() {
            self.env
                .console
                .failed("No IP addresses for authoritative nameservers found. Aborting.");
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
            env: self.env,
            name_server_ips,
        }))
    }
}

impl<'a> Partial<SoaRecords<'a>> {
    pub async fn lookup_soa_records(self) -> Result<Partial<SoaCheckResult<'a>>> {
        match self {
            Partial::Next(next) => next.lookup_soa_records().await,
            Partial::ExitStatus(e) => Ok(Partial::ExitStatus(e)),
        }
    }
}

pub struct SoaRecords<'a> {
    env: Environment<'a, SoaCheckConfig>,
    name_server_ips: Vec<IpAddr>,
}

impl<'a> SoaRecords<'a> {
    async fn lookup_soa_records(self) -> Result<Partial<SoaCheckResult<'a>>> {
        let authoritative_name_servers = self
            .name_server_ips
            .into_iter()
            .map(|ip| NameServerConfig::udp((ip, 53)))
            .map(ResolverConfig::new);
        let resolvers = AppResolver::from_configs(authoritative_name_servers, &self.env.app_config).await?;
        let query = MultiQuery::single(self.env.mod_config.domain_name.as_str(), RecordType::SOA)?;

        if self.env.console.show_partial_headers() {
            self.env.console.caption("Running DNS lookups for SOA records.");
            self.env.console.print_estimates_lookups(&resolvers.resolvers(), &query);
        }

        info!("Running lookups for SOA records of authoritative name servers");
        let start_time = Instant::now();
        let lookups = resolvers.lookup(query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        console::print_partial_results(
            &self.env.console,
            &self.env.app_config.output_config,
            &lookups,
            total_run_time,
        )?;

        if !lookups.has_records() {
            self.env
                .console
                .failed("No SOA records from authoritative nameservers found. Aborting.");
            return Ok(Partial::ExitStatus(ExitStatus::Abort));
        }

        Ok(Partial::Next(SoaCheckResult {
            env: self.env,
            soa_lookups: lookups,
        }))
    }
}

impl<'a> Partial<SoaCheckResult<'a>> {
    pub fn output(self) -> Result<ExitStatus> {
        match self {
            Partial::Next(next) => next.output(),
            Partial::ExitStatus(e) => Ok(e),
        }
    }
}

pub struct SoaCheckResult<'a> {
    env: Environment<'a, SoaCheckConfig>,
    soa_lookups: Lookups,
}

impl<'a> SoaCheckResult<'a> {
    pub fn output(self) -> Result<ExitStatus> {
        let records: IndexSet<_> = self.soa_lookups.soa().unique().to_owned().into_iter().collect();
        let diffs = records.differences();

        if self.env.console.not_quiet() {
            self.env.console.finished();
        }

        if let Some(diffs) = diffs {
            self.env.console.attention("Found deviations in SOA records: ");
            self.env.console.info(format!("{:?}", diffs));
            Ok(ExitStatus::CheckFailed)
        } else {
            self.env.console.ok("All SOA records in sync.");
            Ok(ExitStatus::Ok)
        }
    }
}
