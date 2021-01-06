use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::anyhow;
use indexmap::set::IndexSet;
use tracing::{debug, info};

use crate::app::modules::soa_check::config::SoaCheckConfig;
use crate::app::modules::{AppModule, Environment, PartialError, PartialResult};
use crate::app::output::OutputType;
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::app::{AppConfig, ExitStatus};
use crate::diff::SetDiffer;
use crate::nameserver::NameServerConfig;
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookups, MultiQuery, ResolverConfig};
use crate::{Name, RecordType};

pub struct SoaCheck {}

impl AppModule<SoaCheckConfig> for SoaCheck {}

impl SoaCheck {
    pub async fn init<'a>(
        app_config: &'a AppConfig,
        config: &'a SoaCheckConfig,
    ) -> PartialResult<AuthoritativeNameServers<'a>> {
        if app_config.output == OutputType::Json && config.partial_results {
            return Err(anyhow!("JSON output is incompatible with partial result output").into());
        }

        let env = Self::init_env(app_config, config)?;
        let domain_name = env.name_builder.from_str(&config.domain_name)?;
        let query = MultiQuery::single(domain_name, RecordType::NS)?;
        debug!("Querying: {:?}", query);
        let app_resolver = AppResolver::create_resolvers(app_config).await?;

        env.console
            .print_resolver_opts(app_resolver.resolver_group_opts(), &app_resolver.resolver_opts());

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
    pub async fn lookup_authoritative_name_servers(self) -> PartialResult<NameServerIps<'a>> {
        self.env.console.print_partial_headers(
            "Running lookups for authoritative name servers.",
            &self.app_resolver.resolvers(),
            &self.query,
        );

        info!("Running lookups for authoritative name servers.");
        let (lookups, run_time) = time(self.app_resolver.lookup(self.query)).await?;
        info!("Finished Lookups.");

        self.env
            .console
            .print_partial_results(&self.env.app_config.output_config, &lookups, run_time)?;

        if !lookups.has_records() {
            self.env.console.failed("No records found. Aborting.");
            return Err(PartialError::Failed(ExitStatus::Abort));
        }

        let name_servers = lookups.ns().unique().to_owned();

        Ok(NameServerIps {
            env: self.env,
            app_resolver: self.app_resolver,
            name_servers,
        })
    }
}

pub struct NameServerIps<'a> {
    env: Environment<'a, SoaCheckConfig>,
    app_resolver: AppResolver,
    name_servers: HashSet<Name>,
}

impl<'a> NameServerIps<'a> {
    pub async fn lookup_name_server_ips(self) -> PartialResult<SoaRecords<'a>> {
        let query = MultiQuery::new(self.name_servers, vec![RecordType::A, RecordType::AAAA])?;

        self.env.console.print_partial_headers(
            "Running lookups for IP addresses of authoritative name servers.",
            &self.app_resolver.resolvers(),
            &query,
        );

        info!("Running lookups for IP addresses of authoritative name servers.");
        let (lookups, run_time) = time(self.app_resolver.lookup(query)).await?;
        info!("Finished Lookups.");

        self.env
            .console
            .print_partial_results(&self.env.app_config.output_config, &lookups, run_time)?;

        if !lookups.has_records() {
            self.env
                .console
                .failed("No IP addresses for authoritative nameservers found. Aborting.");
            return Err(PartialError::Failed(ExitStatus::Abort));
        }

        let name_server_ips = lookups
            .a()
            .unique()
            .to_owned()
            .into_iter()
            .map(IpAddr::from)
            .chain(lookups.aaaa().unique().to_owned().into_iter().map(IpAddr::from))
            .collect();

        Ok(SoaRecords {
            env: self.env,
            name_server_ips,
        })
    }
}

pub struct SoaRecords<'a> {
    env: Environment<'a, SoaCheckConfig>,
    name_server_ips: Vec<IpAddr>,
}

impl<'a> SoaRecords<'a> {
    pub async fn lookup_soa_records(self) -> PartialResult<OutputSoaCheckResult<'a>> {
        let authoritative_name_servers = self
            .name_server_ips
            .into_iter()
            .map(|ip| NameServerConfig::udp((ip, 53)))
            .map(ResolverConfig::new);
        let resolvers = AppResolver::from_configs(authoritative_name_servers, &self.env.app_config).await?;
        let query = MultiQuery::single(self.env.mod_config.domain_name.as_str(), RecordType::SOA)?;

        self.env.console.print_partial_headers(
            "Running lookups for SOA records from authoritative name servers.",
            &resolvers.resolvers(),
            &query,
        );

        info!("Running lookups for SOA records from authoritative name servers.");
        let (lookups, run_time) = time(resolvers.lookup(query)).await?;
        info!("Finished Lookups.");

        self.env
            .console
            .print_partial_results(&self.env.app_config.output_config, &lookups, run_time)?;

        if !lookups.has_records() {
            self.env
                .console
                .failed("No SOA records from authoritative nameservers found. Aborting.");
            return Err(PartialError::Failed(ExitStatus::Abort));
        }

        Ok(OutputSoaCheckResult {
            env: self.env,
            soa_lookups: lookups,
        })
    }
}

pub struct OutputSoaCheckResult<'a> {
    env: Environment<'a, SoaCheckConfig>,
    soa_lookups: Lookups,
}

impl<'a> OutputSoaCheckResult<'a> {
    pub fn output(self) -> PartialResult<ExitStatus> {
        let records: IndexSet<_> = self.soa_lookups.soa().unique().to_owned().into_iter().collect();
        let diffs = records.differences();

        self.env.console.print_finished();

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
