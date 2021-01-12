use std::iter::FromIterator;
use std::net::IpAddr;

use anyhow::{anyhow, Result};
use indexmap::set::IndexSet;
use tracing::info;

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::cnames::Cnames;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::diff::SetDiffer;
use crate::nameserver::NameServerConfig;
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookups, MultiQuery, ResolverConfig};
use crate::resources::rdata::SOA;
use crate::{Name, RecordType};

pub struct Soa<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> Soa<'a> {
    pub async fn soa(self) -> PartialResult<Cnames<'a>> {
        let result = if self.env.mod_config.soa {
            let results = self.do_soa().await;
            Some(results)
        } else {
            None
        };

        Ok(Cnames {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.soa(result),
        })
    }

    async fn do_soa(&self) -> Vec<CheckResult> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking SOA lints");
        }
        let mut results = Vec::new();

        let authoritative_soa_records = self.check_authoritative_servers(&mut results).await;
        if let Ok(authoritative_soa_records) = authoritative_soa_records {
            self.check_authoritative_records(authoritative_soa_records, &mut results);
        }

        if self.env.console.show_partial_results() {
            for r in &results {
                match r {
                    CheckResult::NotFound() => self.env.console.info("No SOA records found."),
                    CheckResult::Ok(str) => self.env.console.ok(str),
                    CheckResult::Warning(str) => self.env.console.attention(str),
                    CheckResult::Failed(str) => self.env.console.failed(str),
                }
            }
        }

        results
    }

    async fn check_authoritative_servers(&self, results: &mut Vec<CheckResult>) -> Result<Vec<SOA>> {
        if self.env.console.show_partial_headers() {
            self.env.console.itemize("Authoritative SOA records");
        }

        let auth_servers = self.lookup_authoritative_name_servers().await?;
        let name_server_ips = self.lookup_name_server_ips(auth_servers).await?;
        let soas = self.lookup_soa_records(name_server_ips).await;
        if let Err(err) = soas {
            results.push(CheckResult::NotFound());
            return Err(err);
        }

        let records: IndexSet<_> = soas?.soa().unique().to_owned().into_iter().collect();
        let diffs = records.differences();

        let check = match diffs.map(|x| x.len()) {
            Some(diffs) => CheckResult::Failed(format!("Found {} differences in authoritative SOA records", diffs)),
            None => CheckResult::Ok("All authoritative SOA records are in sync".to_string()),
        };
        results.push(check);

        Ok(Vec::from_iter(records))
    }

    async fn lookup_authoritative_name_servers(&self) -> Result<Vec<Name>> {
        let domain_name = self.env.name_builder.from_str(&self.env.mod_config.domain_name)?;
        let query = MultiQuery::single(domain_name, RecordType::NS)?;

        let lookups = intermediate_lookups!(self, query, "Running lookups for authoritative name servers.");
        if !lookups.has_records() {
            return Err(anyhow!("No authoritative name server records found."));
        }

        let auth_severs = lookups.ns().unique().to_owned();

        Ok(Vec::from_iter(auth_severs))
    }

    async fn lookup_name_server_ips(&self, name_servers: Vec<Name>) -> Result<Vec<IpAddr>> {
        let query = MultiQuery::new(name_servers, vec![RecordType::A, RecordType::AAAA])?;

        let lookups = intermediate_lookups!(
            self,
            query,
            "Running lookups for IP addresses of authoritative name servers."
        );
        if !lookups.has_records() {
            return Err(anyhow!("No IP addresses for authoritative nameservers found."));
        }

        let name_server_ips = lookups
            .a()
            .unique()
            .to_owned()
            .into_iter()
            .map(IpAddr::from)
            .chain(lookups.aaaa().unique().to_owned().into_iter().map(IpAddr::from))
            .collect();

        Ok(name_server_ips)
    }

    async fn lookup_soa_records(&self, name_server_ips: Vec<IpAddr>) -> Result<Lookups> {
        let authoritative_name_servers = name_server_ips
            .into_iter()
            .map(|ip| NameServerConfig::udp((ip, 53)))
            .map(ResolverConfig::new);
        let resolvers = AppResolver::from_configs(authoritative_name_servers, &self.env.app_config).await?;
        let query = MultiQuery::single(self.env.mod_config.domain_name.as_str(), RecordType::SOA)?;

        let lookups = intermediate_lookups!(
            self,
            query,
            resolver: resolvers,
            "Running lookups for SOA records from authoritative name servers."
        );
        if !lookups.has_records() {
            return Err(anyhow!("No SOA records from authoritative nameservers found."));
        }

        Ok(lookups)
    }

    fn check_authoritative_records(&self, mut authoritative_soa_records: Vec<SOA>, results: &mut Vec<CheckResult>) {
        if self.env.console.show_partial_headers() {
            self.env
                .console
                .itemize("Comparing authoritative with looked up SOA records");
        }

        let mut lookuped_soa_records = self.check_results.lookups.soa().into_iter().cloned().collect();
        authoritative_soa_records.append(&mut lookuped_soa_records);

        let records: IndexSet<_> = authoritative_soa_records.unique().to_owned().into_iter().collect();
        let diffs = records.differences();

        let check = match diffs.map(|x| x.len()) {
            Some(_) => CheckResult::Failed(format!("Looked up SOA records differ from authoritative SOA records")),
            None => CheckResult::Ok("Looked up SOA records match authoritative SOA records".to_string()),
        };
        results.push(check);
    }
}
