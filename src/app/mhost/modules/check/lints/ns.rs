// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use tracing::info;

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::delegation::Delegation;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::nameserver::NameServerConfig;
use crate::resolver::lookup::Uniquify;
use crate::resolver::{MultiQuery, ResolverConfig};
use crate::{Name, RecordType};

use super::check_ns_count;

pub struct Ns<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> Ns<'a> {
    pub async fn ns(self) -> PartialResult<Delegation<'a>> {
        let result = if self.env.mod_config.ns {
            let results = self.do_ns().await?;
            Some(results)
        } else {
            None
        };

        Ok(Delegation {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.ns(result),
        })
    }

    async fn do_ns(&self) -> PartialResult<Vec<CheckResult>> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking NS delegation lints");
        }

        let mut results = check_ns_count(&self.check_results.lookups);

        let ns_names: Vec<Name> = self
            .check_results
            .lookups
            .ns()
            .unique()
            .to_owned()
            .into_iter()
            .collect();

        if !ns_names.is_empty() {
            self.check_delegation_and_diversity(&ns_names, &mut results).await?;
        }

        print_check_results!(self, results, "No NS records found.");

        Ok(results)
    }

    async fn check_delegation_and_diversity(
        &self,
        ns_names: &[Name],
        results: &mut Vec<CheckResult>,
    ) -> PartialResult<()> {
        // Resolve NS names to IPs (shared for both lame delegation and diversity checks)
        if self.env.console.show_partial_headers() {
            self.env.console.itemize("Lame delegation");
        }

        let query = match MultiQuery::new(ns_names.to_vec(), vec![RecordType::A, RecordType::AAAA]) {
            Ok(q) => q,
            Err(_) => {
                results.push(CheckResult::Warning(
                    "Could not resolve NS server addresses".to_string(),
                ));
                return Ok(());
            }
        };

        let lookups = intermediate_lookups!(self, query, "Running lookups for NS server IP addresses.");
        let ipv4s: Vec<Ipv4Addr> = lookups.a().unique().to_owned().into_iter().collect();
        let ns_ips: Vec<IpAddr> = ipv4s
            .iter()
            .copied()
            .map(IpAddr::from)
            .chain(lookups.aaaa().unique().to_owned().into_iter().map(IpAddr::from))
            .collect();

        if ns_ips.is_empty() {
            results.push(CheckResult::Failed(
                "No IP addresses resolved for NS servers: possible lame delegation".to_string(),
            ));
            return Ok(());
        }

        // Lame delegation check: query each NS server directly for SOA
        let authoritative_configs = ns_ips
            .iter()
            .map(|ip| NameServerConfig::udp((*ip, 53)))
            .map(ResolverConfig::new);
        let resolvers = match AppResolver::from_configs(authoritative_configs, self.env.app_config).await {
            Ok(r) => r,
            Err(_) => {
                results.push(CheckResult::Warning(
                    "Could not create resolvers for NS lame delegation check".to_string(),
                ));
                return Ok(());
            }
        };
        let query = match MultiQuery::single(self.env.mod_config.domain_name.as_str(), RecordType::SOA) {
            Ok(q) => q,
            Err(_) => return Ok(()),
        };

        let soa_lookups = intermediate_lookups!(
            self,
            query,
            resolver: resolvers,
            "Running SOA lookups against NS servers to detect lame delegation."
        );

        let ipv4_total = ipv4s.len();
        let ipv6_total = ns_ips.len() - ipv4_total;

        let mut ipv4_responding = 0usize;
        let mut ipv6_responding = 0usize;
        for lookup in soa_lookups.iter() {
            if lookup.result().is_response() {
                if nameserver_ip(lookup.name_server()).is_ipv6() {
                    ipv6_responding += 1;
                } else {
                    ipv4_responding += 1;
                }
            }
        }

        if ipv4_responding == ipv4_total && ipv6_responding == ipv6_total {
            results.push(CheckResult::Ok(format!(
                "All {} NS servers respond authoritatively",
                ns_ips.len()
            )));
        } else if ipv4_responding == ipv4_total && ipv6_responding < ipv6_total {
            results.push(CheckResult::Ok(format!(
                "All {} NS servers respond authoritatively via IPv4",
                ipv4_total
            )));
            results.push(CheckResult::Warning(format!(
                "Only {}/{} IPv6 NS addresses respond: possible client IPv6 connectivity issue",
                ipv6_responding, ipv6_total
            )));
        } else {
            let responding = ipv4_responding + ipv6_responding;
            results.push(CheckResult::Failed(format!(
                "Only {}/{} NS servers respond authoritatively: possible lame delegation",
                responding,
                ns_ips.len()
            )));
        }

        // Network diversity check using already-resolved IPv4 addresses
        if self.env.console.show_partial_headers() {
            self.env.console.itemize("NS network diversity");
        }
        Self::check_network_diversity(&ipv4s, results);
        Ok(())
    }

    fn check_network_diversity(ips: &[Ipv4Addr], results: &mut Vec<CheckResult>) {
        if ips.len() < 2 {
            return;
        }

        let networks: HashSet<[u8; 3]> = ips
            .iter()
            .map(|ip| {
                let octets = ip.octets();
                [octets[0], octets[1], octets[2]]
            })
            .collect();

        if networks.len() == 1 {
            results.push(CheckResult::Warning(
                "All NS servers are in the same /24 network: a single network failure could make the domain unreachable"
                    .to_string(),
            ));
        } else {
            results.push(CheckResult::Ok(format!(
                "NS servers are distributed across {} different /24 networks",
                networks.len()
            )));
        }
    }
}

fn nameserver_ip(ns: &NameServerConfig) -> &IpAddr {
    match ns {
        NameServerConfig::Udp { ip_addr, .. }
        | NameServerConfig::Tcp { ip_addr, .. }
        | NameServerConfig::Tls { ip_addr, .. }
        | NameServerConfig::Https { ip_addr, .. } => ip_addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_network_diversity_same_network() {
        let mut results = Vec::new();
        let ips = vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)];
        Ns::check_network_diversity(&ips, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_network_diversity_different_networks() {
        let mut results = Vec::new();
        let ips = vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 0, 0, 1)];
        Ns::check_network_diversity(&ips, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_network_diversity_single_ip() {
        let mut results = Vec::new();
        let ips = vec![Ipv4Addr::new(192, 168, 1, 1)];
        Ns::check_network_diversity(&ips, &mut results);
        assert!(results.is_empty()); // Not enough IPs to check
    }
}
