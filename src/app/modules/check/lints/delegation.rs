// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;
use std::time::Duration;

use tracing::{debug, info};

use super::cnames::Cnames;
use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookups, MultiQuery, ResolverConfig};
use crate::{Name, RecordType};

pub struct Delegation<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> Delegation<'a> {
    pub async fn delegation(self) -> PartialResult<Cnames<'a>> {
        let result = if self.env.mod_config.delegation {
            Some(self.do_delegation().await?)
        } else {
            None
        };

        Ok(Cnames {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.delegation(result),
        })
    }

    async fn do_delegation(&self) -> PartialResult<Vec<CheckResult>> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking delegation consistency");
        }

        // Get child NS names from the domain's own records
        let child_ns: HashSet<Name> = self
            .check_results
            .lookups
            .ns()
            .unique()
            .to_owned()
            .into_iter()
            .collect();

        if child_ns.is_empty() {
            let results = vec![CheckResult::NotFound()];
            print_check_results!(self, results, "No NS records found, cannot check delegation.");
            return Ok(results);
        }

        // Compute parent zone
        let parent_zone = self.domain_name.base_name();
        if parent_zone.is_root() {
            let results = vec![CheckResult::Warning(
                "Cannot check delegation for a top-level domain".to_string(),
            )];
            print_check_results!(self, results, "Cannot check delegation for TLD.");
            return Ok(results);
        }

        // Query NS records for the parent zone via the app resolver
        let parent_ns_query = match MultiQuery::multi_record(parent_zone.clone(), vec![RecordType::NS]) {
            Ok(q) => q,
            Err(_) => {
                let results = vec![CheckResult::Warning(
                    "Could not build query for parent zone NS records".to_string(),
                )];
                print_check_results!(self, results, "Cannot check delegation.");
                return Ok(results);
            }
        };

        let parent_zone_lookups: Lookups =
            intermediate_lookups!(self, parent_ns_query, "Looking up parent zone NS records for delegation check.");

        let parent_ns_names: Vec<Name> = parent_zone_lookups.ns().unique().to_owned().into_iter().collect();

        if parent_ns_names.is_empty() {
            let results = vec![CheckResult::Warning(
                "Could not retrieve parent zone NS records".to_string(),
            )];
            print_check_results!(self, results, "No parent NS records found.");
            return Ok(results);
        }

        // Resolve parent NS names to IP addresses
        let resolve_query = match MultiQuery::new(parent_ns_names, vec![RecordType::A, RecordType::AAAA]) {
            Ok(q) => q,
            Err(_) => {
                let results = vec![CheckResult::Warning(
                    "Could not resolve parent NS server addresses for delegation check".to_string(),
                )];
                print_check_results!(self, results, "Cannot resolve parent NS addresses.");
                return Ok(results);
            }
        };

        let ns_lookups: Lookups =
            intermediate_lookups!(self, resolve_query, "Resolving parent NS IP addresses for delegation check.");

        let parent_ns_ips: Vec<std::net::IpAddr> = ns_lookups
            .a()
            .unique()
            .to_owned()
            .into_iter()
            .map(std::net::IpAddr::from)
            .chain(
                ns_lookups
                    .aaaa()
                    .unique()
                    .to_owned()
                    .into_iter()
                    .map(std::net::IpAddr::from),
            )
            .collect();

        if parent_ns_ips.is_empty() {
            let results = vec![CheckResult::Warning(
                "No IP addresses resolved for parent NS servers: cannot check delegation".to_string(),
            )];
            print_check_results!(self, results, "No parent NS IPs resolved.");
            return Ok(results);
        }

        // Query parent NS for the child domain's NS records (delegation records)
        let mut delegation_ns: HashSet<Name> = HashSet::new();

        for ip in parent_ns_ips.iter().take(3) {
            info!("Querying parent NS {} for delegation records of {}", ip, self.domain_name);

            let ns_config = crate::nameserver::NameServerConfig::udp((*ip, 53));
            let resolver_config = ResolverConfig::new(ns_config);

            match AppResolver::from_configs(vec![resolver_config], self.env.app_config).await {
                Ok(parent_resolver) => {
                    if let Ok(query) = MultiQuery::multi_record(self.domain_name.clone(), vec![RecordType::NS]) {
                        match tokio::time::timeout(Duration::from_secs(5), parent_resolver.lookup(query)).await {
                            Ok(Ok(delegation_lookups)) => {
                                for ns in delegation_lookups.ns().unique().to_owned() {
                                    delegation_ns.insert(ns);
                                }
                            }
                            Ok(Err(e)) => {
                                debug!("Delegation query failed against {}: {}", ip, e);
                            }
                            Err(_) => {
                                debug!("Delegation query timed out against {}", ip);
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to create resolver for delegation check against {}: {}", ip, e);
                }
            }
        }

        let results = classify_delegation_results(&child_ns, &delegation_ns);

        print_check_results!(self, results, "Could not check delegation consistency.");

        Ok(results)
    }
}

fn classify_delegation_results(child: &HashSet<Name>, parent: &HashSet<Name>) -> Vec<CheckResult> {
    if parent.is_empty() {
        return vec![CheckResult::Warning(
            "Could not retrieve delegation NS records from parent nameservers".to_string(),
        )];
    }

    if child == parent {
        return vec![CheckResult::Ok(
            "Parent and child NS records are consistent".to_string(),
        )];
    }

    let mut results = Vec::new();

    let missing_from_parent: Vec<&Name> = child.difference(parent).collect();
    for name in &missing_from_parent {
        results.push(CheckResult::Failed(format!(
            "NS {} present in child zone but missing from parent delegation",
            name
        )));
    }

    let extra_in_parent: Vec<&Name> = parent.difference(child).collect();
    for name in &extra_in_parent {
        results.push(CheckResult::Failed(format!(
            "NS {} present in parent delegation but missing from child zone",
            name
        )));
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn set(names: &[&str]) -> HashSet<Name> {
        names.iter().map(|s| name(s)).collect()
    }

    #[test]
    fn matching_sets() {
        let child = set(&["ns1.example.com.", "ns2.example.com."]);
        let parent = set(&["ns1.example.com.", "ns2.example.com."]);
        let results = classify_delegation_results(&child, &parent);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn empty_parent() {
        let child = set(&["ns1.example.com."]);
        let parent = HashSet::new();
        let results = classify_delegation_results(&child, &parent);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn child_has_extra_ns() {
        let child = set(&["ns1.example.com.", "ns2.example.com.", "ns3.example.com."]);
        let parent = set(&["ns1.example.com.", "ns2.example.com."]);
        let results = classify_delegation_results(&child, &parent);
        assert_eq!(results.len(), 1);
        assert!(results.iter().all(|r| matches!(r, CheckResult::Failed(_))));
        if let CheckResult::Failed(msg) = &results[0] {
            assert!(msg.contains("ns3.example.com."));
            assert!(msg.contains("missing from parent"));
        }
    }

    #[test]
    fn parent_has_extra_ns() {
        let child = set(&["ns1.example.com."]);
        let parent = set(&["ns1.example.com.", "ns2.example.com."]);
        let results = classify_delegation_results(&child, &parent);
        assert_eq!(results.len(), 1);
        assert!(results.iter().all(|r| matches!(r, CheckResult::Failed(_))));
        if let CheckResult::Failed(msg) = &results[0] {
            assert!(msg.contains("ns2.example.com."));
            assert!(msg.contains("missing from child"));
        }
    }

    #[test]
    fn disjoint_sets() {
        let child = set(&["ns1.example.com.", "ns2.example.com."]);
        let parent = set(&["ns3.example.com.", "ns4.example.com."]);
        let results = classify_delegation_results(&child, &parent);
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|r| matches!(r, CheckResult::Failed(_))));
    }
}
