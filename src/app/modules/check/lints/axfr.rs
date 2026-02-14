// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::time::Duration;

use tracing::{debug, info};

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::{CheckResult, CheckResults, OutputCheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookups, MultiQuery, ResolverConfig};
use crate::{Name, RecordType};

pub struct Axfr<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> Axfr<'a> {
    pub async fn axfr(self) -> PartialResult<OutputCheckResults<'a>> {
        let result = if self.env.mod_config.axfr {
            Some(self.do_axfr().await?)
        } else {
            None
        };

        Ok(OutputCheckResults {
            env: self.env,
            domain_name: self.domain_name,
            check_results: self.check_results.axfr(result),
        })
    }

    async fn do_axfr(&self) -> PartialResult<Vec<CheckResult>> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking AXFR zone transfer security");
        }

        let ns_names: Vec<Name> = self
            .check_results
            .lookups
            .ns()
            .unique()
            .to_owned()
            .into_iter()
            .collect();

        if ns_names.is_empty() {
            let results = vec![CheckResult::NotFound()];
            print_check_results!(self, results, "No NS records found, cannot check AXFR.");
            return Ok(results);
        }

        // Resolve NS names to IP addresses
        let query = match MultiQuery::new(ns_names, vec![RecordType::A, RecordType::AAAA]) {
            Ok(q) => q,
            Err(_) => {
                let results = vec![CheckResult::Warning(
                    "Could not resolve NS server addresses for AXFR check".to_string(),
                )];
                print_check_results!(self, results, "No NS records found, cannot check AXFR.");
                return Ok(results);
            }
        };

        let lookups: Lookups = intermediate_lookups!(self, query, "Running lookups for NS server IP addresses for AXFR check.");
        let ns_ips: Vec<std::net::IpAddr> = lookups
            .a()
            .unique()
            .to_owned()
            .into_iter()
            .map(std::net::IpAddr::from)
            .chain(lookups.aaaa().unique().to_owned().into_iter().map(std::net::IpAddr::from))
            .collect();

        if ns_ips.is_empty() {
            let results = vec![CheckResult::Warning(
                "No IP addresses resolved for NS servers: cannot check AXFR".to_string(),
            )];
            print_check_results!(self, results, "No NS records found, cannot check AXFR.");
            return Ok(results);
        }

        let results = Self::check_axfr(&self.domain_name, &ns_ips, &self.app_resolver, self.env.app_config).await;

        print_check_results!(self, results, "No NS records found, cannot check AXFR.");

        Ok(results)
    }

    async fn check_axfr(
        domain_name: &Name,
        ns_ips: &[std::net::IpAddr],
        _app_resolver: &AppResolver,
        app_config: &crate::app::AppConfig,
    ) -> Vec<CheckResult> {
        let mut vulnerable_ips = Vec::new();

        for ip in ns_ips.iter().take(3) {
            info!("Trying AXFR against {} for security check", ip);

            let ns_config = crate::nameserver::NameServerConfig::tcp((*ip, 53));
            let resolver_config = ResolverConfig::new(ns_config);

            match AppResolver::from_configs(vec![resolver_config], app_config).await {
                Ok(axfr_resolver) => {
                    if let Ok(query) = MultiQuery::multi_record(domain_name.clone(), vec![RecordType::AXFR]) {
                        match tokio::time::timeout(Duration::from_secs(5), axfr_resolver.lookup(query)).await {
                            Ok(Ok(axfr_lookups)) if axfr_lookups.has_records() => {
                                info!("AXFR succeeded against {} - zone transfer is publicly accessible!", ip);
                                vulnerable_ips.push((*ip, axfr_lookups.records().len()));
                            }
                            Ok(Ok(_)) => {
                                debug!("AXFR returned no records from {}", ip);
                            }
                            Ok(Err(e)) => {
                                debug!("AXFR refused/failed against {} (expected): {}", ip, e);
                            }
                            Err(_) => {
                                debug!("AXFR timed out against {} (expected)", ip);
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to create resolver for AXFR against {}: {}", ip, e);
                }
            }
        }

        classify_axfr_results(&vulnerable_ips)
    }
}

fn classify_axfr_results(vulnerable_ips: &[(std::net::IpAddr, usize)]) -> Vec<CheckResult> {
    if vulnerable_ips.is_empty() {
        vec![CheckResult::Ok(
            "Zone transfer (AXFR) properly restricted".to_string(),
        )]
    } else {
        vulnerable_ips
            .iter()
            .map(|(ip, count)| {
                CheckResult::Failed(format!(
                    "Zone transfer publicly accessible from {} ({} records returned): attackers can enumerate all DNS records",
                    ip, count
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_axfr_no_vulnerable_ips() {
        let results = classify_axfr_results(&[]);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_axfr_one_vulnerable() {
        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let results = classify_axfr_results(&[(ip, 42)]);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(_)));
        if let CheckResult::Failed(msg) = &results[0] {
            assert!(msg.contains("192.168.1.1"));
            assert!(msg.contains("42 records"));
        }
    }

    #[test]
    fn check_axfr_multiple_vulnerable() {
        let ip1: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let results = classify_axfr_results(&[(ip1, 10), (ip2, 20)]);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| matches!(r, CheckResult::Failed(_))));
    }
}
