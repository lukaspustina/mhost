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

pub struct OpenResolver<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> OpenResolver<'a> {
    pub async fn open_resolver(self) -> PartialResult<OutputCheckResults<'a>> {
        let result = if self.env.mod_config.open_resolver {
            Some(self.do_open_resolver().await?)
        } else {
            None
        };

        Ok(OutputCheckResults {
            env: self.env,
            domain_name: self.domain_name,
            check_results: self.check_results.open_resolver(result),
        })
    }

    async fn do_open_resolver(&self) -> PartialResult<Vec<CheckResult>> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking for open resolver");
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
            print_check_results!(self, results, "No NS records found, cannot check for open resolver.");
            return Ok(results);
        }

        // Resolve NS names to IP addresses
        let query = match MultiQuery::new(ns_names, vec![RecordType::A, RecordType::AAAA]) {
            Ok(q) => q,
            Err(_) => {
                let results = vec![CheckResult::Warning(
                    "Could not resolve NS server addresses for open resolver check".to_string(),
                )];
                print_check_results!(self, results, "No NS records found, cannot check for open resolver.");
                return Ok(results);
            }
        };

        let lookups: Lookups =
            intermediate_lookups!(self, query, "Running lookups for NS server IP addresses for open resolver check.");
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
                "No IP addresses resolved for NS servers: cannot check for open resolver".to_string(),
            )];
            print_check_results!(self, results, "No NS records found, cannot check for open resolver.");
            return Ok(results);
        }

        let results = Self::check_open_resolver(&ns_ips, self.env.app_config).await;

        print_check_results!(self, results, "No NS records found, cannot check for open resolver.");

        Ok(results)
    }

    async fn check_open_resolver(
        ns_ips: &[std::net::IpAddr],
        app_config: &crate::app::AppConfig,
    ) -> Vec<CheckResult> {
        let mut open_ips = Vec::new();
        let probe_name: Name = "www.google.com.".parse().expect("valid probe domain name");

        for ip in ns_ips.iter().take(3) {
            info!("Probing {} for open resolver behavior", ip);

            let ns_config = crate::nameserver::NameServerConfig::udp((*ip, 53));
            let resolver_config = ResolverConfig::new(ns_config);

            match AppResolver::from_configs(vec![resolver_config], app_config).await {
                Ok(probe_resolver) => {
                    if let Ok(query) = MultiQuery::multi_record(probe_name.clone(), vec![RecordType::A]) {
                        match tokio::time::timeout(Duration::from_secs(5), probe_resolver.lookup(query)).await {
                            Ok(Ok(probe_lookups)) if probe_lookups.has_records() => {
                                info!("Open resolver detected at {} - answered recursive query for external domain", ip);
                                open_ips.push(*ip);
                            }
                            Ok(Ok(_)) => {
                                debug!("No records returned from {} for external query (properly configured)", ip);
                            }
                            Ok(Err(e)) => {
                                debug!("Query refused/failed against {} (expected): {}", ip, e);
                            }
                            Err(_) => {
                                debug!("Query timed out against {} (expected)", ip);
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to create resolver for open resolver probe against {}: {}", ip, e);
                }
            }
        }

        classify_open_resolver_results(&open_ips)
    }
}

fn classify_open_resolver_results(open_ips: &[std::net::IpAddr]) -> Vec<CheckResult> {
    if open_ips.is_empty() {
        vec![CheckResult::Ok(
            "No open resolvers detected among authoritative nameservers".to_string(),
        )]
    } else {
        open_ips
            .iter()
            .map(|ip| {
                CheckResult::Failed(format!(
                    "Open resolver detected at {}: answers recursive queries for external domains, enabling DNS amplification attacks",
                    ip
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_open_resolvers() {
        let results = classify_open_resolver_results(&[]);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn one_open_resolver() {
        let ip: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let results = classify_open_resolver_results(&[ip]);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(_)));
        if let CheckResult::Failed(msg) = &results[0] {
            assert!(msg.contains("192.168.1.1"));
            assert!(msg.contains("amplification"));
        }
    }

    #[test]
    fn multiple_open_resolvers() {
        let ip1: std::net::IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let results = classify_open_resolver_results(&[ip1, ip2]);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| matches!(r, CheckResult::Failed(_))));
    }
}
