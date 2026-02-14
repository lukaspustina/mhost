// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::dnssec_lint::DnssecCheck;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::resolver::lookup::Uniquify;
use crate::resources::{Record, RecordType};
use crate::Name;

const MIN_TTL: u32 = 60;
const MAX_NS_MX_TTL: u32 = 604_800; // 1 week
const MAX_SOA_MINIMUM: u32 = 86_400; // 1 day

pub struct Ttl<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> Ttl<'a> {
    pub fn ttl(self) -> PartialResult<DnssecCheck<'a>> {
        let result = if self.env.mod_config.ttl {
            Some(self.do_ttl())
        } else {
            None
        };

        Ok(DnssecCheck {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.ttl(result),
        })
    }

    fn do_ttl(&self) -> Vec<CheckResult> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking TTL sanity lints");
        }
        let mut results = Vec::new();

        let records: Vec<&Record> = self.check_results.lookups.records();

        Self::check_low_ttls(&records, &mut results);
        Self::check_high_ns_mx_ttls(&records, &mut results);
        Self::check_soa_minimum_ttl(&self.check_results.lookups, &mut results);

        if self.env.console.show_partial_results() {
            for r in &results {
                match r {
                    CheckResult::NotFound() => self.env.console.info("No records to check TTLs."),
                    CheckResult::Ok(str) => self.env.console.ok(str),
                    CheckResult::Warning(str) => self.env.console.attention(str),
                    CheckResult::Failed(str) => self.env.console.failed(str),
                }
            }
        }

        results
    }

    fn check_low_ttls(records: &[&Record], results: &mut Vec<CheckResult>) {
        let low_ttl_records: Vec<String> = records
            .iter()
            .filter(|r| r.ttl() < MIN_TTL && r.ttl() > 0)
            .map(|r| format!("{} ({}s, {:?})", r.name(), r.ttl(), r.record_type()))
            .collect();

        if low_ttl_records.is_empty() {
            results.push(CheckResult::Ok(format!("No records with TTL below {}s", MIN_TTL)));
        } else {
            results.push(CheckResult::Warning(format!(
                "Records with very low TTL (<{}s): {}. This causes excessive query load",
                MIN_TTL,
                low_ttl_records.join(", ")
            )));
        }
    }

    fn check_high_ns_mx_ttls(records: &[&Record], results: &mut Vec<CheckResult>) {
        let high_ttl_records: Vec<String> = records
            .iter()
            .filter(|r| {
                (r.record_type() == RecordType::NS || r.record_type() == RecordType::MX) && r.ttl() > MAX_NS_MX_TTL
            })
            .map(|r| format!("{} ({}s, {:?})", r.name(), r.ttl(), r.record_type()))
            .collect();

        if high_ttl_records.is_empty() {
            results.push(CheckResult::Ok(
                "No NS/MX records with excessively high TTL".to_string(),
            ));
        } else {
            results.push(CheckResult::Warning(format!(
                "NS/MX records with TTL over 1 week: {}. This makes DNS migrations dangerously slow",
                high_ttl_records.join(", ")
            )));
        }
    }

    fn check_soa_minimum_ttl(lookups: &crate::resolver::Lookups, results: &mut Vec<CheckResult>) {
        let unique_soa = lookups.soa().unique();
        let soa_records: Vec<_> = unique_soa.iter().collect();
        for soa in &soa_records {
            if soa.minimum() > MAX_SOA_MINIMUM {
                results.push(CheckResult::Warning(format!(
                    "SOA minimum TTL is {}s (>{} day): high negative caching TTL can delay propagation of new records",
                    soa.minimum(),
                    MAX_SOA_MINIMUM / 86_400
                )));
                return;
            }
        }
        if !soa_records.is_empty() {
            results.push(CheckResult::Ok(
                "SOA minimum TTL is within reasonable range".to_string(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_low_ttls_all_ok() {
        let records: Vec<&Record> = vec![];
        let mut results = Vec::new();
        Ttl::check_low_ttls(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_high_ns_mx_ttls_ok() {
        let records: Vec<&Record> = vec![];
        let mut results = Vec::new();
        Ttl::check_high_ns_mx_ttls(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_soa_minimum_ok() {
        use crate::resolver::Lookups;
        let lookups = Lookups::empty();
        let mut results = Vec::new();
        Ttl::check_soa_minimum_ttl(&lookups, &mut results);
        assert!(results.is_empty()); // No SOA records to check
    }
}
