// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::https_svcb::HttpsSvcb;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::resolver::lookup::Uniquify;
use crate::resources::rdata::DNSSEC;
use crate::Name;

pub struct DnssecCheck<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> DnssecCheck<'a> {
    pub fn dnssec(self) -> PartialResult<HttpsSvcb<'a>> {
        let result = if self.env.mod_config.dnssec {
            Some(self.do_dnssec())
        } else {
            None
        };

        Ok(HttpsSvcb {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.dnssec(result),
        })
    }

    fn do_dnssec(&self) -> Vec<CheckResult> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking DNSSEC lints");
        }
        let mut results = Vec::new();

        let unique_dnssec = self.check_results.lookups.dnssec().unique();
        let dnssec_records: Vec<&DNSSEC> = unique_dnssec.iter().collect();

        Self::check_dnssec_presence(&dnssec_records, &mut results);

        if !dnssec_records.is_empty() {
            Self::check_dnssec_key_types(&dnssec_records, &mut results);
        }

        if self.env.console.show_partial_results() {
            for r in &results {
                match r {
                    CheckResult::NotFound() => self.env.console.info("No DNSSEC records found."),
                    CheckResult::Ok(str) => self.env.console.ok(str),
                    CheckResult::Warning(str) => self.env.console.attention(str),
                    CheckResult::Failed(str) => self.env.console.failed(str),
                }
            }
        }

        results
    }

    fn check_dnssec_presence(records: &[&DNSSEC], results: &mut Vec<CheckResult>) {
        if records.is_empty() {
            results.push(CheckResult::Warning(
                "No DNSSEC records found: domain is not DNSSEC-signed, DNS responses cannot be authenticated"
                    .to_string(),
            ));
        } else {
            let sub_types: Vec<&str> = records.iter().map(|r| r.sub_type()).collect();
            results.push(CheckResult::Ok(format!(
                "Domain has DNSSEC records: {}",
                sub_types.join(", ")
            )));
        }
    }

    fn check_dnssec_key_types(records: &[&DNSSEC], results: &mut Vec<CheckResult>) {
        let has_dnskey = records.iter().any(|r| r.sub_type() == "DNSKEY");
        let has_rrsig = records.iter().any(|r| r.sub_type() == "RRSIG");

        if has_dnskey && has_rrsig {
            results.push(CheckResult::Ok(
                "DNSKEY and RRSIG records present: DNSSEC chain appears complete".to_string(),
            ));
        } else if has_dnskey && !has_rrsig {
            results.push(CheckResult::Warning(
                "DNSKEY present but no RRSIG records found: DNSSEC signatures may be missing".to_string(),
            ));
        } else if !has_dnskey && has_rrsig {
            results.push(CheckResult::Warning(
                "RRSIG present but no DNSKEY records found: DNSSEC validation may fail".to_string(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_presence_empty() {
        let mut results = Vec::new();
        DnssecCheck::check_dnssec_presence(&[], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_presence_found() {
        let mut results = Vec::new();
        let dnskey = DNSSEC::new("DNSKEY".to_string(), "256 3 8 key".to_string());
        DnssecCheck::check_dnssec_presence(&[&dnskey], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_key_types_complete() {
        let mut results = Vec::new();
        let dnskey = DNSSEC::new("DNSKEY".to_string(), "data".to_string());
        let rrsig = DNSSEC::new("RRSIG".to_string(), "data".to_string());
        DnssecCheck::check_dnssec_key_types(&[&dnskey, &rrsig], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_key_types_missing_rrsig() {
        let mut results = Vec::new();
        let dnskey = DNSSEC::new("DNSKEY".to_string(), "data".to_string());
        DnssecCheck::check_dnssec_key_types(&[&dnskey], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_key_types_missing_dnskey() {
        let mut results = Vec::new();
        let rrsig = DNSSEC::new("RRSIG".to_string(), "data".to_string());
        DnssecCheck::check_dnssec_key_types(&[&rrsig], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }
}
