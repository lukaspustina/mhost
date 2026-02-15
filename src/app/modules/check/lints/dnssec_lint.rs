// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::axfr::Axfr;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::Name;

struct DnssecCounts {
    dnskey: usize,
    ds: usize,
    rrsig: usize,
    nsec: usize,
    nsec3: usize,
    nsec3param: usize,
}

impl DnssecCounts {
    fn total(&self) -> usize {
        self.dnskey + self.ds + self.rrsig + self.nsec + self.nsec3 + self.nsec3param
    }
}

pub struct DnssecCheck<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> DnssecCheck<'a> {
    pub fn dnssec(self) -> PartialResult<Axfr<'a>> {
        let result = if self.env.mod_config.dnssec {
            Some(self.do_dnssec())
        } else {
            None
        };

        Ok(Axfr {
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

        let counts = DnssecCounts {
            dnskey: self.check_results.lookups.dnskey().len(),
            ds: self.check_results.lookups.ds().len(),
            rrsig: self.check_results.lookups.rrsig().len(),
            nsec: self.check_results.lookups.nsec().len(),
            nsec3: self.check_results.lookups.nsec3().len(),
            nsec3param: self.check_results.lookups.nsec3param().len(),
        };

        Self::check_dnssec_presence(&counts, &mut results);

        if counts.total() > 0 {
            Self::check_dnssec_key_types(counts.dnskey > 0, counts.rrsig > 0, &mut results);
        }

        print_check_results!(self, results, "No DNSSEC records found.");

        results
    }

    fn check_dnssec_presence(counts: &DnssecCounts, results: &mut Vec<CheckResult>) {
        if counts.total() == 0 {
            results.push(CheckResult::Warning(
                "No DNSSEC records found: domain is not DNSSEC-signed, DNS responses cannot be authenticated"
                    .to_string(),
            ));
        } else {
            let mut types = Vec::new();
            if counts.dnskey > 0 {
                types.push("DNSKEY");
            }
            if counts.ds > 0 {
                types.push("DS");
            }
            if counts.rrsig > 0 {
                types.push("RRSIG");
            }
            if counts.nsec > 0 {
                types.push("NSEC");
            }
            if counts.nsec3 > 0 {
                types.push("NSEC3");
            }
            if counts.nsec3param > 0 {
                types.push("NSEC3PARAM");
            }
            results.push(CheckResult::Ok(format!(
                "Domain has DNSSEC records: {}",
                types.join(", ")
            )));
        }
    }

    fn check_dnssec_key_types(has_dnskey: bool, has_rrsig: bool, results: &mut Vec<CheckResult>) {
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

    fn counts(dnskey: usize, ds: usize, rrsig: usize, nsec: usize, nsec3: usize, nsec3param: usize) -> DnssecCounts {
        DnssecCounts {
            dnskey,
            ds,
            rrsig,
            nsec,
            nsec3,
            nsec3param,
        }
    }

    #[test]
    fn check_presence_empty() {
        let mut results = Vec::new();
        DnssecCheck::check_dnssec_presence(&counts(0, 0, 0, 0, 0, 0), &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_presence_found() {
        let mut results = Vec::new();
        DnssecCheck::check_dnssec_presence(&counts(1, 0, 1, 0, 0, 0), &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_key_types_complete() {
        let mut results = Vec::new();
        DnssecCheck::check_dnssec_key_types(true, true, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_key_types_missing_rrsig() {
        let mut results = Vec::new();
        DnssecCheck::check_dnssec_key_types(true, false, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_key_types_missing_dnskey() {
        let mut results = Vec::new();
        DnssecCheck::check_dnssec_key_types(false, true, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }
}
