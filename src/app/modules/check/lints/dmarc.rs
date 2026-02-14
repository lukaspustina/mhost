// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use tracing::info;

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::caa::CaaCheck;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::resolver::lookup::Uniquify;
use crate::resolver::MultiQuery;
use crate::resources::rdata::parsed_txt;
use crate::{Name, RecordType};

pub struct DmarcCheck<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> DmarcCheck<'a> {
    pub async fn dmarc(self) -> PartialResult<CaaCheck<'a>> {
        let result = if self.env.mod_config.dmarc {
            Some(self.do_dmarc().await?)
        } else {
            None
        };

        Ok(CaaCheck {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.dmarc(result),
        })
    }

    async fn do_dmarc(&self) -> PartialResult<Vec<CheckResult>> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking DMARC TXT records lints");
        }
        let mut results = Vec::new();

        // Look up _dmarc.<domain> TXT records
        let dmarc_name = format!("_dmarc.{}", self.env.mod_config.domain_name);
        let query = match MultiQuery::single(dmarc_name.as_str(), RecordType::TXT) {
            Ok(q) => q,
            Err(_) => {
                results.push(CheckResult::Warning(
                    "Could not construct DMARC lookup query".to_string(),
                ));
                return Ok(results);
            }
        };

        if self.env.console.show_partial_headers() {
            self.env.console.itemize("DMARC record lookup");
        }

        let lookups = intermediate_lookups!(self, query, "Running lookups for DMARC TXT records.");

        let dmarc_txts: Vec<String> = lookups
            .txt()
            .unique()
            .iter()
            .map(|txt| txt.as_string())
            .filter(|s| is_dmarc(s))
            .collect();

        Self::check_num_of_dmarc_records(&dmarc_txts, &mut results);
        Self::check_parsed_dmarc_records(&dmarc_txts, &mut results);

        print_check_results!(self, results, "No DMARC record found.");

        Ok(results)
    }

    fn check_num_of_dmarc_records(dmarcs: &[String], results: &mut Vec<CheckResult>) {
        let check = match dmarcs.len() {
            0 => CheckResult::Warning(
                "No DMARC record found: without DMARC, email spoofing for this domain cannot be detected by receivers"
                    .to_string(),
            ),
            1 => CheckResult::Ok("Found exactly one DMARC record".to_string()),
            n => CheckResult::Failed(format!(
                "Found {} DMARC records: a domain must not have multiple DMARC records; cf. RFC 7489, section 6.6.3",
                n
            )),
        };
        results.push(check);
    }

    fn check_parsed_dmarc_records(dmarcs: &[String], results: &mut Vec<CheckResult>) {
        for txt in dmarcs {
            match parsed_txt::Dmarc::from_str(txt) {
                Ok(dmarc) => {
                    results.push(CheckResult::Ok("Successfully parsed DMARC record".to_string()));
                    Self::check_dmarc_policy(&dmarc, results);
                }
                Err(_) => {
                    results.push(CheckResult::Failed("Failed to parse DMARC record".to_string()));
                }
            }
        }
    }

    fn check_dmarc_policy(dmarc: &parsed_txt::Dmarc<'_>, results: &mut Vec<CheckResult>) {
        match dmarc.policy() {
            "none" => results.push(CheckResult::Warning(
                "DMARC policy is 'none': emails failing authentication will not be blocked. Consider 'quarantine' or 'reject'"
                    .to_string(),
            )),
            "quarantine" => results.push(CheckResult::Ok(
                "DMARC policy is 'quarantine': suspicious emails will be quarantined".to_string(),
            )),
            "reject" => results.push(CheckResult::Ok(
                "DMARC policy is 'reject': emails failing authentication will be rejected".to_string(),
            )),
            other => results.push(CheckResult::Warning(format!(
                "Unknown DMARC policy '{}': expected 'none', 'quarantine', or 'reject'",
                other
            ))),
        }
    }
}

fn is_dmarc(txt: &str) -> bool {
    txt.starts_with("v=DMARC1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_dmarc_true() {
        assert!(is_dmarc("v=DMARC1; p=reject"));
    }

    #[test]
    fn is_dmarc_false() {
        assert!(!is_dmarc("v=spf1 include:example.com ~all"));
    }

    #[test]
    fn check_num_zero() {
        let mut results = Vec::new();
        DmarcCheck::check_num_of_dmarc_records(&[], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_num_one() {
        let mut results = Vec::new();
        DmarcCheck::check_num_of_dmarc_records(&["v=DMARC1; p=reject".to_string()], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_num_multiple() {
        let mut results = Vec::new();
        DmarcCheck::check_num_of_dmarc_records(
            &["v=DMARC1; p=reject".to_string(), "v=DMARC1; p=none".to_string()],
            &mut results,
        );
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(_)));
    }

    #[test]
    fn check_parsed_valid_reject() {
        let mut results = Vec::new();
        DmarcCheck::check_parsed_dmarc_records(&["v=DMARC1; p=reject".to_string()], &mut results);
        assert_eq!(results.len(), 2);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
        assert!(matches!(&results[1], CheckResult::Ok(_)));
    }

    #[test]
    fn check_parsed_valid_none_policy() {
        let mut results = Vec::new();
        DmarcCheck::check_parsed_dmarc_records(&["v=DMARC1; p=none".to_string()], &mut results);
        assert_eq!(results.len(), 2);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
        assert!(matches!(&results[1], CheckResult::Warning(_)));
    }

    #[test]
    fn check_parsed_invalid() {
        let mut results = Vec::new();
        DmarcCheck::check_parsed_dmarc_records(&["garbage data".to_string()], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(_)));
    }

    #[test]
    fn check_policy_quarantine() {
        let dmarc = parsed_txt::Dmarc::from_str("v=DMARC1; p=quarantine").unwrap();
        let mut results = Vec::new();
        DmarcCheck::check_dmarc_policy(&dmarc, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }
}
