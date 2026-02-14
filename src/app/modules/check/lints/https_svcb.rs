// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use tracing::info;

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::{CheckResult, CheckResults, OutputCheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::resolver::lookup::Uniquify;
use crate::resolver::MultiQuery;
use crate::resources::rdata::SVCB;
use crate::{Name, RecordType};

pub struct HttpsSvcb<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> HttpsSvcb<'a> {
    pub async fn https_svcb(self) -> PartialResult<OutputCheckResults<'a>> {
        let result = if self.env.mod_config.https_svcb {
            Some(self.do_https_svcb().await?)
        } else {
            None
        };

        Ok(OutputCheckResults {
            env: self.env,
            domain_name: self.domain_name,
            check_results: self.check_results.https_svcb(result),
        })
    }

    async fn do_https_svcb(&self) -> PartialResult<Vec<CheckResult>> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking HTTPS/SVCB record lints");
        }
        let mut results = Vec::new();

        let unique_https = self.check_results.lookups.https().unique();
        let https_records: Vec<&SVCB> = unique_https.iter().collect();
        let unique_svcb = self.check_results.lookups.svcb().unique();
        let svcb_records: Vec<&SVCB> = unique_svcb.iter().collect();

        if https_records.is_empty() && svcb_records.is_empty() {
            results.push(CheckResult::NotFound());
        } else {
            if !https_records.is_empty() {
                Self::check_svcb_records("HTTPS", &https_records, &mut results);
                self.check_targets_resolve("HTTPS", &https_records, &mut results).await?;
            }
            if !svcb_records.is_empty() {
                Self::check_svcb_records("SVCB", &svcb_records, &mut results);
                self.check_targets_resolve("SVCB", &svcb_records, &mut results).await?;
            }
        }

        if self.env.console.show_partial_results() {
            for r in &results {
                match r {
                    CheckResult::NotFound() => self.env.console.info("No HTTPS/SVCB records found."),
                    CheckResult::Ok(str) => self.env.console.ok(str),
                    CheckResult::Warning(str) => self.env.console.attention(str),
                    CheckResult::Failed(str) => self.env.console.failed(str),
                }
            }
        }

        Ok(results)
    }

    fn check_svcb_records(record_type: &str, records: &[&SVCB], results: &mut Vec<CheckResult>) {
        let alias_count = records.iter().filter(|r| r.is_alias()).count();
        let service_count = records.len() - alias_count;

        if alias_count > 0 && service_count > 0 {
            results.push(CheckResult::Warning(format!(
                "{} records mix alias (priority 0) and service modes: this may cause inconsistent behavior; cf. RFC 9460",
                record_type
            )));
        } else if alias_count > 1 {
            results.push(CheckResult::Warning(format!(
                "Multiple {} alias records found: only one alias record is expected; cf. RFC 9460",
                record_type
            )));
        } else {
            results.push(CheckResult::Ok(format!(
                "{} records are well-formed ({} alias, {} service mode)",
                record_type, alias_count, service_count
            )));
        }
    }

    async fn check_targets_resolve(&self, record_type: &str, records: &[&SVCB], results: &mut Vec<CheckResult>) -> PartialResult<()> {
        if self.env.console.show_partial_headers() {
            self.env
                .console
                .itemize(format!("{} target resolution", record_type));
        }

        let targets: Vec<Name> = records
            .iter()
            .filter(|r| !r.is_alias())
            .map(|r| r.target_name())
            .filter(|name| !name.is_root())
            .cloned()
            .collect();

        if targets.is_empty() {
            return Ok(());
        }

        let query = match MultiQuery::new(targets.clone(), vec![RecordType::A, RecordType::AAAA]) {
            Ok(q) => q,
            Err(_) => return Ok(()),
        };

        let lookups = intermediate_lookups!(
            self,
            query,
            "Running lookups for {} target IP addresses.",
            record_type
        );

        let resolved_names: Vec<Name> = lookups
            .rr_a()
            .iter()
            .chain(lookups.rr_aaaa().iter())
            .map(|r| r.name().clone())
            .collect();

        let mut dangling = Vec::new();
        for target in &targets {
            if !resolved_names.iter().any(|name| name == target) {
                dangling.push(target.to_string());
            }
        }

        if dangling.is_empty() {
            results.push(CheckResult::Ok(format!(
                "All {} service targets resolve to IP addresses",
                record_type
            )));
        } else {
            results.push(CheckResult::Failed(format!(
                "{} service targets do not resolve: {}",
                record_type,
                dangling.join(", ")
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn check_svcb_records_service_only() {
        let mut results = Vec::new();
        let target = Name::from_str("cdn.example.com.").unwrap();
        let svc = SVCB::new(1, target, vec![]);
        HttpsSvcb::check_svcb_records("HTTPS", &[&svc], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_svcb_records_alias_only() {
        let mut results = Vec::new();
        let target = Name::from_str("other.example.com.").unwrap();
        let alias = SVCB::new(0, target, vec![]);
        HttpsSvcb::check_svcb_records("HTTPS", &[&alias], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_svcb_records_mixed_modes() {
        let mut results = Vec::new();
        let target1 = Name::from_str("other.example.com.").unwrap();
        let target2 = Name::from_str("cdn.example.com.").unwrap();
        let alias = SVCB::new(0, target1, vec![]);
        let svc = SVCB::new(1, target2, vec![]);
        HttpsSvcb::check_svcb_records("HTTPS", &[&alias, &svc], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_svcb_records_multiple_aliases() {
        let mut results = Vec::new();
        let target1 = Name::from_str("a.example.com.").unwrap();
        let target2 = Name::from_str("b.example.com.").unwrap();
        let alias1 = SVCB::new(0, target1, vec![]);
        let alias2 = SVCB::new(0, target2, vec![]);
        HttpsSvcb::check_svcb_records("SVCB", &[&alias1, &alias2], &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }
}
