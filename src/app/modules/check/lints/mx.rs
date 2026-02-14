// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;

use tracing::info;

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::spf::Spf;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::resolver::lookup::Uniquify;
use crate::resolver::MultiQuery;
use crate::resources::rdata::MX;
use crate::{Name, RecordType};

pub struct Mx<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> Mx<'a> {
    pub async fn mx(self) -> PartialResult<Spf<'a>> {
        let result = if self.env.mod_config.mx {
            Some(self.do_mx().await?)
        } else {
            None
        };

        Ok(Spf {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.mx(result),
        })
    }

    async fn do_mx(&self) -> PartialResult<Vec<CheckResult>> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking MX hygiene lints");
        }
        let mut results = Vec::new();

        let unique_mx = self.check_results.lookups.mx().unique();
        let mx_records: Vec<&MX> = unique_mx.iter().collect();

        if mx_records.is_empty() {
            Self::check_null_mx_absent(&mut results);
        } else {
            Self::check_null_mx(&mx_records, &mut results);
            Self::check_duplicate_preferences(&mx_records, &mut results);
            self.check_mx_targets_resolve(&mx_records, &mut results).await?;
        }

        print_check_results!(self, results, "No MX records found.");

        Ok(results)
    }

    fn check_null_mx_absent(results: &mut Vec<CheckResult>) {
        results.push(CheckResult::Warning(
            "No MX records found: if this domain does not handle mail, consider adding a Null MX record (RFC 7505)"
                .to_string(),
        ));
    }

    fn check_null_mx(mx_records: &[&MX], results: &mut Vec<CheckResult>) {
        let has_null_mx = mx_records
            .iter()
            .any(|mx| mx.preference() == 0 && mx.exchange().is_root());

        if has_null_mx {
            if mx_records.len() > 1 {
                results.push(CheckResult::Failed(
                    "Null MX (preference 0, target '.') must be the only MX record; cf. RFC 7505".to_string(),
                ));
            } else {
                results.push(CheckResult::Ok(
                    "Domain has a valid Null MX record (RFC 7505)".to_string(),
                ));
            }
        }
    }

    fn check_duplicate_preferences(mx_records: &[&MX], results: &mut Vec<CheckResult>) {
        let mut pref_counts: HashMap<u16, usize> = HashMap::new();
        for mx in mx_records {
            *pref_counts.entry(mx.preference()).or_insert(0) += 1;
        }

        let duplicates: Vec<u16> = pref_counts
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(pref, _)| *pref)
            .collect();

        if duplicates.is_empty() {
            results.push(CheckResult::Ok("All MX records have unique preferences".to_string()));
        } else {
            results.push(CheckResult::Warning(format!(
                "Duplicate MX preferences found: {:?}. While valid, this may indicate a misconfiguration",
                duplicates
            )));
        }
    }

    async fn check_mx_targets_resolve(&self, mx_records: &[&MX], results: &mut Vec<CheckResult>) -> PartialResult<()> {
        if self.env.console.show_partial_headers() {
            self.env.console.itemize("MX targets resolve");
        }

        let exchanges: Vec<Name> = mx_records
            .iter()
            .filter(|mx| !mx.exchange().is_root())
            .map(|mx| mx.exchange().clone())
            .collect();

        if exchanges.is_empty() {
            return Ok(());
        }

        let query = match MultiQuery::new(exchanges.clone(), vec![RecordType::A, RecordType::AAAA]) {
            Ok(q) => q,
            Err(_) => return Ok(()),
        };

        let lookups = intermediate_lookups!(self, query, "Running lookups for MX target IP addresses.");

        let resolved_a: Vec<Name> = lookups.rr_a().iter().map(|r| r.name().clone()).collect();
        let resolved_aaaa: Vec<Name> = lookups.rr_aaaa().iter().map(|r| r.name().clone()).collect();

        let mut dangling = Vec::new();
        for exchange in &exchanges {
            let has_a = resolved_a.iter().any(|name| name == exchange);
            let has_aaaa = resolved_aaaa.iter().any(|name| name == exchange);
            if !has_a && !has_aaaa {
                dangling.push(exchange.to_string());
            }
        }

        if dangling.is_empty() {
            results.push(CheckResult::Ok("All MX targets resolve to IP addresses".to_string()));
        } else {
            results.push(CheckResult::Failed(format!(
                "MX targets do not resolve: {}. Mail delivery will fail for these targets",
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
    fn check_null_mx_absent_produces_warning() {
        let mut results = Vec::new();
        Mx::check_null_mx_absent(&mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }

    #[test]
    fn check_null_mx_valid_single() {
        let mut results = Vec::new();
        let null_mx = MX::new(0, Name::root());
        let records = vec![&null_mx];
        Mx::check_null_mx(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_null_mx_with_other_records() {
        let mut results = Vec::new();
        let null_mx = MX::new(0, Name::root());
        let regular_mx = MX::new(10, Name::from_str("mail.example.com.").unwrap());
        let records = vec![&null_mx, &regular_mx];
        Mx::check_null_mx(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Failed(_)));
    }

    #[test]
    fn check_duplicate_preferences_unique() {
        let mut results = Vec::new();
        let mx1 = MX::new(10, Name::from_str("mx1.example.com.").unwrap());
        let mx2 = MX::new(20, Name::from_str("mx2.example.com.").unwrap());
        let records = vec![&mx1, &mx2];
        Mx::check_duplicate_preferences(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Ok(_)));
    }

    #[test]
    fn check_duplicate_preferences_duplicated() {
        let mut results = Vec::new();
        let mx1 = MX::new(10, Name::from_str("mx1.example.com.").unwrap());
        let mx2 = MX::new(10, Name::from_str("mx2.example.com.").unwrap());
        let records = vec![&mx1, &mx2];
        Mx::check_duplicate_preferences(&records, &mut results);
        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], CheckResult::Warning(_)));
    }
}
