// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use tracing::info;

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::spf::Spf;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::resolver::lookup::Uniquify;
use crate::resolver::MultiQuery;
use crate::resources::rdata::SVCB;
use crate::{Name, RecordType};

use super::check_https_svcb_mode;

pub struct HttpsSvcb<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> HttpsSvcb<'a> {
    pub async fn https_svcb(self) -> PartialResult<Spf<'a>> {
        let result = if self.env.mod_config.https_svcb {
            Some(self.do_https_svcb().await?)
        } else {
            None
        };

        Ok(Spf {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.https_svcb(result),
        })
    }

    async fn do_https_svcb(&self) -> PartialResult<Vec<CheckResult>> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking HTTPS/SVCB record lints");
        }

        let mut results = check_https_svcb_mode(&self.check_results.lookups);

        // Run async target resolution for non-empty records
        let unique_https = self.check_results.lookups.https().unique();
        let https_records: Vec<&SVCB> = unique_https.iter().collect();
        let unique_svcb = self.check_results.lookups.svcb().unique();
        let svcb_records: Vec<&SVCB> = unique_svcb.iter().collect();

        if !https_records.is_empty() {
            self.check_targets_resolve("HTTPS", &https_records, &mut results)
                .await?;
        }
        if !svcb_records.is_empty() {
            self.check_targets_resolve("SVCB", &svcb_records, &mut results).await?;
        }

        print_check_results!(self, results, "No HTTPS/SVCB records found.");

        Ok(results)
    }

    async fn check_targets_resolve(
        &self,
        record_type: &str,
        records: &[&SVCB],
        results: &mut Vec<CheckResult>,
    ) -> PartialResult<()> {
        if self.env.console.show_partial_headers() {
            self.env.console.itemize(format!("{} target resolution", record_type));
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

        let lookups = intermediate_lookups!(self, query, "Running lookups for {} target IP addresses.", record_type);

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
