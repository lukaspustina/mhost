// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use tracing::info;

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::https_svcb::HttpsSvcb;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::resolver::lookup::Uniquify;
use crate::resolver::MultiQuery;
use crate::resources::rdata::MX;
use crate::{Name, RecordType};

use super::check_mx_sync;

pub struct Mx<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> Mx<'a> {
    pub async fn mx(self) -> PartialResult<HttpsSvcb<'a>> {
        let result = if self.env.mod_config.mx {
            Some(self.do_mx().await?)
        } else {
            None
        };

        Ok(HttpsSvcb {
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

        let mut results = check_mx_sync(&self.check_results.lookups);

        let unique_mx = self.check_results.lookups.mx().unique();
        let mx_records: Vec<&MX> = unique_mx.iter().collect();

        if !mx_records.is_empty() {
            self.check_mx_targets_resolve(&mx_records, &mut results).await?;
        }

        print_check_results!(self, results, "No MX records found.");

        Ok(results)
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
