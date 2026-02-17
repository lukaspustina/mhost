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
use crate::{Name, RecordType};

use super::{check_dmarc_records, is_dmarc};

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

        results = check_dmarc_records(&dmarc_txts);

        print_check_results!(self, results, "No DMARC record found.");

        Ok(results)
    }
}
