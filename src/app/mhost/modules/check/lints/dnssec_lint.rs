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

use super::check_dnssec;

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

        let results = check_dnssec(&self.check_results.lookups);

        print_check_results!(self, results, "No DNSSEC records found.");

        results
    }
}
