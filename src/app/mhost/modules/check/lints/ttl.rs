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
use crate::Name;

use super::check_ttl;

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

        let results = check_ttl(&self.check_results.lookups);

        print_check_results!(self, results, "No records to check TTLs.");

        results
    }
}
