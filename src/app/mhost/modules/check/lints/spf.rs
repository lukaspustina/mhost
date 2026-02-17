// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::dmarc::DmarcCheck;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::Name;

use super::check_spf;

pub struct Spf<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    #[allow(dead_code)]
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> Spf<'a> {
    pub fn spf(self) -> PartialResult<DmarcCheck<'a>> {
        let result = if self.env.mod_config.spf {
            Some(self.do_spf())
        } else {
            None
        };

        Ok(DmarcCheck {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.spf(result),
        })
    }

    fn do_spf(&self) -> Vec<CheckResult> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking SPF TXT records lints");
        }

        let results = check_spf(&self.check_results.lookups);

        print_check_results!(self, results, "No SPF records found.");

        results
    }
}
