// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::ttl::Ttl;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::Name;

use super::check_caa;

pub struct CaaCheck<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> CaaCheck<'a> {
    pub fn caa(self) -> PartialResult<Ttl<'a>> {
        let result = if self.env.mod_config.caa {
            Some(self.do_caa())
        } else {
            None
        };

        Ok(Ttl {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.caa(result),
        })
    }

    fn do_caa(&self) -> Vec<CheckResult> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking CAA record lints");
        }

        let results = check_caa(&self.check_results.lookups);

        print_check_results!(self, results, "No CAA records found.");

        results
    }
}
