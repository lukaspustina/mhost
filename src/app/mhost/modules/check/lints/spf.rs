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
use crate::diff::Differ;
use crate::resolver::lookup::Uniquify;
use crate::resolver::Lookups;
use crate::resources::rdata::{parsed_txt, TXT};
use crate::Name;

/// Run SPF lint checks against the given lookups.
pub fn check_spf(lookups: &Lookups) -> Vec<CheckResult> {
    let spfs: Vec<String> = lookups
        .txt()
        .unique()
        .iter()
        .filter(|x| x.is_spf())
        .map(TXT::as_string)
        .collect();
    let mut results = Vec::new();
    check_num_of_spf_records(&spfs, &mut results);
    check_parsed_spf_records(&spfs, &mut results);
    results
}

fn check_num_of_spf_records(spfs: &[String], results: &mut Vec<CheckResult>) {
    let check = match spfs.len() {
        0 => CheckResult::NotFound(),
        1 => CheckResult::Ok("Found exactly one SPF record".to_string()),
        n => CheckResult::Failed(format!(
            "Found {} SPF records: A domain must not have multiple records; cf. RFC 4408, section 3.1.2",
            n
        )),
    };
    results.push(check);
}

fn check_parsed_spf_records(spfs: &[String], results: &mut Vec<CheckResult>) {
    // Check, if Txt records can be parsed into SPF records
    let mut parsed_spfs = Vec::new();
    for str in spfs {
        if let Ok(spf) = parsed_txt::Spf::from_str(str) {
            results.push(CheckResult::Ok("Successfully parsed SPF record".to_string()));
            parsed_spfs.push(spf)
        } else {
            results.push(CheckResult::Failed("Failed to parse SPF record".to_string()));
        }
    }

    // If there are multiple parsable SPF records, check if they at least are the same
    if parsed_spfs.len() > 1 {
        let mut it = parsed_spfs.into_iter();
        let first = it.next().unwrap();
        for next in it {
            if first.difference(&next).is_some() {
                results.push(CheckResult::Warning("Spf records differ".to_string()));
            }
        }
    }
}

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
