// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::{CheckResult, CheckResults, OutputCheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::diff::Differ;
use crate::resolver::lookup::Uniquify;
use crate::resources::rdata::{parsed_txt, TXT};
use crate::Name;

pub struct Spf<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    #[allow(dead_code)]
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> Spf<'a> {
    pub fn spf(self) -> PartialResult<OutputCheckResults<'a>> {
        let result = if self.env.mod_config.spf {
            Some(self.do_spf())
        } else {
            None
        };

        Ok(OutputCheckResults {
            env: self.env,
            domain_name: self.domain_name,
            check_results: self.check_results.spf(result),
        })
    }

    fn do_spf(&self) -> Vec<CheckResult> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking SPF TXT records lints");
        }
        let mut results = Vec::new();

        let spfs: Vec<String> = self
            .check_results
            .lookups
            .txt()
            .unique()
            .iter()
            .filter(|x| x.is_spf())
            .map(TXT::as_string)
            .collect();

        Spf::check_num_of_spf_records(&spfs, &mut results);
        Spf::check_parsed_spf_records(&spfs, &mut results);

        if self.env.console.show_partial_results() {
            for r in &results {
                match r {
                    CheckResult::NotFound() => self.env.console.info("No SPF records found."),
                    CheckResult::Ok(str) => self.env.console.ok(str),
                    CheckResult::Warning(str) => self.env.console.attention(str),
                    CheckResult::Failed(str) => self.env.console.failed(str),
                }
            }
        }

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
            if let Ok(spf) = parsed_txt::Spf::from_str(&str) {
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
}
