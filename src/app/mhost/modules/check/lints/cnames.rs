// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;

use anyhow::Result;
use tracing::{debug, info};

use crate::app::common::lints::cnames::classify_chain_depth;
use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::mx::Mx;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::resolver::lookup::Uniquify;
use crate::resolver::MultiQuery;
use crate::{Name, RecordType};

use super::check_cname_apex;

macro_rules! record_lint {
    ($record:ident, $mapper:expr, $level:ident, $msg:literal) => {
        async fn $record(&self, results: &mut Vec<CheckResult>) -> Result<()> {
            let symbol = stringify!($record).to_uppercase();
            let names: Vec<Name> = self
                .check_results
                .lookups
                .$record()
                .unique()
                .iter()
                .map($mapper)
                .cloned()
                .collect();
            let query = MultiQuery::new(names, vec![RecordType::CNAME])?;

            if self.env.console.show_partial_headers() {
                self.env.console.itemize(&symbol);
            }

            let lookups = intermediate_lookups!(self, query, "Running lookups for {} records of domain.", symbol);

            if lookups.cname().is_empty() {
                results.push(CheckResult::Ok(format!("{} do not point to CNAME", &symbol)));
            } else {
                results.push(CheckResult::$level($msg.to_string()));
            }

            Ok(())
        }
    };
}

pub struct Cnames<'a> {
    pub env: Environment<'a, CheckConfig>,
    pub domain_name: Name,
    pub app_resolver: AppResolver,
    pub check_results: CheckResults,
}

impl<'a> Cnames<'a> {
    pub async fn cnames(self) -> PartialResult<Mx<'a>> {
        let result = if self.env.mod_config.cnames {
            let results = self.do_cnames().await?;
            Some(results)
        } else {
            None
        };

        Ok(Mx {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results: self.check_results.cnames(result),
        })
    }

    async fn do_cnames(&self) -> PartialResult<Vec<CheckResult>> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking CNAME lints");
        }
        let mut results = check_cname_apex(&self.check_results.lookups);

        self.mx(&mut results).await?;
        self.srv(&mut results).await?;
        self.cname(&mut results).await?;
        self.cname_chain_depth(&mut results).await?;

        print_check_results!(self, results, "No records found.");

        Ok(results)
    }

    record_lint!(
        mx,
        |x| x.exchange(),
        Failed,
        "MX points to CNAME: MX name must not be an alias; cf. RFC 2181, section 10.3"
    );

    record_lint!(
        srv,
        |x| x.target(),
        Failed,
        "SRV points to CNAME: SRV name must not be an alias; cf. RFC 2782, section Target"
    );

    record_lint!(
        cname,
        |x| x,
        Warning,
        "CNAME points to other CNAME: this should be avoided; cf. RFC 1034, section 3.6.2"
    );

    async fn cname_chain_depth(&self, results: &mut Vec<CheckResult>) -> Result<()> {
        let cname_targets: Vec<Name> = self
            .check_results
            .lookups
            .cname()
            .unique()
            .to_owned()
            .into_iter()
            .collect();

        if cname_targets.is_empty() {
            return Ok(());
        }

        if self.env.console.show_partial_headers() {
            self.env.console.itemize("Chain depth");
        }

        for start in &cname_targets {
            let mut seen = HashSet::new();
            seen.insert(self.domain_name.clone());
            let mut current = start.clone();
            let mut depth: usize = 1;

            loop {
                if seen.contains(&current) {
                    results.push(CheckResult::Failed(format!(
                        "Circular CNAME chain detected: {} points back to already-seen name {}",
                        if depth == 1 { &self.domain_name } else { &current },
                        current
                    )));
                    break;
                }

                seen.insert(current.clone());

                let query = match MultiQuery::multi_record(current.clone(), vec![RecordType::CNAME]) {
                    Ok(q) => q,
                    Err(_) => break,
                };

                debug!("Following CNAME chain at depth {} for {}", depth, current);
                let lookups = intermediate_lookups!(self, query, "Following CNAME chain at depth {}.", depth);
                let next_targets: Vec<Name> = lookups.cname().unique().to_owned().into_iter().collect();

                if next_targets.is_empty() {
                    // Chain terminates — classify the depth
                    results.extend(classify_chain_depth(&self.domain_name, depth));
                    break;
                }

                depth += 1;
                current = next_targets.into_iter().next().unwrap();

                // Safety limit to avoid runaway resolution
                if depth > 15 {
                    results.push(CheckResult::Failed(format!(
                        "CNAME chain from {} exceeds safety limit of 15 hops",
                        self.domain_name
                    )));
                    break;
                }
            }
        }

        Ok(())
    }
}
