// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use anyhow::Result;
use tracing::info;

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::check::lints::spf::Spf;
use crate::app::modules::check::lints::{CheckResult, CheckResults};
use crate::app::modules::{Environment, PartialResult};
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::resolver::lookup::Uniquify;
use crate::resolver::MultiQuery;
use crate::{Name, RecordType};

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
    pub async fn cnames(self) -> PartialResult<Spf<'a>> {
        let result = if self.env.mod_config.cnames {
            let results = self.do_cnames().await?;
            Some(results)
        } else {
            None
        };

        Ok(Spf {
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
        let mut results = Vec::new();

        self.apex(&mut results)?;
        self.mx(&mut results).await?;
        self.srv(&mut results).await?;
        self.cname(&mut results).await?;

        if self.env.console.show_partial_results() {
            for r in &results {
                match r {
                    CheckResult::NotFound() => self.env.console.info("No records found."),
                    CheckResult::Ok(str) => self.env.console.ok(str),
                    CheckResult::Warning(str) => self.env.console.attention(str),
                    CheckResult::Failed(str) => self.env.console.failed(str),
                }
            }
        }

        Ok(results)
    }

    // This lint should never fail, because even a specific DNS server implementation may allow configurations of
    // CNAMEs on APEX zones, it should never deliver these RR as answers, since this would be in violation of the DNS RFC.
    // cf. https://www.isc.org/blogs/cname-at-the-apex-of-a-zone/ for a easy to understand explanation.
    #[allow(clippy::unnecessary_wraps)]
    fn apex(&self, results: &mut Vec<CheckResult>) -> Result<()> {
        if self.env.console.show_partial_headers() {
            self.env.console.itemize("Apex");
        }

        let lookups = &self.check_results.lookups;
        let is_apex = !lookups.soa().is_empty();

        if is_apex {
            if lookups.cname().is_empty() {
                results.push(CheckResult::Ok("Apex zone without CNAME".to_string()));
            } else {
                results.push(CheckResult::Failed(
                    "Apex zone with CNAME: apex zones must not have CNAME records; cf. RFC 1034, section 3.6.2"
                        .to_string(),
                ));
            }
        } else {
            results.push(CheckResult::Ok("Not apex zone".to_string()));
        }

        Ok(())
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
}
