// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use anyhow::anyhow;
use serde::Serialize;
use tracing::info;

use soa::Soa;

use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::{AppModule, Environment, PartialError, PartialResult, RunInfo};
use crate::app::output::summary::{SummaryFormatter, SummaryOptions};
use crate::app::output::OutputType;
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::app::{output, AppConfig, ExitStatus};
use crate::resolver::{Lookups, MultiQuery};
use crate::{Name, RecordType};
use std::io::Write;

#[doc(hidden)]
macro_rules! intermediate_lookups {
    ($Self:ident, $query:ident, resolver: $resolver:ident, $msg:expr, $($args:ident),*) => {{
        __intermediate_lookups!(Slf: $Self, query: $query, resolver: $resolver, msg: $msg, $($args),*)
    }};
    ($Self:ident, $query:ident, resolver: $resolver:ident, $msg:expr) => {{
        __intermediate_lookups!(Slf: $Self, query: $query, resolver: $resolver, msg: $msg,)
    }};
    ($Self:ident, $query:ident, $msg:expr, $($args:ident),*) => {{
        let resolver = &$Self.app_resolver;
        __intermediate_lookups!(Slf: $Self, query: $query, resolver: resolver, msg: $msg, $($args),*)
    }};
    ($Self:ident, $query:ident, $msg:expr) => {{
        let resolver = &$Self.app_resolver;
        __intermediate_lookups!(Slf: $Self, query: $query, resolver: resolver, msg: $msg,)
    }};
}

macro_rules! __intermediate_lookups {
    (Slf: $Self:ident, query: $query:ident, resolver: $resolver:ident, msg: $msg:expr, $($args:ident),*) => {
        {
            let query: MultiQuery = $query;
            if $Self.env.console.show_partial_headers() && $Self.env.mod_config.show_intermediate_lookups {
                $Self.env.console.print_lookup_estimates(&$resolver.resolvers(), &query);
            }

            info!($msg, $($args),*);
            let (lookups, run_time) = time($resolver.lookup(query)).await?;
            info!("Finished Lookups.");

            if $Self.env.mod_config.show_intermediate_lookups {
                $Self
                    .env
                    .console
                    .print_partial_results(&$Self.env.app_config.output_config, &lookups, run_time)?;
            }
            lookups
        }
    };
}

pub mod cnames;
pub mod soa;
pub mod spf;

#[derive(Debug, Serialize)]
pub struct CheckResults {
    lookups: Lookups,
    soa: Option<Vec<CheckResult>>,
    cnames: Option<Vec<CheckResult>>,
    spf: Option<Vec<CheckResult>>,
}

impl CheckResults {
    pub fn new(lookups: Lookups) -> CheckResults {
        CheckResults {
            lookups,
            soa: None,
            spf: None,
            cnames: None,
        }
    }

    pub fn cnames(self, cnames: Option<Vec<CheckResult>>) -> CheckResults {
        CheckResults { cnames, ..self }
    }

    pub fn soa(self, soa: Option<Vec<CheckResult>>) -> CheckResults {
        CheckResults { soa, ..self }
    }

    pub fn spf(self, spf: Option<Vec<CheckResult>>) -> CheckResults {
        CheckResults { spf, ..self }
    }

    pub fn has_warnings(&self) -> bool {
        (self.cnames.is_some() && self.cnames.as_ref().unwrap().iter().any(|x| x.is_warning()))
            || (self.soa.is_some() && self.soa.as_ref().unwrap().iter().any(|x| x.is_warning()))
            || (self.spf.is_some() && self.spf.as_ref().unwrap().iter().any(|x| x.is_warning()))
    }

    pub fn has_failures(&self) -> bool {
        (self.cnames.is_some() && self.cnames.as_ref().unwrap().iter().any(|x| x.is_failed()))
            || (self.soa.is_some() && self.soa.as_ref().unwrap().iter().any(|x| x.is_failed()))
            || (self.spf.is_some() && self.spf.as_ref().unwrap().iter().any(|x| x.is_failed()))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub enum CheckResult {
    NotFound(),
    Ok(String),
    Warning(String),
    Failed(String),
}

impl CheckResult {
    pub fn is_warning(&self) -> bool {
        matches!(self, CheckResult::Warning(_))
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, CheckResult::Failed(_))
    }
}

pub struct Check {}

impl AppModule<CheckConfig> for Check {}

impl Check {
    pub async fn init<'a>(app_config: &'a AppConfig, config: &'a CheckConfig) -> PartialResult<LookupAllThereIs<'a>> {
        if app_config.output == OutputType::Json && config.partial_results {
            return Err(anyhow!("JSON output is incompatible with partial result output").into());
        }

        let env = Self::init_env(app_config, config)?;
        let domain_name = env.name_builder.from_str(&config.domain_name)?;
        let app_resolver = AppResolver::create_resolvers(app_config).await?;

        env.console
            .print_resolver_opts(app_resolver.resolver_group_opts(), app_resolver.resolver_opts());

        Ok(LookupAllThereIs {
            env,
            domain_name,
            app_resolver,
        })
    }
}

pub struct LookupAllThereIs<'a> {
    env: Environment<'a, CheckConfig>,
    domain_name: Name,
    app_resolver: AppResolver,
}

impl<'a> LookupAllThereIs<'a> {
    pub async fn lookup_all_records(self) -> PartialResult<Soa<'a>> {
        let record_types = {
            use RecordType::*;
            vec![
                // TODO: AXFR seems to kill dnsmasq in the macOS test-env
                //A, AAAA, ANAME, ANY, AXFR, CAA, CNAME, IXFR, MX, NS, OPT, SOA, SRV, TXT, DNSSEC,
                A, AAAA, ANAME, ANY, CAA, CNAME, IXFR, MX, NS, OPT, SOA, SRV, TXT, DNSSEC,
            ]
        };
        let query = MultiQuery::multi_record(self.domain_name.clone(), record_types)?;

        self.env.console.print_partial_headers(
            "Running DNS lookups for all available records.",
            self.app_resolver.resolvers(),
            &query,
        );

        info!("Running lookups of all records of domain.");
        let (lookups, run_time) = time(self.app_resolver.lookup(query)).await?;
        info!("Finished Lookups.");

        self.env
            .console
            .print_partial_results(&self.env.app_config.output_config, &lookups, run_time)?;

        if !lookups.has_records() {
            self.env.console.failed("No records found. Aborting.");
            return Err(PartialError::Failed(ExitStatus::Abort));
        }

        let check_results = CheckResults::new(lookups);

        Ok(Soa {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            check_results,
        })
    }
}

pub struct OutputCheckResults<'a> {
    env: Environment<'a, CheckConfig>,
    #[allow(dead_code)]
    domain_name: Name,
    check_results: CheckResults,
}

impl<'a> OutputCheckResults<'a> {
    pub fn output(self) -> PartialResult<ExitStatus> {
        match self.env.app_config.output {
            OutputType::Json => self.json_output(),
            OutputType::Summary => self.summary_output(),
        }
    }

    fn json_output(self) -> PartialResult<ExitStatus> {
        #[derive(Debug, Serialize)]
        struct Json {
            info: RunInfo,
            check_results: CheckResults,
        }
        impl SummaryFormatter for Json {
            fn output<W: Write>(&self, _: &mut W, _: &SummaryOptions) -> crate::Result<()> {
                unimplemented!()
            }
        }
        let data = Json {
            info: self.env.run_info,
            check_results: self.check_results,
        };

        output::output(&self.env.app_config.output_config, &data)?;
        Ok(ExitStatus::Ok)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn summary_output(self) -> PartialResult<ExitStatus> {
        self.env.console.print_finished();

        if self.check_results.has_failures() {
            self.env.console.failed("Found failures");
            Ok(ExitStatus::CheckFailed)
        } else if self.check_results.has_warnings() {
            self.env.console.attention("Found warnings");
            Ok(ExitStatus::CheckFailed)
        } else {
            self.env.console.ok("No issues found.");
            Ok(ExitStatus::Ok)
        }
    }
}
