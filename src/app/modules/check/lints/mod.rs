use anyhow::anyhow;
use tracing::info;

use crate::app::console::{Console, ConsoleOpts};
use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::{Environment, PartialError, PartialResult};
use crate::app::output::OutputType;
use crate::app::resolver::{AppResolver, NameBuilder};
use crate::app::{AppConfig, ExitStatus};
use crate::resolver::{Lookups, MultiQuery};
use crate::{Name, RecordType};

pub mod cnames;
pub mod spf;

use crate::app::utils::time;
use cnames::Cnames;

#[derive(Debug)]
pub struct CheckResults {
    lookups: Lookups,
    cnames: Option<Vec<CheckResult>>,
    spf: Option<Vec<CheckResult>>,
}

impl CheckResults {
    pub fn new(lookups: Lookups) -> CheckResults {
        CheckResults {
            lookups,
            spf: None,
            cnames: None,
        }
    }

    pub fn spf(self, spf: Option<Vec<CheckResult>>) -> CheckResults {
        CheckResults { spf, ..self }
    }

    pub fn cnames(self, cnames: Option<Vec<CheckResult>>) -> CheckResults {
        CheckResults { cnames, ..self }
    }

    pub fn has_warnings(&self) -> bool {
        (self.cnames.is_some() && self.cnames.as_ref().unwrap().iter().any(|x| x.is_warning()))
            || (self.spf.is_some() && self.spf.as_ref().unwrap().iter().any(|x| x.is_warning()))
    }

    pub fn has_failures(&self) -> bool {
        (self.cnames.is_some() && self.cnames.as_ref().unwrap().iter().any(|x| x.is_failed()))
            || (self.spf.is_some() && self.spf.as_ref().unwrap().iter().any(|x| x.is_failed()))
    }
}

#[derive(Debug, PartialEq, Eq)]
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

impl Check {
    pub async fn init<'a>(app_config: &'a AppConfig, config: &'a CheckConfig) -> PartialResult<LookupAllThereIs<'a>> {
        if app_config.output == OutputType::Json && config.partial_results {
            return Err(anyhow!("JSON output is incompatible with partial result output").into());
        }

        let console_opts = ConsoleOpts::from(app_config).with_partial_results(config.partial_results);
        let console = Console::new(console_opts);
        let env = Environment::new(app_config, config, console);

        let name_builder = NameBuilder::new(app_config);
        let domain_name = name_builder.from_str(&config.domain_name)?;
        let app_resolver = AppResolver::create_resolvers(app_config).await?;

        env.console
            .print_resolver_opts(app_resolver.resolver_group_opts(), &app_resolver.resolver_opts());

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
    pub async fn lookup_all_records(self) -> PartialResult<Cnames<'a>> {
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
            &self.app_resolver.resolvers(),
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

        Ok(Cnames {
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
