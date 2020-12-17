use std::time::Instant;

use anyhow::{anyhow, Result};
use tracing::info;

use crate::app::console::Console;
use crate::app::modules::check::config::CheckConfig;
use crate::app::modules::{Environment, Partial};
use crate::app::output::OutputType;
use crate::app::resolver::{AppResolver, NameBuilder};
use crate::app::{console, AppConfig, ExitStatus};
use crate::diff::SetDiffer;
use crate::resolver::lookup::Uniquify;
use crate::resolver::{Lookups, MultiQuery};
use crate::resources::rdata::{parsed_txt, TXT};
use crate::{Error, Name, RecordType};

#[derive(Debug)]
pub struct PartialResults {
    lookups: Lookups,
    spf: Option<Vec<PartialResult>>,
}

impl PartialResults {
    pub fn new(lookups: Lookups) -> PartialResults {
        PartialResults { lookups, spf: None }
    }

    pub fn spf(self, spf: Option<Vec<PartialResult>>) -> PartialResults {
        PartialResults { spf, ..self }
    }

    pub fn has_issues(&self) -> bool {
        (self.spf.is_some() && self.spf.as_ref().unwrap().iter().any(|x| x.is_issue()))
    }

    pub fn has_warnings(&self) -> bool {
        (self.spf.is_some() && self.spf.as_ref().unwrap().iter().any(|x| x.is_warning()))
    }

    pub fn has_failures(&self) -> bool {
        (self.spf.is_some() && self.spf.as_ref().unwrap().iter().any(|x| x.is_failed()))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PartialResult {
    NotFound(),
    Ok(String),
    Warning(String),
    Failed(String),
}

impl PartialResult {
    pub fn is_warning(&self) -> bool {
        matches!(self, PartialResult::Warning(_))
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, PartialResult::Failed(_))
    }

    pub fn is_issue(&self) -> bool {
        self.is_warning() || self.is_failed()
    }
}

pub struct Check {}

impl Check {
    pub async fn init<'a>(app_config: &'a AppConfig, config: &'a CheckConfig) -> Result<LookupAllThereIs<'a>> {
        if app_config.output == OutputType::Json && config.partial_results {
            return Err(anyhow!("JSON output is incompatible with partial result output"));
        }
        let console = Console::with_partial_results(app_config, config.partial_results);
        let env = Environment::new(app_config, config, console);

        let name_builder = NameBuilder::new(app_config);
        let domain_name = name_builder.from_str(&config.domain_name)?;
        let app_resolver = AppResolver::create_resolvers(app_config).await?;

        if env.console.not_quiet() {
            env.console
                .print_opts(app_resolver.resolver_group_opts(), &app_resolver.resolver_opts());
        }

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
    pub async fn lookup_all_records(self) -> Result<Partial<Spf<'a>>> {
        let query = MultiQuery::multi_record(self.domain_name.clone(), RecordType::all())?;

        if self.env.console.show_partial_headers() {
            self.env
                .console
                .caption("Running DNS lookups for all available records.");
            self.env
                .console
                .print_estimates_lookups(&self.app_resolver.resolvers(), &query);
        }

        info!("Running lookups of all records of domain.");
        let start_time = Instant::now();
        let lookups = self.app_resolver.lookup(query).await?;
        let total_run_time = Instant::now() - start_time;
        info!("Finished Lookups.");

        console::print_partial_results(
            &self.env.console,
            &self.env.app_config.output_config,
            &lookups,
            total_run_time,
        )?;

        if !lookups.has_records() {
            self.env.console.failed("No records found. Aborting.");
            return Ok(Partial::ExitStatus(ExitStatus::Abort));
        }

        let partial_results = PartialResults::new(lookups);

        Ok(Partial::Next(Spf {
            env: self.env,
            domain_name: self.domain_name,
            app_resolver: self.app_resolver,
            partial_results,
        }))
    }
}

impl<'a> Partial<Spf<'a>> {
    pub fn spf(self) -> Result<Partial<CheckResult<'a>>> {
        match self {
            Partial::Next(next) => next.spf(),
            Partial::ExitStatus(e) => Ok(Partial::ExitStatus(e)),
        }
    }
}

pub struct Spf<'a> {
    env: Environment<'a, CheckConfig>,
    domain_name: Name,
    app_resolver: AppResolver,
    partial_results: PartialResults,
}

impl<'a> Spf<'a> {
    fn spf(self) -> Result<Partial<CheckResult<'a>>> {
        let result = if self.env.mod_config.spf {
            Some(self.do_spf())
        } else {
            None
        };

        Ok(Partial::Next(CheckResult {
            env: self.env,
            domain_name: self.domain_name,
            partial_results: self.partial_results.spf(result),
        }))
    }

    fn do_spf(&self) -> Vec<PartialResult> {
        if self.env.console.show_partial_headers() {
            self.env.console.caption("Checking SPF TXT records");
        }
        let mut results = Vec::new();

        let spfs: Vec<String> = self
            .partial_results
            .lookups
            .txt()
            .unique()
            .iter()
            .filter(|x| x.is_spf())
            .map(TXT::as_string)
            .collect();

        Spf::check_num_of_spf_records(&spfs, &mut results);
        Spf::check_parse_spf_records(&spfs, &mut results);

        if self.env.console.show_partial_results() {
            for r in &results {
                match r {
                    PartialResult::NotFound() => self.env.console.info("No SPF records found."),
                    PartialResult::Ok(str) => self.env.console.ok(str),
                    PartialResult::Warning(str) => self.env.console.attention(str),
                    PartialResult::Failed(str) => self.env.console.failed(str),
                }
            }
        }

        results
    }

    fn check_num_of_spf_records(spfs: &Vec<String>, results: &mut Vec<PartialResult>) {
        let check = match spfs.len() {
            0 => PartialResult::NotFound(),
            1 => PartialResult::Ok("Found exactly one SPF record".to_string()),
            n => PartialResult::Failed(format!(
                "Found {} SPF records, but a domain MUST NOT have multiple records; cf. RFC 4408, section 3.1.2",
                n
            )),
        };
        results.push(check);
    }

    fn check_parse_spf_records(spfs: &Vec<String>, results: &mut Vec<PartialResult>) {
        for spf in spfs {
            let res = parsed_txt::Spf::from_str(&spf);
            if res.is_ok() {
                results.push(PartialResult::Ok("Successfully parsed SPF record".to_string()));
            } else {
                results.push(PartialResult::Failed("Failed to parse SPF record".to_string()));
            }
        }
    }
}

impl<'a> Partial<CheckResult<'a>> {
    pub fn output(self) -> Result<ExitStatus> {
        match self {
            Partial::Next(next) => next.output(),
            Partial::ExitStatus(e) => Ok(e),
        }
    }
}

pub struct CheckResult<'a> {
    env: Environment<'a, CheckConfig>,
    domain_name: Name,
    partial_results: PartialResults,
}

impl<'a> CheckResult<'a> {
    pub fn output(self) -> Result<ExitStatus> {
        if self.env.console.not_quiet() {
            self.env.console.finished();
        }

        if self.partial_results.has_failures() {
            self.env.console.failed("Found failures");
            Ok(ExitStatus::CheckFailed)
        } else if self.partial_results.has_warnings() {
            self.env.console.attention("Found warnings");
            Ok(ExitStatus::CheckFailed)
        } else {
            self.env.console.ok("No issues found.");
            Ok(ExitStatus::Ok)
        }
    }
}
