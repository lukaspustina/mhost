// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;
use std::io::Write;

use anyhow::{Context, Result};
use serde::Serialize;
use tracing::{debug, info};
use yansi::Paint;

use crate::app::modules::diff::config::DiffConfig;
use crate::app::modules::{AppModule, Environment, PartialResult, RunInfo};
use crate::app::output::summary::{Rendering, SummaryFormatter, SummaryOptions};
use crate::app::output::styles as output_styles;
use crate::app::output::OutputType;
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::app::{output, AppConfig, ExitStatus};
use crate::nameserver::NameServerConfig;
use crate::resolver::{Lookups, MultiQuery, ResolverConfig};
use crate::resources::Record;
use crate::RecordType;

pub struct Diff {}

impl AppModule<DiffConfig> for Diff {}

impl Diff {
    pub async fn init<'a>(app_config: &'a AppConfig, config: &'a DiffConfig) -> PartialResult<DnsLookups<'a>> {
        let env = Self::init_env(app_config, config)?;

        let domain_name = env.name_builder.from_str(&config.domain_name)?;
        let query =
            MultiQuery::multi_record(domain_name, config.record_types.clone()).context("Failed to build query")?;
        debug!("Querying: {:?}", query);

        let left_configs: Vec<ResolverConfig> = parse_nameserver_specs(&config.left)?;
        let right_configs: Vec<ResolverConfig> = parse_nameserver_specs(&config.right)?;

        let left_resolver = AppResolver::from_configs(left_configs, app_config).await?;
        let right_resolver = AppResolver::from_configs(right_configs, app_config).await?;

        env.console
            .print_resolver_opts(left_resolver.resolver_group_opts(), left_resolver.resolver_opts());

        Ok(DnsLookups {
            env,
            query,
            left_resolver,
            right_resolver,
        })
    }
}

fn parse_nameserver_specs(specs: &[String]) -> Result<Vec<ResolverConfig>> {
    specs
        .iter()
        .map(|s| {
            NameServerConfig::from_str(s)
                .map(ResolverConfig::from)
                .map_err(|e| anyhow::anyhow!(e))
                .with_context(|| format!("Failed to parse nameserver spec '{}'", s))
        })
        .collect()
}

pub struct DnsLookups<'a> {
    env: Environment<'a, DiffConfig>,
    query: MultiQuery,
    left_resolver: AppResolver,
    right_resolver: AppResolver,
}

impl<'a> DnsLookups<'a> {
    pub async fn lookups(self) -> PartialResult<DiffCompute<'a>> {
        self.env.console.print_partial_headers(
            "Running left lookups.",
            self.left_resolver.resolvers(),
            &self.query,
        );
        info!("Running left lookups");
        let left_query = self.query.clone();
        let (left_lookups, left_time) = time(self.left_resolver.lookup(left_query)).await?;
        info!("Finished left lookups in {:?}.", left_time);

        self.env.console.print_partial_headers(
            "Running right lookups.",
            self.right_resolver.resolvers(),
            &self.query,
        );
        info!("Running right lookups");
        let (right_lookups, right_time) = time(self.right_resolver.lookup(self.query)).await?;
        info!("Finished right lookups in {:?}.", right_time);

        if self.env.console.not_quiet() {
            self.env.console.info(format!(
                "Left: {} lookups in {:.1?}, Right: {} lookups in {:.1?}",
                left_lookups.len(),
                left_time,
                right_lookups.len(),
                right_time,
            ));
        }

        Ok(DiffCompute {
            env: self.env,
            left_lookups,
            right_lookups,
        })
    }
}

pub struct DiffCompute<'a> {
    env: Environment<'a, DiffConfig>,
    left_lookups: Lookups,
    right_lookups: Lookups,
}

impl<'a> DiffCompute<'a> {
    pub fn compute(self) -> DiffOutput<'a> {
        let left_servers: Vec<String> = self
            .env
            .mod_config
            .left
            .clone();
        let right_servers: Vec<String> = self
            .env
            .mod_config
            .right
            .clone();

        let mut all_types: HashSet<RecordType> = self.left_lookups.record_types();
        all_types.extend(self.right_lookups.record_types());
        let mut all_types: Vec<RecordType> = all_types.into_iter().collect();
        all_types.sort_by(|a, b| {
            use crate::app::output::Ordinal;
            a.ordinal().cmp(&b.ordinal())
        });

        let mut record_diffs = Vec::new();

        for rr_type in all_types {
            let left_records: HashSet<&Record> = self.left_lookups.records_by_type(rr_type).into_iter().collect();
            let right_records: HashSet<&Record> = self.right_lookups.records_by_type(rr_type).into_iter().collect();

            let only_left: Vec<Record> = left_records
                .difference(&right_records)
                .map(|r| (*r).clone())
                .collect();
            let only_right: Vec<Record> = right_records
                .difference(&left_records)
                .map(|r| (*r).clone())
                .collect();

            if !only_left.is_empty() || !only_right.is_empty() {
                record_diffs.push(RecordTypeDiff {
                    record_type: rr_type,
                    only_left,
                    only_right,
                });
            }
        }

        let results = DiffResults {
            domain_name: self.env.mod_config.domain_name.clone(),
            left_servers,
            right_servers,
            record_diffs,
        };

        DiffOutput {
            env: self.env,
            results,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DiffResults {
    pub domain_name: String,
    pub left_servers: Vec<String>,
    pub right_servers: Vec<String>,
    pub record_diffs: Vec<RecordTypeDiff>,
}

#[derive(Debug, Serialize)]
pub struct RecordTypeDiff {
    pub record_type: RecordType,
    pub only_left: Vec<Record>,
    pub only_right: Vec<Record>,
}

impl DiffResults {
    pub fn has_differences(&self) -> bool {
        !self.record_diffs.is_empty()
    }
}

impl SummaryFormatter for DiffResults {
    fn output<W: Write>(&self, writer: &mut W, opts: &SummaryOptions) -> crate::Result<()> {
        writeln!(writer, "DNS Diff for {}", self.domain_name)?;
        writeln!(writer, "  Left:  {}", self.left_servers.join(", "))?;
        writeln!(writer, "  Right: {}", self.right_servers.join(", "))?;
        writeln!(writer)?;

        if self.record_diffs.is_empty() {
            writeln!(writer, " {} No differences found.", output_styles::ok_prefix())?;
            return Ok(());
        }

        for diff in &self.record_diffs {
            writeln!(writer, " {} {}:", output_styles::caption_prefix(), diff.record_type)?;

            for record in &diff.only_left {
                writeln!(
                    writer,
                    "   {} left only: {}",
                    "-".paint(output_styles::ATTENTION),
                    record.render(opts),
                )?;
            }

            for record in &diff.only_right {
                writeln!(
                    writer,
                    "   {} right only: {}",
                    "+".paint(output_styles::OK),
                    record.render(opts),
                )?;
            }
        }

        Ok(())
    }
}

pub struct DiffOutput<'a> {
    env: Environment<'a, DiffConfig>,
    results: DiffResults,
}

impl DiffOutput<'_> {
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
            #[serde(flatten)]
            results: DiffResults,
        }
        impl SummaryFormatter for Json {
            fn output<W: Write>(&self, _: &mut W, _: &SummaryOptions) -> crate::Result<()> {
                Err(crate::Error::InternalError {
                    msg: "summary formatting is not supported for JSON output",
                })
            }
        }
        let data = Json {
            info: self.env.run_info,
            results: self.results,
        };

        output::output(&self.env.app_config.output_config, &data)?;
        Ok(ExitStatus::Ok)
    }

    fn summary_output(self) -> PartialResult<ExitStatus> {
        output::output(&self.env.app_config.output_config, &self.results)?;

        if self.env.console.not_quiet() {
            self.env.console.finished();
        }

        Ok(ExitStatus::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::RData;
    use hickory_resolver::Name;
    use std::net::Ipv4Addr;

    fn make_a_record(name: &str, ip: Ipv4Addr) -> Record {
        Record::new_for_test(
            Name::from_utf8(name).unwrap(),
            RecordType::A,
            300,
            RData::A(ip),
        )
    }

    #[test]
    fn diff_results_no_differences() {
        let results = DiffResults {
            domain_name: "example.com".to_string(),
            left_servers: vec!["8.8.8.8".to_string()],
            right_servers: vec!["1.1.1.1".to_string()],
            record_diffs: Vec::new(),
        };

        assert!(!results.has_differences());
    }

    #[test]
    fn diff_results_with_differences() {
        let results = DiffResults {
            domain_name: "example.com".to_string(),
            left_servers: vec!["8.8.8.8".to_string()],
            right_servers: vec!["1.1.1.1".to_string()],
            record_diffs: vec![RecordTypeDiff {
                record_type: RecordType::A,
                only_left: Vec::new(),
                only_right: Vec::new(),
            }],
        };

        assert!(results.has_differences());
    }

    #[test]
    fn summary_output_no_diffs() {
        let results = DiffResults {
            domain_name: "example.com".to_string(),
            left_servers: vec!["8.8.8.8".to_string()],
            right_servers: vec!["1.1.1.1".to_string()],
            record_diffs: Vec::new(),
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        let res = results.output(&mut buf, &opts);

        assert!(res.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("No differences found"));
    }

    #[test]
    fn summary_output_with_diffs() {
        let results = DiffResults {
            domain_name: "example.com".to_string(),
            left_servers: vec!["8.8.8.8".to_string()],
            right_servers: vec!["1.1.1.1".to_string()],
            record_diffs: vec![RecordTypeDiff {
                record_type: RecordType::A,
                only_left: vec![make_a_record("example.com", Ipv4Addr::new(1, 2, 3, 4))],
                only_right: vec![make_a_record("example.com", Ipv4Addr::new(5, 6, 7, 8))],
            }],
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        let res = results.output(&mut buf, &opts);

        assert!(res.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("left only"));
        assert!(output.contains("right only"));
        assert!(output.contains("1.2.3.4"));
        assert!(output.contains("5.6.7.8"));
    }

    #[test]
    fn summary_output_header_format() {
        let results = DiffResults {
            domain_name: "example.com".to_string(),
            left_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            right_servers: vec!["1.1.1.1".to_string()],
            record_diffs: Vec::new(),
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("DNS Diff for example.com"));
        assert!(output.contains("Left:  8.8.8.8, 8.8.4.4"));
        assert!(output.contains("Right: 1.1.1.1"));
    }

    #[test]
    fn parse_nameserver_specs_valid() {
        let specs = vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()];
        let result = parse_nameserver_specs(&specs);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn parse_nameserver_specs_invalid() {
        let specs = vec!["not-a-valid-nameserver-!!!".to_string()];
        let result = parse_nameserver_specs(&specs);
        assert!(result.is_err());
    }

    #[test]
    fn parse_nameserver_specs_empty() {
        let specs: Vec<String> = Vec::new();
        let result = parse_nameserver_specs(&specs);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn json_serialization() {
        let results = DiffResults {
            domain_name: "example.com".to_string(),
            left_servers: vec!["8.8.8.8".to_string()],
            right_servers: vec!["1.1.1.1".to_string()],
            record_diffs: vec![RecordTypeDiff {
                record_type: RecordType::A,
                only_left: vec![make_a_record("example.com", Ipv4Addr::new(1, 2, 3, 4))],
                only_right: Vec::new(),
            }],
        };

        let json = serde_json::to_string(&results);
        assert!(json.is_ok());
        let json = json.unwrap();
        assert!(json.contains("\"domain_name\":\"example.com\""));
        assert!(json.contains("\"left_servers\":[\"8.8.8.8\"]"));
        assert!(json.contains("\"record_diffs\""));
        assert!(json.contains("\"only_left\""));
    }
}
