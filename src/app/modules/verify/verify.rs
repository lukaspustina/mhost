// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::{HashMap, HashSet};
use std::io::Write;

use anyhow::Context;
use serde::Serialize;
use tracing::{debug, info};

use crate::app::modules::verify::config::VerifyConfig;
use crate::app::modules::{AppModule, Environment, PartialResult, RunInfo};
use crate::app::output::summary::{SummaryFormatter, SummaryOptions};
use crate::app::output::OutputType;
use crate::app::resolver::AppResolver;
use crate::app::utils::time;
use crate::app::{output, AppConfig, ExitStatus};
use crate::resolver::MultiQuery;
use crate::resources::zone;
use crate::resources::{Record, RecordType};
use crate::Name;

pub struct Verify {}

impl AppModule<VerifyConfig> for Verify {}

impl Verify {
    pub async fn init<'a>(
        app_config: &'a AppConfig,
        config: &'a VerifyConfig,
    ) -> PartialResult<VerifyCompare<'a>> {
        let env = Self::init_env(app_config, config)?;

        // Parse zone file
        let origin = config
            .origin
            .as_ref()
            .map(|o| Name::from_ascii(o).or_else(|_| Name::from_utf8(o)))
            .transpose()
            .context("Failed to parse origin")?;

        env.console
            .caption(format!("Parsing zone file: {}", config.zone_file.display()));
        info!("Parsing zone file: {}", config.zone_file.display());

        let zone = zone::parse(&config.zone_file, origin)?;
        let zone_origin = zone.origin().clone();
        let zone_records = zone.into_records();

        info!(
            "Parsed {} records from zone file (origin: {})",
            zone_records.len(),
            zone_origin
        );

        if zone_records.is_empty() {
            env.console
                .attention("Zone file contains no verifiable records.");
        }

        // Collect unique (name, record_type) pairs for querying
        let mut query_pairs: HashSet<(Name, RecordType)> = HashSet::new();
        for record in &zone_records {
            query_pairs.insert((record.name().clone(), record.record_type()));
        }

        // Build queries: one per unique name with its record types
        let mut names_to_types: HashMap<Name, HashSet<RecordType>> = HashMap::new();
        for (name, rtype) in &query_pairs {
            names_to_types
                .entry(name.clone())
                .or_default()
                .insert(*rtype);
        }

        let resolver = AppResolver::create_resolvers(app_config).await?;

        env.console
            .print_resolver_opts(resolver.resolver_group_opts(), resolver.resolver_opts());

        let all_names: Vec<Name> = names_to_types.keys().cloned().collect();
        let all_types: HashSet<RecordType> = names_to_types.values().flatten().copied().collect();
        let all_types: Vec<RecordType> = all_types.into_iter().collect();

        if all_names.is_empty() {
            return Ok(VerifyCompare {
                env,
                zone_records,
                zone_origin,
                live_records: Vec::new(),
            });
        }

        let query = MultiQuery::new(all_names, all_types).context("Failed to build query")?;

        env.console.caption("Running DNS lookups for verification.");
        info!("Running DNS lookups");
        let (lookups, lookup_time) = time(resolver.lookup(query)).await?;
        info!("Finished lookups in {:?}.", lookup_time);

        if env.console.not_quiet() {
            env.console
                .info(format!("{} lookups in {:.1?}", lookups.len(), lookup_time));
        }

        let live_records: Vec<Record> = lookups.records().into_iter().cloned().collect();

        Ok(VerifyCompare {
            env,
            zone_records,
            zone_origin,
            live_records,
        })
    }
}

pub struct VerifyCompare<'a> {
    env: Environment<'a, VerifyConfig>,
    zone_records: Vec<Record>,
    zone_origin: Name,
    live_records: Vec<Record>,
}

impl<'a> VerifyCompare<'a> {
    pub fn compare(self) -> VerifyOutput<'a> {
        // Group zone records by (name, type)
        let mut expected: HashMap<(Name, RecordType), HashSet<Record>> = HashMap::new();
        for record in &self.zone_records {
            expected
                .entry((record.name().clone(), record.record_type()))
                .or_default()
                .insert(record.clone());
        }

        // Group live records by (name, type)
        let mut actual: HashMap<(Name, RecordType), HashSet<Record>> = HashMap::new();
        for record in &self.live_records {
            actual
                .entry((record.name().clone(), record.record_type()))
                .or_default()
                .insert(record.clone());
        }

        let mut matches = Vec::new();
        let mut missing = Vec::new();
        let mut ttl_drifts = Vec::new();

        // Check each expected (name, type) pair
        for (key, expected_records) in &expected {
            match actual.get(key) {
                None => {
                    // No live records for this pair — all expected records are missing
                    missing.extend(expected_records.iter().cloned());
                }
                Some(actual_records) => {
                    for expected_record in expected_records {
                        if actual_records.contains(expected_record) {
                            matches.push(expected_record.clone());

                            // TTL drift check in strict mode
                            if self.env.mod_config.strict {
                                if let Some(actual_record) =
                                    actual_records.iter().find(|r| *r == expected_record)
                                {
                                    if expected_record.ttl() != actual_record.ttl() {
                                        ttl_drifts.push(TtlDrift {
                                            record: expected_record.clone(),
                                            expected_ttl: expected_record.ttl(),
                                            actual_ttl: actual_record.ttl(),
                                        });
                                    }
                                }
                            }
                        } else {
                            missing.push(expected_record.clone());
                        }
                    }
                }
            }
        }

        // Find extra records: in live DNS but not in zone file
        // Only for (name, type) pairs that appear in the zone file
        let mut extra = Vec::new();
        for (key, actual_records) in &actual {
            if let Some(expected_records) = expected.get(key) {
                for actual_record in actual_records {
                    if !expected_records.contains(actual_record) {
                        extra.push(actual_record.clone());
                    }
                }
            }
        }

        let results = VerifyResults {
            zone_file: self.env.mod_config.zone_file.display().to_string(),
            origin: self.zone_origin.to_string(),
            matches,
            missing,
            extra,
            ttl_drifts,
        };

        debug!("Verify results: {} matched, {} missing, {} extra, {} TTL drifts",
            results.matches.len(),
            results.missing.len(),
            results.extra.len(),
            results.ttl_drifts.len(),
        );

        VerifyOutput {
            env: self.env,
            results,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct VerifyResults {
    pub zone_file: String,
    pub origin: String,
    pub matches: Vec<Record>,
    pub missing: Vec<Record>,
    pub extra: Vec<Record>,
    pub ttl_drifts: Vec<TtlDrift>,
}

#[derive(Debug, Serialize)]
pub struct TtlDrift {
    pub record: Record,
    pub expected_ttl: u32,
    pub actual_ttl: u32,
}

impl VerifyResults {
    pub fn has_issues(&self) -> bool {
        !self.missing.is_empty() || !self.ttl_drifts.is_empty()
    }
}

pub struct VerifyOutput<'a> {
    env: Environment<'a, VerifyConfig>,
    results: VerifyResults,
}

impl VerifyOutput<'_> {
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
            results: VerifyResults,
        }
        impl SummaryFormatter for Json {
            fn output<W: Write>(&self, _: &mut W, _: &SummaryOptions) -> crate::Result<()> {
                Err(crate::Error::InternalError {
                    msg: "summary formatting is not supported for JSON output",
                })
            }
        }

        let has_issues = self.results.has_issues();
        let data = Json {
            info: self.env.run_info,
            results: self.results,
        };

        output::output(&self.env.app_config.output_config, &data)?;

        if has_issues {
            Ok(ExitStatus::CheckFailed)
        } else {
            Ok(ExitStatus::Ok)
        }
    }

    fn summary_output(self) -> PartialResult<ExitStatus> {
        let has_issues = self.results.has_issues();

        output::output(&self.env.app_config.output_config, &self.results)?;

        if self.env.console.not_quiet() {
            self.env.console.finished();
        }

        if has_issues {
            Ok(ExitStatus::CheckFailed)
        } else {
            Ok(ExitStatus::Ok)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::RData;
    use std::net::Ipv4Addr;

    fn make_a_record(name: &str, ip: Ipv4Addr, ttl: u32) -> Record {
        Record::new_for_test(
            Name::from_utf8(name).unwrap(),
            RecordType::A,
            ttl,
            RData::A(ip),
        )
    }

    fn make_mx_record(name: &str, pref: u16, exchange: &str, ttl: u32) -> Record {
        use crate::resources::rdata::MX;
        Record::new_for_test(
            Name::from_utf8(name).unwrap(),
            RecordType::MX,
            ttl,
            RData::MX(MX::new(pref, Name::from_utf8(exchange).unwrap())),
        )
    }

    #[test]
    fn verify_results_no_issues() {
        let results = VerifyResults {
            zone_file: "zone.db".to_string(),
            origin: "example.com.".to_string(),
            matches: vec![make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            missing: Vec::new(),
            extra: Vec::new(),
            ttl_drifts: Vec::new(),
        };

        assert!(!results.has_issues());
    }

    #[test]
    fn verify_results_with_missing() {
        let results = VerifyResults {
            zone_file: "zone.db".to_string(),
            origin: "example.com.".to_string(),
            matches: Vec::new(),
            missing: vec![make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            extra: Vec::new(),
            ttl_drifts: Vec::new(),
        };

        assert!(results.has_issues());
    }

    #[test]
    fn verify_results_with_ttl_drifts() {
        let results = VerifyResults {
            zone_file: "zone.db".to_string(),
            origin: "example.com.".to_string(),
            matches: vec![make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            missing: Vec::new(),
            extra: Vec::new(),
            ttl_drifts: vec![TtlDrift {
                record: make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300),
                expected_ttl: 3600,
                actual_ttl: 300,
            }],
        };

        assert!(results.has_issues());
    }

    #[test]
    fn verify_results_extra_not_an_issue() {
        let results = VerifyResults {
            zone_file: "zone.db".to_string(),
            origin: "example.com.".to_string(),
            matches: vec![make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            missing: Vec::new(),
            extra: vec![make_a_record("example.com.", Ipv4Addr::new(5, 6, 7, 8), 300)],
            ttl_drifts: Vec::new(),
        };

        assert!(!results.has_issues(), "extra records alone are informational, not issues");
    }

    #[test]
    fn json_serialization_round_trip() {
        let results = VerifyResults {
            zone_file: "zone.db".to_string(),
            origin: "example.com.".to_string(),
            matches: vec![make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            missing: vec![make_mx_record("example.com.", 10, "mail.example.com.", 300)],
            extra: Vec::new(),
            ttl_drifts: Vec::new(),
        };

        let json = serde_json::to_string(&results);
        assert!(json.is_ok());
        let json = json.unwrap();
        assert!(json.contains("\"zone_file\":\"zone.db\""));
        assert!(json.contains("\"origin\":\"example.com.\""));
        assert!(json.contains("\"missing\""));
        assert!(json.contains("\"matches\""));
    }

    #[test]
    fn summary_output_no_issues() {
        let results = VerifyResults {
            zone_file: "zone.db".to_string(),
            origin: "example.com.".to_string(),
            matches: vec![
                make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300),
                make_a_record("www.example.com.", Ipv4Addr::new(1, 2, 3, 4), 300),
            ],
            missing: Vec::new(),
            extra: Vec::new(),
            ttl_drifts: Vec::new(),
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        let res = results.output(&mut buf, &opts);
        assert!(res.is_ok());
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("All 2 records verified"));
    }

    #[test]
    fn summary_output_with_missing() {
        let results = VerifyResults {
            zone_file: "zone.db".to_string(),
            origin: "example.com.".to_string(),
            matches: vec![make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            missing: vec![make_a_record("www.example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            extra: Vec::new(),
            ttl_drifts: Vec::new(),
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Missing"));
        assert!(output.contains("1.2.3.4"));
    }

    #[test]
    fn summary_output_with_extra() {
        let results = VerifyResults {
            zone_file: "zone.db".to_string(),
            origin: "example.com.".to_string(),
            matches: vec![make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            missing: Vec::new(),
            extra: vec![make_a_record("example.com.", Ipv4Addr::new(5, 6, 7, 8), 300)],
            ttl_drifts: Vec::new(),
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("Extra"));
        assert!(output.contains("5.6.7.8"));
    }

    #[test]
    fn summary_output_with_ttl_drifts() {
        let results = VerifyResults {
            zone_file: "zone.db".to_string(),
            origin: "example.com.".to_string(),
            matches: vec![make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 300)],
            missing: Vec::new(),
            extra: Vec::new(),
            ttl_drifts: vec![TtlDrift {
                record: make_a_record("example.com.", Ipv4Addr::new(1, 2, 3, 4), 3600),
                expected_ttl: 3600,
                actual_ttl: 300,
            }],
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("TTL"));
        assert!(output.contains("3600"));
        assert!(output.contains("300"));
    }
}
