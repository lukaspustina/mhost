// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde::Serialize;
use tracing::{debug, info, warn};
use yansi::Paint;

use crate::app::modules::trace::config::TraceConfig;
use crate::app::modules::{AppModule, Environment, PartialResult, RunInfo};
use crate::app::output::summary::{Rendering, SummaryFormatter, SummaryOptions};
use crate::app::output::styles as output_styles;
use crate::app::output::OutputType;
use crate::app::resolver;
use crate::app::{output, AppConfig, ExitStatus};
use crate::resolver::delegation;
use crate::resolver::raw::{self, RawQueryResult};
use crate::resources::Record;
use crate::RecordType;

pub struct Trace {}

impl AppModule<TraceConfig> for Trace {}

impl Trace {
    pub async fn init<'a>(
        app_config: &'a AppConfig,
        config: &'a TraceConfig,
    ) -> PartialResult<TraceRun<'a>> {
        let env = Self::init_env(app_config, config)?;
        let domain_name = env.name_builder.from_str(&config.domain_name)?;

        Ok(TraceRun {
            env,
            domain_name,
        })
    }
}

pub struct TraceRun<'a> {
    env: Environment<'a, TraceConfig>,
    domain_name: hickory_resolver::Name,
}

impl<'a> TraceRun<'a> {
    pub async fn execute(self) -> PartialResult<TraceOutput<'a>> {
        let record_type = self.env.mod_config.record_type;
        let max_hops = self.env.mod_config.max_hops;
        let timeout = self.env.app_config.timeout;
        let show_all_servers = self.env.mod_config.show_all_servers;
        let partial_results = self.env.console.show_partial_results();

        let root_label = match (self.env.app_config.ipv4_only, self.env.app_config.ipv6_only) {
            (true, _) => "IPv4 root servers",
            (_, true) => "IPv6 root servers",
            _ => "IPv4+IPv6 root servers",
        };
        if self.env.console.not_quiet() {
            self.env.console.info(format!(
                "Tracing {} {} from {}.",
                self.domain_name, record_type, root_label
            ));
        }
        info!("Starting DNS trace for {} {}", self.domain_name, record_type);

        // Print header early when partial results are enabled
        if partial_results {
            let mut stdout = std::io::stdout();
            write_header(&mut stdout, &self.env.mod_config.domain_name, record_type)
                .map_err(|e| anyhow::anyhow!("failed to write partial output: {}", e))?;
        }

        let hickory_name = hickory_resolver::proto::rr::Name::from_ascii(
            self.domain_name.to_ascii(),
        )
        .map_err(|e| anyhow::anyhow!("failed to parse domain name: {}", e))?;

        let hickory_record_type: hickory_resolver::proto::rr::RecordType = record_type.into();

        let total_start = Instant::now();
        let hops = self.walk_delegation(
            &hickory_name,
            hickory_record_type,
            record_type,
            max_hops,
            timeout,
        )
        .await;
        let total_time = total_start.elapsed();

        // Print footer when partial results were shown
        if partial_results {
            let mut stdout = std::io::stdout();
            write_footer(&mut stdout, hops.len(), total_time)
                .map_err(|e| anyhow::anyhow!("failed to write partial output: {}", e))?;
        }

        let results = TraceResults {
            domain_name: self.env.mod_config.domain_name.clone(),
            record_type,
            hops,
            total_time,
            show_all_servers,
        };

        Ok(TraceOutput {
            env: self.env,
            results,
            partial_results_shown: partial_results,
        })
    }

    async fn walk_delegation(
        &self,
        name: &hickory_resolver::proto::rr::Name,
        hickory_rt: hickory_resolver::proto::rr::RecordType,
        record_type: RecordType,
        max_hops: usize,
        timeout: Duration,
    ) -> Vec<TraceHop> {
        let show_all_servers = self.env.mod_config.show_all_servers;
        let partial_results = self.env.console.show_partial_results();
        let mut hops = Vec::new();

        // Start with root servers based on IP version flags:
        //   -4 → IPv4 roots only, -6 → IPv6 roots only, default → both
        let mut current_servers = delegation::root_server_addrs(
            self.env.app_config.ipv4_only,
            self.env.app_config.ipv6_only,
        );

        let mut current_zone = ".".to_string();

        for level in 0..max_hops {
            if current_servers.is_empty() {
                warn!("No servers to query at level {}", level);
                if self.env.console.not_quiet() {
                    let family = if self.env.app_config.ipv4_only {
                        "IPv4"
                    } else if self.env.app_config.ipv6_only {
                        "IPv6"
                    } else {
                        "any"
                    };
                    self.env.console.attention(format!(
                        "No {} addresses available for nameservers at hop {}. \
                         Try without -4/-6 for dual-stack.",
                        family,
                        level + 1
                    ));
                }
                break;
            }

            let server_addrs: Vec<SocketAddr> =
                current_servers.iter().map(|(addr, _)| *addr).collect();

            // Build name → server_name map
            let server_names: HashMap<SocketAddr, Option<String>> =
                current_servers.iter().cloned().collect();

            debug!(
                "Hop {}: querying {} servers for {} {} (zone {})",
                level + 1,
                server_addrs.len(),
                name,
                hickory_rt,
                current_zone,
            );

            let results = raw::parallel_raw_queries(
                &server_addrs,
                name,
                hickory_rt,
                timeout,
                self.env.app_config.max_concurrent_servers,
            )
            .await;

            let (server_results, next_servers, is_final) =
                process_hop_results(&results, &server_names, record_type);

            let referral_groups = compute_referral_groups(&server_results);

            let hop = TraceHop {
                level: level + 1,
                zone_name: current_zone.clone(),
                servers_queried: server_addrs.len(),
                server_results,
                referral_groups,
                is_final,
            };

            hops.push(hop);

            // Print hop immediately when partial results are enabled
            if partial_results {
                if let Some(hop) = hops.last() {
                    let opts = SummaryOptions::default();
                    let mut stdout = std::io::stdout();
                    let _ = write_hop(&mut stdout, hop, &opts, show_all_servers);
                }
            }

            if is_final {
                debug!("Got authoritative answer at hop {}", level + 1);
                break;
            }

            if next_servers.is_empty() {
                warn!("No referral servers found at hop {}", level + 1);
                break;
            }

            // Determine the zone name from referrals
            if let Some(first_result) = hops.last() {
                if let Some(first_referral) = first_result
                    .server_results
                    .iter()
                    .find(|r| matches!(r.outcome, ServerOutcome::Referral))
                {
                    if !first_referral.referral_ns.is_empty() {
                        // The zone is determined by the NS record owner name from the authority section
                        // We'll use the authority section zone name from the raw results
                    }
                }
            }

            // Resolve glue if needed and build next hop server list
            let mut resolved_servers = next_servers.clone();
            resolver::resolve_missing_glue(self.env.app_config, &mut resolved_servers).await;

            // Build next hop server list, filtering by address family
            let mut next_zone = current_zone.clone();
            let referral = delegation::Referral {
                zone_name: current_zone.clone(),
                ns_servers: resolved_servers,
            };
            current_servers = delegation::build_server_list(&referral, |ip| {
                self.env.app_config.ip_allowed(ip)
            });

            // Determine next zone from the first referral's authority section
            if let Some(hop) = hops.last() {
                for sr in &hop.server_results {
                    if !sr.referral_ns.is_empty() {
                        // The zone name is inferred from the authority record owner
                        if let Some(ref zone) = sr.authority_zone {
                            next_zone = zone.clone();
                            break;
                        }
                    }
                }
            }
            current_zone = next_zone;
        }

        hops
    }

}

fn process_hop_results(
    results: &[RawQueryResult],
    server_names: &HashMap<SocketAddr, Option<String>>,
    record_type: RecordType,
) -> (
        Vec<ServerResult>,
        HashMap<String, Vec<IpAddr>>, // next_servers: ns_name -> glue IPs
        bool,                          // is_final
    ) {
        let mut server_results = Vec::new();
        let mut next_servers: HashMap<String, Vec<IpAddr>> = HashMap::new();
        let mut is_final = false;

        for rqr in results {
            let server_name = server_names
                .get(&rqr.server)
                .cloned()
                .flatten();

            match &rqr.result {
                Ok(response) => {
                    if response.is_authoritative() && !response.answers().is_empty() {
                        // Authoritative answer
                        let answer_records = response
                            .answers()
                            .iter()
                            .filter_map(|r| convert_record(r, record_type))
                            .collect();

                        server_results.push(ServerResult {
                            server_ip: rqr.server.ip(),
                            server_name,
                            latency: response.latency(),
                            outcome: ServerOutcome::Answer,
                            answer_records,
                            referral_ns: Vec::new(),
                            authority_zone: None,
                        });
                        is_final = true;
                    } else if response.is_authoritative() && response.answers().is_empty() {
                        // Authoritative NODATA or NXDOMAIN
                        let rcode = response.response_code();
                        server_results.push(ServerResult {
                            server_ip: rqr.server.ip(),
                            server_name,
                            latency: response.latency(),
                            outcome: ServerOutcome::Answer,
                            answer_records: Vec::new(),
                            referral_ns: Vec::new(),
                            authority_zone: None,
                        });
                        is_final = true;
                        debug!(
                            "Authoritative {} from {} (rcode={:?})",
                            if rcode == hickory_resolver::proto::op::ResponseCode::NXDomain {
                                "NXDOMAIN"
                            } else {
                                "NODATA"
                            },
                            rqr.server,
                            rcode
                        );
                    } else {
                        // Referral — extract NS from authority section
                        let ns_names = response.referral_ns_names();
                        let glue = response.glue_ips();
                        let referral_ns: Vec<String> =
                            ns_names.iter().map(|n| n.to_ascii()).collect();

                        // Determine zone name from authority section owner
                        let authority_zone = response
                            .authority()
                            .iter()
                            .find(|r| {
                                r.record_type()
                                    == hickory_resolver::proto::rr::RecordType::NS
                            })
                            .map(|r| r.name().to_ascii());

                        // Collect glue IPs per NS name
                        for ns_name in &ns_names {
                            let ips: Vec<IpAddr> = glue
                                .iter()
                                .filter(|(name, _)| name == ns_name)
                                .map(|(_, ip)| *ip)
                                .collect();
                            let entry = next_servers
                                .entry(ns_name.to_ascii())
                                .or_default();
                            for ip in ips {
                                if !entry.contains(&ip) {
                                    entry.push(ip);
                                }
                            }
                        }

                        server_results.push(ServerResult {
                            server_ip: rqr.server.ip(),
                            server_name,
                            latency: response.latency(),
                            outcome: ServerOutcome::Referral,
                            answer_records: Vec::new(),
                            referral_ns,
                            authority_zone,
                        });
                    }
                }
                Err(e) => {
                    server_results.push(ServerResult {
                        server_ip: rqr.server.ip(),
                        server_name,
                        latency: Duration::ZERO,
                        outcome: ServerOutcome::Error(format!("{}", e)),
                        answer_records: Vec::new(),
                        referral_ns: Vec::new(),
                        authority_zone: None,
                    });
                }
            }
        }

        (server_results, next_servers, is_final)
}

/// Convert a hickory-proto Record to mhost Record.
fn convert_record(
    record: &hickory_resolver::proto::rr::Record,
    _record_type: RecordType,
) -> Option<Record> {
    Some(Record::from(record))
}

fn compute_referral_groups(server_results: &[ServerResult]) -> Vec<ReferralGroup> {
    let mut groups: HashMap<Vec<String>, Vec<IpAddr>> = HashMap::new();

    for sr in server_results {
        if !matches!(sr.outcome, ServerOutcome::Referral) {
            continue;
        }
        let mut ns_names = sr.referral_ns.clone();
        ns_names.sort();
        groups.entry(ns_names).or_default().push(sr.server_ip);
    }

    let total_referrals: usize = groups.values().map(|v| v.len()).sum();
    let mut referral_groups: Vec<ReferralGroup> = groups
        .into_iter()
        .map(|(ns_names, servers)| {
            let is_majority = servers.len() * 2 > total_referrals;
            ReferralGroup {
                ns_names,
                servers,
                is_majority,
            }
        })
        .collect();

    // Sort: majority group first, then by size descending
    referral_groups.sort_by(|a, b| {
        b.is_majority
            .cmp(&a.is_majority)
            .then_with(|| b.servers.len().cmp(&a.servers.len()))
    });

    referral_groups
}

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct TraceResults {
    pub domain_name: String,
    pub record_type: RecordType,
    pub hops: Vec<TraceHop>,
    #[serde(serialize_with = "serialize_duration_ms")]
    pub total_time: Duration,
    #[serde(skip)]
    pub show_all_servers: bool,
}

#[derive(Debug, Serialize)]
pub struct TraceHop {
    pub level: usize,
    pub zone_name: String,
    pub servers_queried: usize,
    pub server_results: Vec<ServerResult>,
    pub referral_groups: Vec<ReferralGroup>,
    pub is_final: bool,
}

#[derive(Debug, Serialize)]
pub struct ServerResult {
    pub server_ip: IpAddr,
    pub server_name: Option<String>,
    #[serde(serialize_with = "serialize_duration_ms")]
    pub latency: Duration,
    pub outcome: ServerOutcome,
    pub answer_records: Vec<Record>,
    pub referral_ns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_zone: Option<String>,
}

#[derive(Debug, Serialize)]
pub enum ServerOutcome {
    Referral,
    Answer,
    Error(String),
}

#[derive(Debug, Serialize)]
pub struct ReferralGroup {
    pub ns_names: Vec<String>,
    pub servers: Vec<IpAddr>,
    pub is_majority: bool,
}

fn serialize_duration_ms<S>(d: &Duration, s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_f64(d.as_secs_f64() * 1000.0)
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

pub struct TraceOutput<'a> {
    pub env: Environment<'a, TraceConfig>,
    pub results: TraceResults,
    pub partial_results_shown: bool,
}

impl TraceOutput<'_> {
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
            results: TraceResults,
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
        if !self.partial_results_shown {
            output::output(&self.env.app_config.output_config, &self.results)?;
        }

        if self.env.console.not_quiet() {
            self.env.console.finished();
        }

        Ok(ExitStatus::Ok)
    }
}

// ---------------------------------------------------------------------------
// Summary formatter
// ---------------------------------------------------------------------------

/// Write the summary header line.
fn write_header<W: Write>(writer: &mut W, domain_name: &str, record_type: RecordType) -> crate::Result<()> {
    writeln!(
        writer,
        "{} DNS Trace: {} {}",
        output_styles::caption_prefix(),
        domain_name,
        record_type,
    )?;
    Ok(())
}

/// Write the summary footer line.
fn write_footer<W: Write>(writer: &mut W, hop_count: usize, total_time: Duration) -> crate::Result<()> {
    writeln!(writer)?;
    writeln!(
        writer,
        "{} Trace complete: {} hop{}, {:.0?} total",
        output_styles::finished_prefix(),
        hop_count,
        if hop_count == 1 { "" } else { "s" },
        total_time,
    )?;
    Ok(())
}

/// Write a single hop's summary output.
fn write_hop<W: Write>(
    writer: &mut W,
    hop: &TraceHop,
    opts: &SummaryOptions,
    show_all_servers: bool,
) -> crate::Result<()> {
    writeln!(writer)?;

    let zone_label = if hop.zone_name == "." {
        "Root (.)".to_string()
    } else {
        hop.zone_name.clone()
    };

    writeln!(
        writer,
        "{} Hop {}: {} \u{2014} {} server{} queried",
        output_styles::info_prefix(),
        hop.level,
        zone_label.paint(output_styles::EMPH),
        hop.servers_queried,
        if hop.servers_queried == 1 { "" } else { "s" },
    )?;

    // Count outcomes
    let answer_count = hop
        .server_results
        .iter()
        .filter(|r| matches!(r.outcome, ServerOutcome::Answer))
        .count();
    let referral_count = hop
        .server_results
        .iter()
        .filter(|r| matches!(r.outcome, ServerOutcome::Referral))
        .count();
    let error_count = hop
        .server_results
        .iter()
        .filter(|r| matches!(r.outcome, ServerOutcome::Error(_)))
        .count();

    // Compute average latency for successful responses
    let successful_latencies: Vec<Duration> = hop
        .server_results
        .iter()
        .filter(|r| !matches!(r.outcome, ServerOutcome::Error(_)))
        .map(|r| r.latency)
        .collect();
    let avg_latency = if successful_latencies.is_empty() {
        Duration::ZERO
    } else {
        successful_latencies.iter().sum::<Duration>() / successful_latencies.len() as u32
    };

    let responded_count = answer_count + referral_count;

    if hop.is_final {
        // Final answer
        writeln!(
            writer,
            " {} {} ({}/{} consistent, avg {:.0?})",
            output_styles::ok_prefix(),
            "Answer".paint(output_styles::OK),
            answer_count,
            responded_count,
            avg_latency,
        )?;

        // Print answer records
        let mut all_records: Vec<&Record> = Vec::new();
        for sr in &hop.server_results {
            for record in &sr.answer_records {
                if !all_records.contains(&record) {
                    all_records.push(record);
                }
            }
        }

        if all_records.is_empty() {
            // NXDOMAIN or NODATA
            writeln!(
                writer,
                " {} No records returned (NXDOMAIN or NODATA)",
                output_styles::info_prefix(),
            )?;
        } else {
            for record in &all_records {
                writeln!(
                    writer,
                    " {} {}",
                    output_styles::itemization_prefix(),
                    record.render(opts),
                )?;
            }
        }
    } else {
        // Referral
        if hop.referral_groups.len() <= 1 {
            // Consistent referral
            if let Some(group) = hop.referral_groups.first() {
                let target_zone = hop
                    .server_results
                    .iter()
                    .find_map(|sr| sr.authority_zone.clone())
                    .unwrap_or_else(|| "?".to_string());

                writeln!(
                    writer,
                    " {} Referral \u{2192} {} ({}/{} consistent, avg {:.0?})",
                    output_styles::ok_prefix(),
                    target_zone.paint(output_styles::EMPH),
                    referral_count,
                    responded_count,
                    avg_latency,
                )?;

                let ns_list = group.ns_names.join(" ");
                writeln!(
                    writer,
                    " {} NS: {}",
                    output_styles::info_prefix(),
                    ns_list,
                )?;
            }
        } else {
            // Divergence
            writeln!(
                writer,
                " {} {}: {} different referral sets",
                output_styles::attention_prefix(),
                "DIVERGENCE".paint(output_styles::ATTENTION),
                hop.referral_groups.len(),
            )?;

            for (i, group) in hop.referral_groups.iter().enumerate() {
                let target_zone = hop
                    .server_results
                    .iter()
                    .find(|sr| group.servers.contains(&sr.server_ip))
                    .and_then(|sr| sr.authority_zone.clone())
                    .unwrap_or_else(|| "?".to_string());

                writeln!(
                    writer,
                    " {} Group {} ({}/{}): \u{2192} {} NS: {}",
                    output_styles::info_prefix(),
                    i + 1,
                    group.servers.len(),
                    referral_count,
                    target_zone,
                    group.ns_names.join(" "),
                )?;
            }
        }
    }

    // Show per-server details if --show-all-servers
    if show_all_servers {
        for sr in &hop.server_results {
            let name_str = sr
                .server_name
                .as_deref()
                .unwrap_or("unknown");
            let outcome_str = match &sr.outcome {
                ServerOutcome::Referral => "Referral".to_string(),
                ServerOutcome::Answer => "Answer".to_string(),
                ServerOutcome::Error(msg) => format!("Error: {}", msg),
            };
            let latency_str = if matches!(sr.outcome, ServerOutcome::Error(_)) {
                "-".to_string()
            } else {
                format!("{:.0?}", sr.latency)
            };
            writeln!(
                writer,
                " {} {} ({}) {} {}",
                output_styles::itemization_prefix(),
                sr.server_ip,
                name_str,
                latency_str,
                outcome_str,
            )?;
        }
    }

    // Show errors if any (when not showing all servers, since errors are already included above)
    if !show_all_servers && error_count > 0 {
        let errors: Vec<&ServerResult> = hop
            .server_results
            .iter()
            .filter(|r| matches!(r.outcome, ServerOutcome::Error(_)))
            .collect();
        for err_result in errors {
            if let ServerOutcome::Error(ref msg) = err_result.outcome {
                writeln!(
                    writer,
                    " {} {} ({}): {}",
                    output_styles::attention_prefix(),
                    err_result.server_ip,
                    err_result
                        .server_name
                        .as_deref()
                        .unwrap_or("unknown"),
                    msg.paint(output_styles::ERROR),
                )?;
            }
        }
    }

    Ok(())
}

impl SummaryFormatter for TraceResults {
    fn output<W: Write>(&self, writer: &mut W, opts: &SummaryOptions) -> crate::Result<()> {
        write_header(writer, &self.domain_name, self.record_type)?;

        for hop in &self.hops {
            write_hop(writer, hop, opts, self.show_all_servers)?;
        }

        write_footer(writer, self.hops.len(), self.total_time)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::rdata::RData;
    use hickory_resolver::Name;
    use std::net::Ipv4Addr;

    fn make_a_record(domain: &str, ip: Ipv4Addr) -> Record {
        Record::new_for_test(
            Name::from_utf8(domain).unwrap(),
            RecordType::A,
            300,
            RData::A(ip),
        )
    }

    #[test]
    fn compute_referral_groups_single_group() {
        let results = vec![
            ServerResult {
                server_ip: IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
                server_name: None,
                latency: Duration::from_millis(15),
                outcome: ServerOutcome::Referral,
                answer_records: Vec::new(),
                referral_ns: vec![
                    "a.gtld-servers.net.".to_string(),
                    "b.gtld-servers.net.".to_string(),
                ],
                authority_zone: Some("com.".to_string()),
            },
            ServerResult {
                server_ip: IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
                server_name: None,
                latency: Duration::from_millis(20),
                outcome: ServerOutcome::Referral,
                answer_records: Vec::new(),
                referral_ns: vec![
                    "a.gtld-servers.net.".to_string(),
                    "b.gtld-servers.net.".to_string(),
                ],
                authority_zone: Some("com.".to_string()),
            },
        ];

        let groups = compute_referral_groups(&results);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].servers.len(), 2);
        assert!(groups[0].is_majority);
    }

    #[test]
    fn compute_referral_groups_divergence() {
        let results = vec![
            ServerResult {
                server_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                server_name: None,
                latency: Duration::from_millis(15),
                outcome: ServerOutcome::Referral,
                answer_records: Vec::new(),
                referral_ns: vec!["ns1.example.com.".to_string(), "ns2.example.com.".to_string()],
                authority_zone: Some("example.com.".to_string()),
            },
            ServerResult {
                server_ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
                server_name: None,
                latency: Duration::from_millis(20),
                outcome: ServerOutcome::Referral,
                answer_records: Vec::new(),
                referral_ns: vec!["ns1.example.com.".to_string(), "ns3.example.com.".to_string()],
                authority_zone: Some("example.com.".to_string()),
            },
        ];

        let groups = compute_referral_groups(&results);
        assert_eq!(groups.len(), 2);
        // Neither group is majority when exactly split
        assert!(!groups[0].is_majority);
        assert!(!groups[1].is_majority);
    }

    #[test]
    fn compute_referral_groups_skips_non_referrals() {
        let results = vec![
            ServerResult {
                server_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                server_name: None,
                latency: Duration::from_millis(15),
                outcome: ServerOutcome::Answer,
                answer_records: vec![make_a_record("example.com", Ipv4Addr::new(93, 184, 216, 34))],
                referral_ns: Vec::new(),
                authority_zone: None,
            },
        ];

        let groups = compute_referral_groups(&results);
        assert!(groups.is_empty());
    }

    #[test]
    fn trace_results_serialization() {
        let results = TraceResults {
            domain_name: "example.com".to_string(),
            record_type: RecordType::A,
            hops: vec![TraceHop {
                level: 1,
                zone_name: ".".to_string(),
                servers_queried: 13,
                server_results: Vec::new(),
                referral_groups: Vec::new(),
                is_final: false,
            }],
            total_time: Duration::from_millis(52),
            show_all_servers: false,
        };

        let json = serde_json::to_string(&results);
        assert!(json.is_ok());
        let json = json.unwrap();
        assert!(json.contains("\"domain_name\":\"example.com\""));
        assert!(json.contains("\"record_type\":\"A\""));
        assert!(json.contains("\"hops\""));
    }

    #[test]
    fn summary_output_renders() {
        let results = TraceResults {
            domain_name: "example.com".to_string(),
            record_type: RecordType::A,
            hops: vec![
                TraceHop {
                    level: 1,
                    zone_name: ".".to_string(),
                    servers_queried: 2,
                    server_results: vec![
                        ServerResult {
                            server_ip: IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
                            server_name: None,
                            latency: Duration::from_millis(15),
                            outcome: ServerOutcome::Referral,
                            answer_records: Vec::new(),
                            referral_ns: vec!["a.gtld-servers.net.".to_string()],
                            authority_zone: Some("com.".to_string()),
                        },
                        ServerResult {
                            server_ip: IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
                            server_name: None,
                            latency: Duration::from_millis(20),
                            outcome: ServerOutcome::Referral,
                            answer_records: Vec::new(),
                            referral_ns: vec!["a.gtld-servers.net.".to_string()],
                            authority_zone: Some("com.".to_string()),
                        },
                    ],
                    referral_groups: vec![ReferralGroup {
                        ns_names: vec!["a.gtld-servers.net.".to_string()],
                        servers: vec![
                            IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
                            IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
                        ],
                        is_majority: true,
                    }],
                    is_final: false,
                },
                TraceHop {
                    level: 2,
                    zone_name: "com.".to_string(),
                    servers_queried: 1,
                    server_results: vec![ServerResult {
                        server_ip: IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30)),
                        server_name: Some("a.gtld-servers.net.".to_string()),
                        latency: Duration::from_millis(9),
                        outcome: ServerOutcome::Answer,
                        answer_records: vec![make_a_record(
                            "example.com",
                            Ipv4Addr::new(93, 184, 216, 34),
                        )],
                        referral_ns: Vec::new(),
                        authority_zone: None,
                    }],
                    referral_groups: Vec::new(),
                    is_final: true,
                },
            ],
            total_time: Duration::from_millis(52),
            show_all_servers: false,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("DNS Trace: example.com A"));
        assert!(output.contains("Hop 1:"));
        assert!(output.contains("Root (.)"));
        assert!(output.contains("Referral"));
        assert!(output.contains("com."));
        assert!(output.contains("Hop 2:"));
        assert!(output.contains("Answer"));
        assert!(output.contains("Trace complete:"));
        assert!(output.contains("2 hops"));
    }

    // -----------------------------------------------------------------------
    // process_hop_results tests
    // -----------------------------------------------------------------------

    use hickory_resolver::proto::op::{Message, MessageType, ResponseCode};
    use hickory_resolver::proto::rr::{
        rdata, RData as ProtoRData, Record as ProtoRecord,
    };
    use raw::{RawQueryResult, RawResponse};

    fn make_server_names(
        addrs: &[SocketAddr],
        names: &[Option<String>],
    ) -> HashMap<SocketAddr, Option<String>> {
        addrs.iter().cloned().zip(names.iter().cloned()).collect()
    }

    fn make_referral_response(
        zone: &str,
        ns_names: &[&str],
        glue: &[(&str, Ipv4Addr)],
    ) -> RawResponse {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);
        msg.set_authoritative(false);

        for ns_name in ns_names {
            let ns_record = ProtoRecord::from_rdata(
                hickory_resolver::proto::rr::Name::from_ascii(zone).unwrap(),
                172800,
                ProtoRData::NS(rdata::NS(
                    hickory_resolver::proto::rr::Name::from_ascii(ns_name).unwrap(),
                )),
            );
            msg.add_name_server(ns_record);
        }

        for (name, ip) in glue {
            let a_record = ProtoRecord::from_rdata(
                hickory_resolver::proto::rr::Name::from_ascii(name).unwrap(),
                172800,
                ProtoRData::A(rdata::A(*ip)),
            );
            msg.add_additional(a_record);
        }

        RawResponse::new_for_test(msg, Duration::from_millis(15))
    }

    fn make_authoritative_response(records: Vec<ProtoRecord>) -> RawResponse {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);
        msg.set_authoritative(true);
        for record in records {
            msg.add_answer(record);
        }
        RawResponse::new_for_test(msg, Duration::from_millis(9))
    }

    fn make_authoritative_empty(rcode: ResponseCode) -> RawResponse {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);
        msg.set_authoritative(true);
        msg.set_response_code(rcode);
        RawResponse::new_for_test(msg, Duration::from_millis(5))
    }

    fn addr(ip: Ipv4Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip), 53)
    }

    #[test]
    fn process_hop_referral_extracts_ns_and_glue() {
        let server = addr(Ipv4Addr::new(198, 41, 0, 4));
        let response = make_referral_response(
            "com.",
            &["a.gtld-servers.net.", "b.gtld-servers.net."],
            &[
                ("a.gtld-servers.net.", Ipv4Addr::new(192, 5, 6, 30)),
                ("b.gtld-servers.net.", Ipv4Addr::new(192, 33, 14, 30)),
            ],
        );

        let results = vec![RawQueryResult {
            server,
            result: Ok(response),
        }];
        let names = make_server_names(&[server], &[None]);

        let (server_results, next_servers, is_final) =
            process_hop_results(&results, &names, RecordType::A);

        assert!(!is_final);
        assert_eq!(server_results.len(), 1);
        assert!(matches!(
            server_results[0].outcome,
            ServerOutcome::Referral
        ));
        assert_eq!(server_results[0].referral_ns.len(), 2);
        assert_eq!(server_results[0].authority_zone, Some("com.".to_string()));

        // Glue IPs should be collected
        assert_eq!(next_servers.len(), 2);
        assert!(next_servers.contains_key("a.gtld-servers.net."));
        assert!(next_servers.contains_key("b.gtld-servers.net."));
        assert_eq!(
            next_servers["a.gtld-servers.net."],
            vec![IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30))]
        );
    }

    #[test]
    fn process_hop_authoritative_answer() {
        let server = addr(Ipv4Addr::new(93, 184, 216, 34));
        let a_record = ProtoRecord::from_rdata(
            hickory_resolver::proto::rr::Name::from_ascii("example.com.").unwrap(),
            3600,
            ProtoRData::A(rdata::A(Ipv4Addr::new(93, 184, 216, 34))),
        );
        let response = make_authoritative_response(vec![a_record]);

        let results = vec![RawQueryResult {
            server,
            result: Ok(response),
        }];
        let names = make_server_names(&[server], &[Some("ns1.example.com.".to_string())]);

        let (server_results, next_servers, is_final) =
            process_hop_results(&results, &names, RecordType::A);

        assert!(is_final);
        assert_eq!(server_results.len(), 1);
        assert!(matches!(server_results[0].outcome, ServerOutcome::Answer));
        assert_eq!(server_results[0].answer_records.len(), 1);
        assert_eq!(
            server_results[0].server_name,
            Some("ns1.example.com.".to_string())
        );
        assert!(next_servers.is_empty());
    }

    #[test]
    fn process_hop_authoritative_nxdomain() {
        let server = addr(Ipv4Addr::new(10, 0, 0, 1));
        let response = make_authoritative_empty(ResponseCode::NXDomain);

        let results = vec![RawQueryResult {
            server,
            result: Ok(response),
        }];
        let names = make_server_names(&[server], &[None]);

        let (server_results, _, is_final) =
            process_hop_results(&results, &names, RecordType::A);

        assert!(is_final);
        assert_eq!(server_results.len(), 1);
        assert!(matches!(server_results[0].outcome, ServerOutcome::Answer));
        assert!(server_results[0].answer_records.is_empty());
    }

    #[test]
    fn process_hop_error_result() {
        let server = addr(Ipv4Addr::new(10, 0, 0, 1));

        let results = vec![RawQueryResult {
            server,
            result: Err(raw::RawError::Timeout(Duration::from_secs(5))),
        }];
        let names = make_server_names(&[server], &[Some("ns1.example.com.".to_string())]);

        let (server_results, next_servers, is_final) =
            process_hop_results(&results, &names, RecordType::A);

        assert!(!is_final);
        assert_eq!(server_results.len(), 1);
        assert!(matches!(
            server_results[0].outcome,
            ServerOutcome::Error(_)
        ));
        assert_eq!(server_results[0].latency, Duration::ZERO);
        assert!(next_servers.is_empty());
    }

    #[test]
    fn process_hop_mixed_referral_and_error() {
        let server1 = addr(Ipv4Addr::new(198, 41, 0, 4));
        let server2 = addr(Ipv4Addr::new(170, 247, 170, 2));

        let referral = make_referral_response(
            "com.",
            &["a.gtld-servers.net."],
            &[("a.gtld-servers.net.", Ipv4Addr::new(192, 5, 6, 30))],
        );

        let results = vec![
            RawQueryResult {
                server: server1,
                result: Ok(referral),
            },
            RawQueryResult {
                server: server2,
                result: Err(raw::RawError::Timeout(Duration::from_secs(5))),
            },
        ];
        let names = make_server_names(&[server1, server2], &[None, None]);

        let (server_results, next_servers, is_final) =
            process_hop_results(&results, &names, RecordType::A);

        assert!(!is_final);
        assert_eq!(server_results.len(), 2);

        let referrals: Vec<_> = server_results
            .iter()
            .filter(|r| matches!(r.outcome, ServerOutcome::Referral))
            .collect();
        let errors: Vec<_> = server_results
            .iter()
            .filter(|r| matches!(r.outcome, ServerOutcome::Error(_)))
            .collect();
        assert_eq!(referrals.len(), 1);
        assert_eq!(errors.len(), 1);
        assert_eq!(next_servers.len(), 1);
    }

    #[test]
    fn process_hop_referral_without_glue() {
        let server = addr(Ipv4Addr::new(198, 41, 0, 4));
        // Referral with NS but no glue records
        let response = make_referral_response(
            "example.com.",
            &["ns1.otherdomain.net."],
            &[],
        );

        let results = vec![RawQueryResult {
            server,
            result: Ok(response),
        }];
        let names = make_server_names(&[server], &[None]);

        let (server_results, next_servers, is_final) =
            process_hop_results(&results, &names, RecordType::A);

        assert!(!is_final);
        assert_eq!(server_results.len(), 1);
        assert!(matches!(
            server_results[0].outcome,
            ServerOutcome::Referral
        ));
        // NS name present but with empty glue
        assert!(next_servers.contains_key("ns1.otherdomain.net."));
        assert!(next_servers["ns1.otherdomain.net."].is_empty());
    }

    // -----------------------------------------------------------------------
    // Summary output edge case tests
    // -----------------------------------------------------------------------

    #[test]
    fn summary_output_divergence() {
        let results = TraceResults {
            domain_name: "example.com".to_string(),
            record_type: RecordType::A,
            hops: vec![TraceHop {
                level: 1,
                zone_name: ".".to_string(),
                servers_queried: 2,
                server_results: vec![
                    ServerResult {
                        server_ip: IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
                        server_name: None,
                        latency: Duration::from_millis(15),
                        outcome: ServerOutcome::Referral,
                        answer_records: Vec::new(),
                        referral_ns: vec!["ns1.example.com.".to_string()],
                        authority_zone: Some("example.com.".to_string()),
                    },
                    ServerResult {
                        server_ip: IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
                        server_name: None,
                        latency: Duration::from_millis(20),
                        outcome: ServerOutcome::Referral,
                        answer_records: Vec::new(),
                        referral_ns: vec!["ns2.example.com.".to_string()],
                        authority_zone: Some("example.com.".to_string()),
                    },
                ],
                referral_groups: vec![
                    ReferralGroup {
                        ns_names: vec!["ns1.example.com.".to_string()],
                        servers: vec![IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4))],
                        is_majority: false,
                    },
                    ReferralGroup {
                        ns_names: vec!["ns2.example.com.".to_string()],
                        servers: vec![IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2))],
                        is_majority: false,
                    },
                ],
                is_final: false,
            }],
            total_time: Duration::from_millis(20),
            show_all_servers: false,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("DIVERGENCE"));
        assert!(output.contains("2 different referral sets"));
        assert!(output.contains("Group 1"));
        assert!(output.contains("Group 2"));
    }

    #[test]
    fn summary_output_nxdomain() {
        let results = TraceResults {
            domain_name: "nonexistent.example.com".to_string(),
            record_type: RecordType::A,
            hops: vec![TraceHop {
                level: 1,
                zone_name: "example.com.".to_string(),
                servers_queried: 1,
                server_results: vec![ServerResult {
                    server_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    server_name: Some("ns1.example.com.".to_string()),
                    latency: Duration::from_millis(5),
                    outcome: ServerOutcome::Answer,
                    answer_records: Vec::new(),
                    referral_ns: Vec::new(),
                    authority_zone: None,
                }],
                referral_groups: Vec::new(),
                is_final: true,
            }],
            total_time: Duration::from_millis(5),
            show_all_servers: false,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Answer"));
        assert!(output.contains("No records returned"));
    }

    #[test]
    fn summary_output_errors_shown() {
        let results = TraceResults {
            domain_name: "example.com".to_string(),
            record_type: RecordType::A,
            hops: vec![TraceHop {
                level: 1,
                zone_name: ".".to_string(),
                servers_queried: 1,
                server_results: vec![ServerResult {
                    server_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    server_name: Some("broken.root.".to_string()),
                    latency: Duration::ZERO,
                    outcome: ServerOutcome::Error("query timed out after 5s".to_string()),
                    answer_records: Vec::new(),
                    referral_ns: Vec::new(),
                    authority_zone: None,
                }],
                referral_groups: Vec::new(),
                is_final: false,
            }],
            total_time: Duration::from_secs(5),
            show_all_servers: false,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("10.0.0.1"));
        assert!(output.contains("broken.root."));
        assert!(output.contains("query timed out"));
    }

    #[test]
    fn summary_output_show_all_servers() {
        let results = TraceResults {
            domain_name: "example.com".to_string(),
            record_type: RecordType::A,
            hops: vec![TraceHop {
                level: 1,
                zone_name: ".".to_string(),
                servers_queried: 2,
                server_results: vec![
                    ServerResult {
                        server_ip: IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
                        server_name: Some("a.root-servers.net.".to_string()),
                        latency: Duration::from_millis(15),
                        outcome: ServerOutcome::Referral,
                        answer_records: Vec::new(),
                        referral_ns: vec!["a.gtld-servers.net.".to_string()],
                        authority_zone: Some("com.".to_string()),
                    },
                    ServerResult {
                        server_ip: IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
                        server_name: Some("b.root-servers.net.".to_string()),
                        latency: Duration::from_millis(20),
                        outcome: ServerOutcome::Referral,
                        answer_records: Vec::new(),
                        referral_ns: vec!["a.gtld-servers.net.".to_string()],
                        authority_zone: Some("com.".to_string()),
                    },
                ],
                referral_groups: vec![ReferralGroup {
                    ns_names: vec!["a.gtld-servers.net.".to_string()],
                    servers: vec![
                        IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
                        IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
                    ],
                    is_majority: true,
                }],
                is_final: false,
            }],
            total_time: Duration::from_millis(20),
            show_all_servers: true,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Per-server details should appear
        assert!(output.contains("198.41.0.4"));
        assert!(output.contains("a.root-servers.net."));
        assert!(output.contains("170.247.170.2"));
        assert!(output.contains("b.root-servers.net."));
        assert!(output.contains("Referral"));
    }

    #[test]
    fn summary_output_no_show_all_servers_hides_details() {
        let results = TraceResults {
            domain_name: "example.com".to_string(),
            record_type: RecordType::A,
            hops: vec![TraceHop {
                level: 1,
                zone_name: ".".to_string(),
                servers_queried: 2,
                server_results: vec![
                    ServerResult {
                        server_ip: IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
                        server_name: Some("a.root-servers.net.".to_string()),
                        latency: Duration::from_millis(15),
                        outcome: ServerOutcome::Referral,
                        answer_records: Vec::new(),
                        referral_ns: vec!["a.gtld-servers.net.".to_string()],
                        authority_zone: Some("com.".to_string()),
                    },
                    ServerResult {
                        server_ip: IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
                        server_name: Some("b.root-servers.net.".to_string()),
                        latency: Duration::from_millis(20),
                        outcome: ServerOutcome::Referral,
                        answer_records: Vec::new(),
                        referral_ns: vec!["a.gtld-servers.net.".to_string()],
                        authority_zone: Some("com.".to_string()),
                    },
                ],
                referral_groups: vec![ReferralGroup {
                    ns_names: vec!["a.gtld-servers.net.".to_string()],
                    servers: vec![
                        IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
                        IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
                    ],
                    is_majority: true,
                }],
                is_final: false,
            }],
            total_time: Duration::from_millis(20),
            show_all_servers: false,
        };

        let opts = SummaryOptions::default();
        let mut buf = Vec::new();
        results.output(&mut buf, &opts).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Per-server IPs should NOT appear when show_all_servers is false
        // (no errors, so no individual server lines)
        assert!(!output.contains("198.41.0.4"));
        assert!(!output.contains("170.247.170.2"));
    }
}
