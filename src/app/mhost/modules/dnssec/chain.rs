// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! DNSSEC trust chain data model and delegation walking algorithm.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_resolver::proto::rr::{RData, RecordType as HickoryRecordType};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::app::resolver;
use crate::app::AppConfig;
use crate::resolver::delegation;
use crate::resolver::raw::{self, RawQueryResult};
use crate::resources::dnssec_validation::{self, Finding, Severity};
use crate::resources::rdata::{DNSKEY, DS, RRSIG};
use crate::resources::Record;

/// A single level in the DNSSEC trust chain (one zone).
#[derive(Debug, Serialize)]
pub struct DelegationLevel {
    pub zone_name: String,
    pub dnskeys: Vec<DNSKEY>,
    /// DS records from the parent zone pointing to this zone's DNSKEY.
    pub ds_records: Vec<DS>,
    /// RRSIG records covering the DNSKEY RRset at this zone.
    pub rrsigs: Vec<RRSIG>,
    pub findings: Vec<Finding>,
    pub status: Severity,
}

/// The complete DNSSEC trust chain from root to the target zone.
#[derive(Debug, Serialize)]
pub struct TrustChain {
    pub domain_name: String,
    pub levels: Vec<DelegationLevel>,
    #[serde(serialize_with = "serialize_duration_ms")]
    pub total_time: Duration,
    pub status: Severity,
}

fn serialize_duration_ms<S>(d: &Duration, s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_f64(d.as_secs_f64() * 1000.0)
}

/// Split a domain name into its zone labels from root to the full domain.
///
/// Example: `"example.com"` -> `[".", "com.", "example.com."]`
pub fn split_domain_labels(domain: &str) -> Vec<String> {
    let domain = domain.trim_end_matches('.');
    let labels: Vec<&str> = domain.split('.').collect();
    let mut zones = vec![".".to_string()];
    for i in (0..labels.len()).rev() {
        let zone = labels[i..].join(".") + ".";
        zones.push(zone);
    }
    zones
}

/// Extract NS server names and glue IPs from NS query results.
///
/// Handles both referral-style responses (AA=0, NS in authority) and authoritative
/// responses (AA=1, NS in answers) — the latter occurs when querying a parent zone's
/// authoritative server for NS records at a delegation point.
fn extract_ns_servers(results: &[RawQueryResult]) -> HashMap<String, Vec<IpAddr>> {
    let mut ns_servers: HashMap<String, Vec<IpAddr>> = HashMap::new();

    for rqr in results {
        let response = match &rqr.result {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Collect NS names from answers (authoritative) or authority (referral)
        let mut ns_names: Vec<String> = Vec::new();
        for record in response.answers().iter().chain(response.authority().iter()) {
            if record.record_type() == HickoryRecordType::NS {
                if let RData::NS(ns) = record.data() {
                    let name = ns.0.to_ascii();
                    if !ns_names.contains(&name) {
                        ns_names.push(name);
                    }
                }
            }
        }

        // Collect glue IPs from the additional section
        for ns_name in &ns_names {
            let entry = ns_servers.entry(ns_name.clone()).or_default();
            for record in response.additional() {
                let record_name = record.name().to_ascii();
                if record_name == *ns_name {
                    let ip = match record.data() {
                        RData::A(a) => Some(IpAddr::V4(a.0)),
                        RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                        _ => None,
                    };
                    if let Some(ip) = ip {
                        if !entry.contains(&ip) {
                            entry.push(ip);
                        }
                    }
                }
            }
        }
    }

    ns_servers
}

/// Walk the DNSSEC trust chain from root servers to the target domain.
///
/// At each delegation level, queries DNSKEY records (with DNSSEC OK bit set to get
/// RRSIGs), DS records for the child zone, and NS records for referral to the next level.
///
/// If `on_level` is provided, it is called after each level is fully built. The callback
/// receives the completed levels so far, enabling partial/streaming output. The renderer
/// can use the last two levels to display DS→DNSKEY linkage correctly.
pub async fn walk_trust_chain<F>(
    domain_name: &str,
    app_config: &AppConfig,
    max_hops: usize,
    mut on_level: Option<F>,
) -> TrustChain
where
    F: FnMut(&[DelegationLevel]),
{
    let zones = split_domain_labels(domain_name);
    let total_start = Instant::now();
    let mut levels = Vec::new();

    let mut current_servers = delegation::root_server_addrs(app_config.ipv4_only, app_config.ipv6_only);

    let timeout = app_config.timeout;
    let max_concurrent = app_config.max_concurrent_servers;

    let mut ds_from_parent: Vec<DS> = Vec::new();

    let walk_len = zones.len().min(max_hops);

    for (i, zone) in zones.iter().enumerate().take(walk_len) {
        if current_servers.is_empty() {
            warn!("No servers to query at level {} (zone {})", i, zone);
            break;
        }

        let child_zone = zones.get(i + 1);
        let server_addrs: Vec<SocketAddr> = current_servers.iter().map(|(a, _)| *a).collect();

        info!(
            "DNSSEC level {}: querying {} servers for zone {}",
            i,
            server_addrs.len(),
            zone
        );

        let hickory_zone = match hickory_resolver::proto::rr::Name::from_ascii(zone) {
            Ok(n) => n,
            Err(e) => {
                warn!("Failed to parse zone name {}: {}", zone, e);
                break;
            }
        };

        // Query DNSKEY for this zone (with DO bit to get RRSIGs)
        let dnskey_results = raw::parallel_raw_dnssec_queries(
            &server_addrs,
            &hickory_zone,
            hickory_resolver::proto::rr::RecordType::DNSKEY,
            timeout,
            max_concurrent,
        )
        .await;

        // Extract DNSKEY and RRSIG records from answers
        let mut dnskeys = Vec::new();
        let mut rrsigs = Vec::new();
        for rqr in &dnskey_results {
            if let Ok(response) = &rqr.result {
                for record in response.answers() {
                    let mhost_record = Record::from(record);
                    if let Some(key) = mhost_record.data().dnskey() {
                        if !dnskeys.contains(key) {
                            dnskeys.push(key.clone());
                        }
                    }
                    if let Some(sig) = mhost_record.data().rrsig() {
                        if !rrsigs.contains(sig) {
                            rrsigs.push(sig.clone());
                        }
                    }
                }
            }
        }

        debug!(
            "Zone {}: found {} DNSKEY(s), {} RRSIG(s), {} DS from parent",
            zone,
            dnskeys.len(),
            rrsigs.len(),
            ds_from_parent.len()
        );

        // Run validation
        let dnskey_refs: Vec<&DNSKEY> = dnskeys.iter().collect();
        let ds_refs: Vec<&DS> = ds_from_parent.iter().collect();
        let rrsig_refs: Vec<&RRSIG> = rrsigs.iter().collect();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        let mut findings = Vec::new();
        if !dnskeys.is_empty() {
            findings.extend(dnssec_validation::validate_ksk_present(&dnskey_refs));
        }
        if !ds_from_parent.is_empty() {
            findings.extend(dnssec_validation::validate_ds_dnskey_binding(&ds_refs, &dnskey_refs));
        }
        findings.extend(dnssec_validation::validate_rrsig_dnskey_binding(
            &rrsig_refs,
            &dnskey_refs,
        ));
        findings.extend(dnssec_validation::validate_rrsig_expiration(&rrsig_refs, now));

        let mut algos = HashSet::new();
        for key in &dnskeys {
            algos.insert(key.algorithm());
        }
        for sig in &rrsigs {
            algos.insert(sig.algorithm());
        }
        if !algos.is_empty() {
            findings.extend(dnssec_validation::validate_algorithm_strength(&algos));
        }

        // Handle unsigned zone
        if dnskeys.is_empty() && rrsigs.is_empty() && i > 0 {
            findings.push(Finding::warning(format!(
                "Zone {} has no DNSKEY records: not DNSSEC-signed",
                zone
            )));
        }

        let status = findings
            .iter()
            .fold(Severity::Ok, |acc, f| Severity::worst(&acc, &f.severity));

        let level = DelegationLevel {
            zone_name: zone.clone(),
            dnskeys,
            ds_records: ds_from_parent,
            rrsigs,
            findings,
            status,
        };
        levels.push(level);

        if let Some(ref mut cb) = on_level {
            cb(&levels);
        }

        // If there's a child zone, query DS and NS for it
        if let Some(child) = child_zone {
            let hickory_child = match hickory_resolver::proto::rr::Name::from_ascii(child) {
                Ok(n) => n,
                Err(e) => {
                    warn!("Failed to parse child zone name {}: {}", child, e);
                    break;
                }
            };

            // Query DS for child zone (authoritative at current zone)
            let ds_results = raw::parallel_raw_dnssec_queries(
                &server_addrs,
                &hickory_child,
                hickory_resolver::proto::rr::RecordType::DS,
                timeout,
                max_concurrent,
            )
            .await;

            // Query NS for child zone (to get referral for next level)
            let ns_results = raw::parallel_raw_queries(
                &server_addrs,
                &hickory_child,
                hickory_resolver::proto::rr::RecordType::NS,
                timeout,
                max_concurrent,
            )
            .await;

            // Extract DS records
            ds_from_parent = Vec::new();
            for rqr in &ds_results {
                if let Ok(response) = &rqr.result {
                    for record in response.answers() {
                        let mhost_record = Record::from(record);
                        if let Some(ds) = mhost_record.data().ds() {
                            if !ds_from_parent.contains(ds) {
                                ds_from_parent.push(ds.clone());
                            }
                        }
                    }
                }
            }

            // Extract NS servers from query results.
            // NS queries at delegation points may return authoritative answers
            // (AA=1, NS in answers) rather than referrals (AA=0, NS in authority),
            // so we check both sections.
            let mut ns_servers = extract_ns_servers(&ns_results);
            if !ns_servers.is_empty() {
                resolver::resolve_missing_glue(app_config, &mut ns_servers).await;
                current_servers = delegation::build_server_list(
                    &delegation::Referral {
                        zone_name: child.clone(),
                        ns_servers,
                    },
                    |ip| app_config.ip_allowed(ip),
                );
            } else {
                debug!("No NS servers found for child zone {}", child);
                current_servers = Vec::new();
            }
        } else {
            ds_from_parent = Vec::new();
        }
    }

    let total_time = total_start.elapsed();
    let status = levels
        .iter()
        .fold(Severity::Ok, |acc, l| Severity::worst(&acc, &l.status));

    TrustChain {
        domain_name: domain_name.to_string(),
        levels,
        total_time,
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_domain_labels_example_com() {
        let labels = split_domain_labels("example.com");
        assert_eq!(labels, vec![".", "com.", "example.com."]);
    }

    #[test]
    fn split_domain_labels_with_trailing_dot() {
        let labels = split_domain_labels("example.com.");
        assert_eq!(labels, vec![".", "com.", "example.com."]);
    }

    #[test]
    fn split_domain_labels_subdomain() {
        let labels = split_domain_labels("www.example.com");
        assert_eq!(labels, vec![".", "com.", "example.com.", "www.example.com."]);
    }

    #[test]
    fn split_domain_labels_tld() {
        let labels = split_domain_labels("com");
        assert_eq!(labels, vec![".", "com."]);
    }

    #[test]
    fn delegation_level_construction() {
        let level = DelegationLevel {
            zone_name: ".".to_string(),
            dnskeys: Vec::new(),
            ds_records: Vec::new(),
            rrsigs: Vec::new(),
            findings: vec![Finding::ok("test")],
            status: Severity::Ok,
        };
        assert_eq!(level.status, Severity::Ok);
        assert_eq!(level.findings.len(), 1);
    }

    #[test]
    fn trust_chain_serialization() {
        let chain = TrustChain {
            domain_name: "example.com".to_string(),
            levels: vec![DelegationLevel {
                zone_name: ".".to_string(),
                dnskeys: Vec::new(),
                ds_records: Vec::new(),
                rrsigs: Vec::new(),
                findings: Vec::new(),
                status: Severity::Ok,
            }],
            total_time: Duration::from_millis(145),
            status: Severity::Ok,
        };

        let json = serde_json::to_string(&chain);
        assert!(json.is_ok());
        let json = json.unwrap();
        assert!(json.contains("\"domain_name\":\"example.com\""));
        assert!(json.contains("\"levels\""));
    }

    #[test]
    fn trust_chain_worst_status() {
        let chain = TrustChain {
            domain_name: "example.com".to_string(),
            levels: vec![
                DelegationLevel {
                    zone_name: ".".to_string(),
                    dnskeys: Vec::new(),
                    ds_records: Vec::new(),
                    rrsigs: Vec::new(),
                    findings: Vec::new(),
                    status: Severity::Ok,
                },
                DelegationLevel {
                    zone_name: "com.".to_string(),
                    dnskeys: Vec::new(),
                    ds_records: Vec::new(),
                    rrsigs: Vec::new(),
                    findings: vec![Finding::warning("weak algo")],
                    status: Severity::Warning,
                },
            ],
            total_time: Duration::from_millis(100),
            status: Severity::Warning, // worst across levels
        };

        assert_eq!(chain.status, Severity::Warning);
    }
}
