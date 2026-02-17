use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::app::common::subdomain_spec::default_entries;
use crate::resolver::lookup::Lookups;
use crate::resolver::{MultiQuery, ResolverGroup};
use crate::services::whois::{self, QueryType, WhoisClient, WhoisClientOpts};
use crate::{Name, RecordType};
use futures::stream::{FuturesUnordered, StreamExt};
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::app::Action;

/// Spawns a domain-lookup query as a tokio task on the shared runtime.
///
/// Sends partial results after each completed query so the TUI can display records progressively.
/// The `generation` tag is attached to every action sent back so the main loop can discard
/// stale results when the user starts a new query.
pub fn spawn_domain_query(
    domain: String,
    resolvers: Arc<ResolverGroup>,
    tx: mpsc::Sender<Action>,
    generation: u64,
) -> JoinHandle<()> {
    tokio::task::spawn_local(async move {
        let start = Instant::now();
        if let Err(msg) = run_domain_query(&domain, &resolvers, &tx, generation).await {
            let _ = tx
                .send(Action::DnsError {
                    generation,
                    message: msg,
                })
                .await;
            return;
        }
        let _ = tx
            .send(Action::DnsComplete {
                generation,
                elapsed: start.elapsed(),
            })
            .await;
    })
}

async fn run_domain_query(
    domain: &str,
    resolvers: &ResolverGroup,
    tx: &mpsc::Sender<Action>,
    generation: u64,
) -> Result<(), String> {
    let domain_name = Name::from_str(domain).map_err(|e| format!("{e:#}"))?;
    let entries = default_entries();

    // Separate apex from subdomain entries
    let (apex_entries, subdomain_entries): (Vec<_>, Vec<_>) = entries.into_iter().partition(|e| e.subdomain.is_empty());

    // Build individual queries — one per apex record type, one per subdomain entry
    let mut queries: Vec<MultiQuery> = Vec::new();

    // Apex: one query per record type for maximum concurrency
    let mut apex_types: Vec<RecordType> = apex_entries.iter().map(|e| e.record_type).collect();
    for rt in [RecordType::DNSKEY, RecordType::DS, RecordType::HINFO] {
        if !apex_types.contains(&rt) {
            apex_types.push(rt);
        }
    }
    for rt in apex_types {
        if let Ok(q) = MultiQuery::multi_record(domain_name.clone(), vec![rt]) {
            queries.push(q);
        }
    }

    // Subdomains: one query per entry
    for entry in &subdomain_entries {
        if let Ok(sub) = Name::from_str(entry.subdomain) {
            if let Ok(full_name) = sub.append_domain(&domain_name) {
                if let Ok(q) = MultiQuery::multi_record(full_name, vec![entry.record_type]) {
                    queries.push(q);
                }
            }
        }
    }

    let total = queries.len();

    // Launch ALL queries concurrently
    let mut futs: FuturesUnordered<_> = queries
        .into_iter()
        .map(|q| {
            let r = &resolvers;
            async move { r.lookup(q).await }
        })
        .collect();

    let mut completed = 0;
    while let Some(result) = futs.next().await {
        completed += 1;
        let lookups = result.unwrap_or_else(|_| Lookups::empty());
        let _ = tx
            .send(Action::DnsBatch {
                generation,
                lookups,
                completed,
                total,
            })
            .await;
    }

    Ok(())
}

/// Extract unique IP addresses from A and AAAA records in the lookups.
pub fn ips_from_lookups(lookups: &Lookups) -> Vec<IpNetwork> {
    let mut seen = HashSet::new();
    let mut ips = Vec::new();

    for lookup in lookups.iter() {
        for record in lookup.records() {
            if let Some(ipv4) = record.data().a() {
                let ip = IpNetwork::from(IpAddr::V4(*ipv4));
                if seen.insert(ip) {
                    ips.push(ip);
                }
            }
            if let Some(ipv6) = record.data().aaaa() {
                let ip = IpNetwork::from(IpAddr::V6(*ipv6));
                if seen.insert(ip) {
                    ips.push(ip);
                }
            }
        }
    }

    ips
}

/// Spawns a WHOIS query as a tokio task on the shared runtime.
///
/// Queries GeoLocation, NetworkInfo, and Whois data for each unique IP found in the lookups.
/// The `generation` tag is attached so the main loop can discard stale results.
pub fn spawn_whois_query(ips: Vec<IpNetwork>, tx: mpsc::Sender<Action>, generation: u64) {
    tokio::task::spawn_local(async move {
        let query_types = vec![QueryType::NetworkInfo, QueryType::GeoLocation, QueryType::Whois];
        let query = whois::MultiQuery::new(ips, query_types);
        let opts = WhoisClientOpts::new(8, Duration::from_secs(5), false);
        let client = WhoisClient::new(opts);

        match client.query(query).await {
            Ok(responses) => {
                let _ = tx
                    .send(Action::WhoisResult {
                        generation,
                        data: responses,
                    })
                    .await;
            }
            Err(e) => {
                let _ = tx
                    .send(Action::WhoisError {
                        generation,
                        message: format!("{e:#}"),
                    })
                    .await;
            }
        }
    });
}
