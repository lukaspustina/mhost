use std::str::FromStr;
use std::time::{Duration, Instant};

use futures::stream::{FuturesUnordered, StreamExt};
use mhost::app::modules::domain_lookup::subdomain_spec::default_entries;
use mhost::nameserver::predefined::PredefinedProvider;
use mhost::resolver::lookup::Lookups;
use mhost::resolver::{MultiQuery, ResolverGroupBuilder};
use mhost::{Name, RecordType};
use tokio::sync::mpsc;

use crate::app::Action;

/// Spawns a domain-lookup query on a background OS thread with its own tokio runtime.
///
/// Sends partial results after each completed query so the TUI can display records progressively.
pub fn spawn_domain_query(domain: String, tx: mpsc::Sender<Action>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build DNS runtime");

        rt.block_on(async {
            let start = Instant::now();
            if let Err(msg) = run_domain_query(&domain, &tx).await {
                let _ = tx.send(Action::DnsError(msg)).await;
                return;
            }
            let _ = tx.send(Action::DnsComplete(start.elapsed())).await;
        });
    });
}

async fn run_domain_query(domain: &str, tx: &mpsc::Sender<Action>) -> Result<(), String> {
    let resolvers = ResolverGroupBuilder::new()
        .system()
        .predefined(PredefinedProvider::Google)
        .predefined(PredefinedProvider::Cloudflare)
        .timeout(Duration::from_secs(3))
        .build()
        .await
        .map_err(|e| format!("{e:#}"))?;

    let domain_name = Name::from_str(domain).map_err(|e| format!("{e:#}"))?;
    let entries = default_entries();

    // Separate apex from subdomain entries
    let (apex_entries, subdomain_entries): (Vec<_>, Vec<_>) =
        entries.into_iter().partition(|e| e.subdomain.is_empty());

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
                lookups,
                completed,
                total,
            })
            .await;
    }

    Ok(())
}
