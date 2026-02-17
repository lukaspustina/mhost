use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use crate::app::modules::discover::{ct_logs, discover, permutation, srv_probing, txt_mining, wordlist::Wordlist};
use crate::resolver::lookup::Lookups;
use crate::resolver::{MultiQuery, ResolverGroup};
use crate::{Name, RecordType};
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::app::{Action, DiscoveryStrategy};

/// Parse domain and return the Name, or send an error action and return None.
async fn parse_domain(
    domain: &str,
    strategy: DiscoveryStrategy,
    tx: &mpsc::Sender<Action>,
    generation: u64,
) -> Option<Name> {
    match Name::from_str(domain) {
        Ok(n) => Some(n),
        Err(e) => {
            let _ = tx
                .send(Action::DiscoveryError {
                    generation,
                    strategy,
                    message: format!("{e:#}"),
                })
                .await;
            None
        }
    }
}

/// Run a batch of discovery queries via FuturesUnordered, sending progressive
/// DiscoveryBatch actions as results arrive and a final DiscoveryComplete.
///
/// Shared by CT logs, wordlist, and permutation discovery strategies.
async fn run_discovery_queries(
    queries: Vec<MultiQuery>,
    resolvers: &ResolverGroup,
    wildcard_lookups: &Option<Lookups>,
    strategy: DiscoveryStrategy,
    tx: &mpsc::Sender<Action>,
    generation: u64,
    start: Instant,
) {
    let total = queries.len();

    let mut futs: FuturesUnordered<_> = queries
        .into_iter()
        .map(|q| async move { resolvers.lookup(q).await })
        .collect();

    let mut found = 0usize;
    let mut completed = 0usize;
    while let Some(result) = futs.next().await {
        completed += 1;
        let lookups = match result {
            Ok(l) => l,
            Err(_) => continue,
        };

        let lookups = discover::filter_wildcard_responses(wildcard_lookups, lookups);

        let batch_found = lookups.iter().filter(|l| l.result().is_response()).count();
        found += batch_found;

        let _ = tx
            .send(Action::DiscoveryBatch {
                generation,
                strategy,
                lookups,
                completed,
                total,
            })
            .await;
    }

    let _ = tx
        .send(Action::DiscoveryComplete {
            generation,
            strategy,
            found,
            elapsed: start.elapsed(),
        })
        .await;
}

/// Build one MultiQuery per name for a given set of record types.
fn build_per_name_queries(names: Vec<Name>, record_types: Vec<RecordType>) -> Vec<MultiQuery> {
    names
        .into_iter()
        .filter_map(|name| MultiQuery::multi_record(name, record_types.clone()).ok())
        .collect()
}

/// Spawn CT Logs discovery as a tokio task on the shared runtime.
pub fn spawn_ct_logs(
    domain: String,
    resolvers: Arc<ResolverGroup>,
    tx: mpsc::Sender<Action>,
    generation: u64,
) -> JoinHandle<()> {
    tokio::task::spawn_local(async move {
        let start = Instant::now();
        let domain_trimmed = domain.trim_end_matches('.').to_string();

        // Query crt.sh for CT log entries
        let ct_names = match ct_logs::query_ct_logs(&domain_trimmed).await {
            Ok(names) => names,
            Err(e) => {
                let _ = tx
                    .send(Action::DiscoveryError {
                        generation,
                        strategy: DiscoveryStrategy::CtLogs,
                        message: format!("{e:#}"),
                    })
                    .await;
                return;
            }
        };

        if ct_names.is_empty() {
            let _ = tx
                .send(Action::DiscoveryComplete {
                    generation,
                    strategy: DiscoveryStrategy::CtLogs,
                    found: 0,
                    elapsed: start.elapsed(),
                })
                .await;
            return;
        }

        let names: Vec<Name> = ct_names.iter().filter_map(|n| Name::from_str(n).ok()).collect();
        let queries = build_per_name_queries(names, vec![RecordType::A, RecordType::AAAA]);

        run_discovery_queries(
            queries,
            &resolvers,
            &None,
            DiscoveryStrategy::CtLogs,
            &tx,
            generation,
            start,
        )
        .await;
    })
}

/// Spawn wildcard detection as a tokio task on the shared runtime.
pub fn spawn_wildcard_check(
    domain: String,
    resolvers: Arc<ResolverGroup>,
    tx: mpsc::Sender<Action>,
    generation: u64,
) -> JoinHandle<()> {
    tokio::task::spawn_local(async move {
        let domain_name = match Name::from_str(&domain) {
            Ok(n) => n,
            Err(_) => {
                let _ = tx
                    .send(Action::WildcardComplete {
                        generation,
                        wildcard_lookups: None,
                    })
                    .await;
                return;
            }
        };

        // Generate 5 random subdomain names
        let rnd_names = discover::WildcardCheck::rnd_names(5, 12);
        let rnd_fqdns: Vec<Name> = rnd_names
            .into_iter()
            .filter_map(|x| Name::from_str(&x).ok())
            .filter_map(|x| x.append_domain(&domain_name).ok())
            .collect();

        let query = match MultiQuery::new(rnd_fqdns, vec![RecordType::A, RecordType::AAAA]) {
            Ok(q) => q,
            Err(_) => {
                let _ = tx
                    .send(Action::WildcardComplete {
                        generation,
                        wildcard_lookups: None,
                    })
                    .await;
                return;
            }
        };

        let wildcard_lookups = match resolvers.lookup(query).await {
            Ok(lookups) if lookups.has_records() => Some(lookups),
            _ => None,
        };

        let _ = tx
            .send(Action::WildcardComplete {
                generation,
                wildcard_lookups,
            })
            .await;
    })
}

/// Spawn Wordlist discovery as a tokio task on the shared runtime.
pub fn spawn_wordlist(
    domain: String,
    resolvers: Arc<ResolverGroup>,
    wildcard_lookups: Option<Lookups>,
    tx: mpsc::Sender<Action>,
    generation: u64,
) -> JoinHandle<()> {
    tokio::task::spawn_local(async move {
        let start = Instant::now();

        let domain_name = match parse_domain(&domain, DiscoveryStrategy::Wordlist, &tx, generation).await {
            Some(n) => n,
            None => return,
        };

        // Load default wordlist
        let wordlist: Vec<Name> = match Wordlist::built_in() {
            Ok(wl) => wl
                .into_iter()
                .filter_map(|w| w.append_domain(&domain_name).ok())
                .collect(),
            Err(e) => {
                let _ = tx
                    .send(Action::DiscoveryError {
                        generation,
                        strategy: DiscoveryStrategy::Wordlist,
                        message: format!("{e:#}"),
                    })
                    .await;
                return;
            }
        };

        let record_types = vec![RecordType::A, RecordType::AAAA, RecordType::ANAME, RecordType::CNAME];

        let queries = build_per_name_queries(wordlist, record_types);

        run_discovery_queries(
            queries,
            &resolvers,
            &wildcard_lookups,
            DiscoveryStrategy::Wordlist,
            &tx,
            generation,
            start,
        )
        .await;
    })
}

/// Spawn SRV Probing discovery as a tokio task on the shared runtime.
pub fn spawn_srv_probing(
    domain: String,
    resolvers: Arc<ResolverGroup>,
    tx: mpsc::Sender<Action>,
    generation: u64,
) -> JoinHandle<()> {
    tokio::task::spawn_local(async move {
        let start = Instant::now();

        let domain_name = match parse_domain(&domain, DiscoveryStrategy::SrvProbing, &tx, generation).await {
            Some(n) => n,
            None => return,
        };

        let probes = srv_probing::well_known_srv_probes();
        let srv_names: Vec<Name> = probes
            .iter()
            .filter_map(|probe| {
                let sub = probe.to_subdomain();
                Name::from_str(&sub)
                    .ok()
                    .and_then(|n| n.append_domain(&domain_name).ok())
            })
            .collect();

        let queries = build_per_name_queries(srv_names, vec![RecordType::SRV]);

        run_discovery_queries(
            queries,
            &resolvers,
            &None,
            DiscoveryStrategy::SrvProbing,
            &tx,
            generation,
            start,
        )
        .await;
    })
}

/// Spawn TXT Mining discovery as a tokio task on the shared runtime.
pub fn spawn_txt_mining(
    domain: String,
    resolvers: Arc<ResolverGroup>,
    existing_lookups: Lookups,
    tx: mpsc::Sender<Action>,
    generation: u64,
) -> JoinHandle<()> {
    tokio::task::spawn_local(async move {
        let start = Instant::now();

        let domain_name = match parse_domain(&domain, DiscoveryStrategy::TxtMining, &tx, generation).await {
            Some(n) => n,
            None => return,
        };

        // Extract domains from SPF and DMARC TXT records
        let txt_records = existing_lookups.txt();
        let spf_domains = txt_mining::extract_spf_domains(&txt_records);
        let dmarc_domains = txt_mining::extract_dmarc_domains(&txt_records);
        let mined_domains: HashSet<String> = spf_domains.union(&dmarc_domains).cloned().collect();

        // Query well-known TXT subdomains
        let well_known = txt_mining::well_known_txt_subdomains();
        let subdomain_names: Vec<Name> = well_known
            .iter()
            .filter_map(|sub| {
                Name::from_str(sub)
                    .ok()
                    .and_then(|n| n.append_domain(&domain_name).ok())
            })
            .collect();

        let mut found = 0usize;
        let total = subdomain_names.len() + mined_domains.len();

        // Resolve well-known TXT subdomains
        if !subdomain_names.is_empty() {
            if let Ok(query) = MultiQuery::new(subdomain_names, vec![RecordType::TXT]) {
                if let Ok(lookups) = resolvers.lookup(query).await {
                    let batch_found = lookups.iter().filter(|l| l.result().is_response()).count();
                    found += batch_found;
                    let _ = tx
                        .send(Action::DiscoveryBatch {
                            generation,
                            strategy: DiscoveryStrategy::TxtMining,
                            lookups,
                            completed: well_known.len(),
                            total,
                        })
                        .await;
                }
            }
        }

        // Resolve mined domains
        if !mined_domains.is_empty() {
            let names: Vec<Name> = mined_domains.iter().filter_map(|n| Name::from_str(n).ok()).collect();
            if !names.is_empty() {
                if let Ok(query) = MultiQuery::new(names, vec![RecordType::A, RecordType::AAAA]) {
                    if let Ok(lookups) = resolvers.lookup(query).await {
                        let batch_found = lookups.iter().filter(|l| l.result().is_response()).count();
                        found += batch_found;
                        let _ = tx
                            .send(Action::DiscoveryBatch {
                                generation,
                                strategy: DiscoveryStrategy::TxtMining,
                                lookups,
                                completed: total,
                                total,
                            })
                            .await;
                    }
                }
            }
        }

        let _ = tx
            .send(Action::DiscoveryComplete {
                generation,
                strategy: DiscoveryStrategy::TxtMining,
                found,
                elapsed: start.elapsed(),
            })
            .await;
    })
}

/// Spawn Permutation discovery as a tokio task on the shared runtime.
pub fn spawn_permutation(
    domain: String,
    resolvers: Arc<ResolverGroup>,
    existing_lookups: Lookups,
    wildcard_lookups: Option<Lookups>,
    tx: mpsc::Sender<Action>,
    generation: u64,
) -> JoinHandle<()> {
    tokio::task::spawn_local(async move {
        let start = Instant::now();

        let domain_name = match parse_domain(&domain, DiscoveryStrategy::Permutation, &tx, generation).await {
            Some(n) => n,
            None => return,
        };

        // Extract first-level labels from existing lookups
        let discovered_labels: HashSet<String> = existing_lookups
            .iter()
            .filter(|l| l.result().is_response())
            .map(|l| l.query().name().clone())
            .filter(|name| domain_name.zone_of(name))
            .filter_map(|name| {
                let domain_labels = domain_name.num_labels();
                let name_labels = name.num_labels();
                if name_labels > domain_labels {
                    name.iter()
                        .next()
                        .map(|label| String::from_utf8_lossy(label).to_lowercase())
                } else {
                    None
                }
            })
            .collect();

        if discovered_labels.is_empty() {
            let _ = tx
                .send(Action::DiscoveryComplete {
                    generation,
                    strategy: DiscoveryStrategy::Permutation,
                    found: 0,
                    elapsed: start.elapsed(),
                })
                .await;
            return;
        }

        let permutations = permutation::generate_permutations(&discovered_labels);
        if permutations.is_empty() {
            let _ = tx
                .send(Action::DiscoveryComplete {
                    generation,
                    strategy: DiscoveryStrategy::Permutation,
                    found: 0,
                    elapsed: start.elapsed(),
                })
                .await;
            return;
        }

        let perm_names: Vec<Name> = permutations
            .iter()
            .filter_map(|label| {
                Name::from_str(label)
                    .ok()
                    .and_then(|n| n.append_domain(&domain_name).ok())
            })
            .collect();

        let queries = build_per_name_queries(perm_names, vec![RecordType::A, RecordType::AAAA]);

        run_discovery_queries(
            queries,
            &resolvers,
            &wildcard_lookups,
            DiscoveryStrategy::Permutation,
            &tx,
            generation,
            start,
        )
        .await;
    })
}
