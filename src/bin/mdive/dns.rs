use std::time::Duration;

use mhost::nameserver::predefined::PredefinedProvider;
use mhost::resolver::lookup::Lookups;
use mhost::resolver::{MultiQuery, ResolverGroupBuilder};
use mhost::RecordType;
use tokio::sync::mpsc;

use crate::app::Action;

/// Spawns a DNS query on a background OS thread with its own tokio runtime.
///
/// This is necessary because `ResolverGroup::lookup` produces a `!Send` future
/// (due to `ThreadRng` in the uni-lookup path), so it cannot be used with `tokio::spawn`.
pub fn spawn_query(domain: String, types: Vec<RecordType>, tx: mpsc::Sender<Action>) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build DNS runtime");

        rt.block_on(async {
            let result = run_query(&domain, types).await;
            let _ = tx.send(Action::DnsResult(result)).await;
        });
    });
}

async fn run_query(domain: &str, types: Vec<RecordType>) -> Result<Lookups, String> {
    let resolvers = ResolverGroupBuilder::new()
        .system()
        .predefined(PredefinedProvider::Google)
        .predefined(PredefinedProvider::Cloudflare)
        .timeout(Duration::from_secs(3))
        .build()
        .await
        .map_err(|e| format!("{e:#}"))?;

    let query = MultiQuery::multi_record(domain, types).map_err(|e| format!("{e:#}"))?;

    resolvers.lookup(query).await.map_err(|e| format!("{e:#}"))
}
