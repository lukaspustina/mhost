use crate::error::Error;
use crate::resolver::Resolver;
use crate::{MultiQuery, Query};
use futures::stream::{self, StreamExt};
use log::{debug, trace};
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::proto::xfer::DnsRequestOptions;
use crate::nameserver::NameServerConfig;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug)]
pub struct LookupResult {
    query: Query,
    name_server: Arc<NameServerConfig>,
    result: Lookup,
}

impl LookupResult {
    pub(crate) async fn lookup(resolver: Resolver, query: Query) -> LookupResult {
        do_lookup(&resolver, query).await
    }

    pub(crate) async fn multi_lookups(resolver: Resolver, multi_query: MultiQuery) -> Vec<LookupResult> {
        let MultiQuery { name, record_types } = multi_query;
        let lookups: Vec<_> = record_types
            .into_iter()
            .map(|record_type| Query { name: name.clone(), record_type: record_type.clone() })
            .map(|q| do_lookup(&resolver, q))
            .collect();

        stream::iter(lookups)
            .buffer_unordered(resolver.opts.max_concurrent)
            .inspect(|lookup| trace!("Received lookup {:?}", lookup))
            .collect::<Vec<LookupResult>>()
            .await
    }

    pub fn query(&self) -> &Query {
        &self.query
    }

    pub fn name_server(&self) -> &NameServerConfig {
        &self.name_server
    }

    pub fn result(&self) -> &Lookup {
        &self.result
    }
}

#[derive(Debug)]
pub enum Lookup {
    Lookup(trust_dns_resolver::lookup::Lookup),
    NxDomain { valid_until: Option<Instant> },
    Timeout,
    Error(Error),
}

impl From<std::result::Result<trust_dns_resolver::lookup::Lookup, ResolveError>> for Lookup {
    fn from(res: std::result::Result<trust_dns_resolver::lookup::Lookup, ResolveError>) -> Self {
        match res {
            // TODO: Transform trustdns::lookup into mhost::Records
            Ok(lookup) => Lookup::Lookup(lookup),
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { valid_until, .. } => Lookup::NxDomain { valid_until: *valid_until },
                ResolveErrorKind::Timeout => Lookup::Timeout,
                _ => Lookup::Error(Error::from(err)),
            },
        }
    }
}

async fn do_lookup(resolver: &Resolver, query: Query) -> LookupResult {
    let q = query.clone();
    let result = resolver
        .inner
        .lookup(q.name, q.record_type, DnsRequestOptions::default())
        .await
        .into();
    debug!(
        "Received Lookup for '{}', record type {} from {:?}.",
        &query.name, &query.record_type, resolver.name()
    );

    LookupResult {
        query,
        name_server: resolver.name_server.clone(),
        result,
    }
}
