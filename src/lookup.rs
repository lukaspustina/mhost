use crate::error::Error;
use crate::nameserver::NameServerConfig;
use crate::resolver::Resolver;
use crate::resources::Record;
use crate::serialize::ser_arc_nameserver_config;
use crate::{MultiQuery, Query};
use chrono::{DateTime, Duration, Utc};
use futures::stream::{self, StreamExt};
use log::{debug, trace};
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::proto::xfer::DnsRequestOptions;

#[derive(Debug, Clone, Serialize)]
pub struct LookupResult {
    query: Query,
    #[serde(serialize_with = "ser_arc_nameserver_config")]
    name_server: Arc<NameServerConfig>,
    result: Lookup,
}

impl LookupResult {
    pub async fn lookup(resolver: Resolver, query: Query) -> LookupResult {
        do_lookup(&resolver, query).await
    }

    pub async fn multi_lookups(resolver: Resolver, multi_query: MultiQuery) -> Vec<LookupResult> {
        let MultiQuery { name, record_types } = multi_query;
        let lookups: Vec<_> = record_types
            .into_iter()
            .map(|record_type| Query {
                name: name.clone(),
                record_type,
            })
            .map(|q| do_lookup(&resolver, q))
            .collect();

        stream::iter(lookups)
            .buffer_unordered(resolver.opts.max_concurrent_requests)
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

#[derive(Debug, Clone, Serialize)]
pub enum Lookup {
    Lookup {
        records: Vec<Record>,
        valid_until: DateTime<Utc>,
    },
    NxDomain {
        valid_until: Option<DateTime<Utc>>,
    },
    Timeout,
    Error(String),
}

impl Lookup {
    pub fn is_ok(&self) -> bool {
        match self {
            Lookup::Lookup { .. } => true,
            _ => false,
        }
    }
}

#[doc(hidden)]
impl From<std::result::Result<trust_dns_resolver::lookup::Lookup, ResolveError>> for Lookup {
    fn from(res: std::result::Result<trust_dns_resolver::lookup::Lookup, ResolveError>) -> Self {
        match res {
            Ok(lookup) => {
                let records: Vec<Record> = lookup.record_iter().map(Record::from).collect();
                Lookup::Lookup {
                    records,
                    valid_until: instant_to_utc(lookup.valid_until()),
                }
            }
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { valid_until, .. } => Lookup::NxDomain {
                    valid_until: valid_until.map(instant_to_utc),
                },
                ResolveErrorKind::Timeout => Lookup::Timeout,
                _ => Lookup::Error(Error::from(err).to_string()),
            },
        }
    }
}

async fn do_lookup(resolver: &Resolver, query: Query) -> LookupResult {
    let q = query.clone();
    let result = resolver
        .inner
        .lookup(q.name, q.record_type.into(), DnsRequestOptions::default())
        .await
        .into();
    debug!(
        "Received Lookup for '{}', record type {} from {:?}.",
        &query.name,
        &query.record_type,
        resolver.name()
    );

    LookupResult {
        query,
        name_server: resolver.name_server.clone(),
        result,
    }
}

fn instant_to_utc(instant: Instant) -> DateTime<Utc> {
    let now = Instant::now();
    let duration = instant.duration_since(now);

    Utc::now() + Duration::from_std(duration).unwrap() // Safe, because I know this is a valid duration
}
