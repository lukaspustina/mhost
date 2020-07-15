use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use futures::stream::{self, StreamExt};
use log::{debug, trace};
use serde::Serialize;
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::proto::xfer::DnsRequestOptions;

use crate::error::Error;
use crate::nameserver::NameServerConfig;
use crate::resolver::Resolver;
use crate::resources::Record;
use crate::serialize::ser_arc_nameserver_config;
use crate::{MultiQuery, Query};

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
    Lookup(Response),
    NxDomain(NxDomain),
    Timeout,
    Error(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct Response {
    records: Vec<Record>,
    response_time: Duration,
    valid_until: DateTime<Utc>,
}

impl Response {
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    pub fn response_time(&self) -> &Duration {
        &self.response_time
    }

    pub fn vaild_until(&self) -> &DateTime<Utc> {
        &self.valid_until
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NxDomain {
    response_time: Duration,
    valid_until: Option<DateTime<Utc>>,
}

impl Lookup {
    pub fn is_lookup(&self) -> bool {
        match self {
            Lookup::Lookup { .. } => true,
            _ => false,
        }
    }

    pub fn is_nxdomain(&self) -> bool {
        match self {
            Lookup::NxDomain { .. } => true,
            _ => false,
        }
    }

    pub fn is_timeout(&self) -> bool {
        match self {
            Lookup::Timeout { .. } => true,
            _ => false,
        }
    }

    pub fn is_err(&self) -> bool {
        match self {
            Lookup::Error { .. } => true,
            _ => false,
        }
    }

    pub fn lookup(&self) -> Option<&Response> {
        match self {
            Lookup::Lookup(ref response) => Some(response),
            _ => None,
        }
    }

    pub fn nxdomain(&self) -> Option<&NxDomain> {
        match self {
            Lookup::NxDomain(ref nxdomain) => Some(nxdomain),
            _ => None,
        }
    }

    pub fn err(&self) -> Option<&String> {
        match self {
            Lookup::Error(ref err) => Some(&err),
            _ => None,
        }
    }
}

async fn do_lookup(resolver: &Resolver, query: Query) -> LookupResult {
    let q = query.clone();
    let start_time = Instant::now();
    let result = resolver
        .inner
        .lookup(q.name, q.record_type.into(), DnsRequestOptions::default())
        .await
        .into_lookup(start_time);
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

#[doc(hidden)]
trait IntoLookup {
    fn into_lookup(self, start_time: Instant) -> Lookup;
}

#[doc(hidden)]
impl IntoLookup for std::result::Result<trust_dns_resolver::lookup::Lookup, ResolveError> {
    fn into_lookup(self, start_time: Instant) -> Lookup {
        match self {
            Ok(lookup) => {
                let records: Vec<Record> = lookup.record_iter().map(Record::from).collect();
                Lookup::Lookup(Response {
                    records,
                    response_time: Instant::now() - start_time,
                    valid_until: instant_to_utc(lookup.valid_until()),
                })
            }
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { valid_until, .. } => Lookup::NxDomain(NxDomain {
                    response_time: Instant::now() - start_time,
                    valid_until: valid_until.map(instant_to_utc),
                }),
                ResolveErrorKind::Timeout => Lookup::Timeout,
                _ => Lookup::Error(Error::from(err).to_string()),
            },
        }
    }
}

fn instant_to_utc(instant: Instant) -> DateTime<Utc> {
    let now = Instant::now();
    let duration = instant.duration_since(now);

    Utc::now() + chrono::Duration::from_std(duration).unwrap() // Safe, because I know this is a valid duration
}
