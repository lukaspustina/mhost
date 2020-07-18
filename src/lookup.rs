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
pub struct Lookup {
    query: Query,
    #[serde(serialize_with = "ser_arc_nameserver_config")]
    name_server: Arc<NameServerConfig>,
    result: LookupResult,
}

impl Lookup {
    pub async fn lookup(resolver: Resolver, query: Query) -> Lookup {
        do_lookup(&resolver, query).await
    }

    pub async fn multi_lookup(resolver: Resolver, multi_query: MultiQuery) -> Vec<Lookup> {
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
            .collect::<Vec<Lookup>>()
            .await
    }

    pub fn query(&self) -> &Query {
        &self.query
    }

    pub fn name_server(&self) -> &NameServerConfig {
        &self.name_server
    }

    pub fn result(&self) -> &LookupResult {
        &self.result
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum LookupResult {
    Response(Response),
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

    pub fn valid_until(&self) -> &DateTime<Utc> {
        &self.valid_until
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NxDomain {
    response_time: Duration,
    valid_until: Option<DateTime<Utc>>,
}

impl LookupResult {
    pub fn is_response(&self) -> bool {
        match self {
            LookupResult::Response { .. } => true,
            _ => false,
        }
    }

    pub fn is_nxdomain(&self) -> bool {
        match self {
            LookupResult::NxDomain { .. } => true,
            _ => false,
        }
    }

    pub fn is_timeout(&self) -> bool {
        match self {
            LookupResult::Timeout { .. } => true,
            _ => false,
        }
    }

    pub fn is_err(&self) -> bool {
        match self {
            LookupResult::Error { .. } => true,
            _ => false,
        }
    }

    pub fn response(&self) -> Option<&Response> {
        match self {
            LookupResult::Response(ref response) => Some(response),
            _ => None,
        }
    }

    pub fn nxdomain(&self) -> Option<&NxDomain> {
        match self {
            LookupResult::NxDomain(ref nxdomain) => Some(nxdomain),
            _ => None,
        }
    }

    pub fn err(&self) -> Option<&String> {
        match self {
            LookupResult::Error(ref err) => Some(&err),
            _ => None,
        }
    }
}

async fn do_lookup(resolver: &Resolver, query: Query) -> Lookup {
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

    Lookup {
        query,
        name_server: resolver.name_server.clone(),
        result,
    }
}

#[doc(hidden)]
trait IntoLookup {
    fn into_lookup(self, start_time: Instant) -> LookupResult;
}

#[doc(hidden)]
impl IntoLookup for std::result::Result<trust_dns_resolver::lookup::Lookup, ResolveError> {
    fn into_lookup(self, start_time: Instant) -> LookupResult {
        match self {
            Ok(lookup) => {
                let records: Vec<Record> = lookup.record_iter().map(Record::from).collect();
                LookupResult::Response(Response {
                    records,
                    response_time: Instant::now() - start_time,
                    valid_until: instant_to_utc(lookup.valid_until()),
                })
            }
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { valid_until, .. } => LookupResult::NxDomain(NxDomain {
                    response_time: Instant::now() - start_time,
                    valid_until: valid_until.map(instant_to_utc),
                }),
                ResolveErrorKind::Timeout => LookupResult::Timeout,
                _ => LookupResult::Error(Error::from(err).to_string()),
            },
        }
    }
}

fn instant_to_utc(instant: Instant) -> DateTime<Utc> {
    let now = Instant::now();
    let duration = instant.duration_since(now);

    Utc::now() + chrono::Duration::from_std(duration).unwrap() // Safe, because I know this is a valid duration
}
