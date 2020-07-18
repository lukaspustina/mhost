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
use crate::resolver::{MultiQuery, Query, Resolver};
use crate::resources::Record;
use crate::serialize::ser_arc_nameserver_config;
use std::slice::Iter;
use crate::Name;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::hash::Hash;
use crate::resources::rdata::SOA;

#[derive(Debug, Clone, Serialize)]
pub struct Lookups {
    inner: Vec<Lookup>,
}

impl Lookups {
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn iter(&self) -> Iter<Lookup> {
        self.inner.iter()
    }

    pub fn a(&self) -> Vec<Ipv4Addr> {
        self.inner
            .iter()
            .map(|x| x.result().response())
            .flatten()
            .map(|x| x.records())
            .flatten()
            .map(|x| x.rdata().a())
            .flatten()
            .cloned()
            .collect()
    }

    pub fn ns(&self) -> Vec<Name> {
        self.inner
            .iter()
            .map(|x| x.result().response())
            .flatten()
            .map(|x| x.records())
            .flatten()
            .map(|x| x.rdata().ns())
            .flatten()
            .cloned()
            .collect()
    }

    pub fn soa(&self) -> Vec<SOA> {
        self.inner
            .iter()
            .map(|x| x.result().response())
            .flatten()
            .map(|x| x.records())
            .flatten()
            .map(|x| x.rdata().soa())
            .flatten()
            .cloned()
            .collect()
    }
}

pub trait Uniquify<T> {
    fn unique(self) -> Vec<T>;
}

impl<S, T> Uniquify<T> for S where S: std::marker::Sized + IntoIterator<Item = T>, T: Eq + Hash {
    fn unique(self) -> Vec<T> {
        let set: HashSet<T> = self.into_iter().collect();
        set.into_iter().collect()
    }
}

impl IntoIterator for Lookups {
    type Item = Lookup;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl From<Vec<Lookup>> for Lookups {
    fn from(lookups: Vec<Lookup>) -> Self {
        Lookups { inner: lookups }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Lookup {
    query: Query,
    #[serde(serialize_with = "ser_arc_nameserver_config")]
    name_server: Arc<NameServerConfig>,
    result: LookupResult,
}

impl Lookup {
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

pub async fn lookup<T: Into<MultiQuery>>(resolver: Resolver, query: T) -> Lookups {
    let MultiQuery { names, record_types } = query.into();

    let mut lookup_futures = Vec::new();
    for name in names.iter() {
        for record_type in record_types.iter() {
            let q = Query { name: name.clone(), record_type: record_type.clone() };
            let f = single_lookup(&resolver, q);
            lookup_futures.push(f);
        }
    }

    let lookups = stream::iter(lookup_futures)
        .buffer_unordered(resolver.opts.max_concurrent_requests)
        .inspect(|lookup| trace!("Received lookup {:?}", lookup))
        .collect::<Vec<Lookup>>()
        .await;

    lookups.into()
}

async fn single_lookup(resolver: &Resolver, query: Query) -> Lookup {
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
