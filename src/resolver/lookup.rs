use std::collections::HashSet;
use std::hash::Hash;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::slice::Iter;
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
use crate::resolver::{MultiQuery, Resolver, UniQuery};
use crate::resources::rdata::{Name, MX, NULL, SOA, SRV, TXT, UNKNOWN};
use crate::resources::{RData, Record};
use crate::serialize::ser_arc_nameserver_config;
use crate::RecordType;

#[derive(Debug, Clone, Serialize)]
pub struct Lookups {
    inner: Vec<Lookup>,
}

macro_rules! accessor {
    ($method:ident, $out_type:ty) => {
        pub fn $method(&self) -> Vec<&$out_type> {
            self.filter_record_type(|rdata| rdata.$method())
        }
    };
}

impl Lookups {
    #[allow(dead_code)]
    #[doc(hidden)]
    pub(crate) fn new(inner: Vec<Lookup>) -> Lookups {
        Lookups { inner }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> Iter<Lookup> {
        self.inner.iter()
    }

    accessor!(a, Ipv4Addr);
    accessor!(aaaa, Ipv6Addr);
    accessor!(aname, Name);
    accessor!(cname, Name);
    accessor!(mx, MX);
    accessor!(null, NULL);
    accessor!(ns, Name);
    accessor!(ptr, Name);
    accessor!(soa, SOA);
    accessor!(srv, SRV);
    accessor!(txt, TXT);
    accessor!(unknown, UNKNOWN);

    fn filter_record_type<T, F: Fn(&RData) -> Option<&T>>(&self, filter: F) -> Vec<&T> {
        self.inner
            .iter()
            .map(|x| x.result().response())
            .flatten()
            .map(|x| x.records())
            .flatten()
            .map(|x| filter(x.rdata()))
            .flatten()
            .collect()
    }

    pub fn record_types(&self) -> HashSet<RecordType> {
        self.inner
            .iter()
            .map(|x| x.result().response())
            .flatten()
            .map(|x| x.records())
            .flatten()
            .map(|x| x.rr_type())
            .collect()
    }
}

pub trait Uniquify<'a, T: Clone + Eq + Hash> {
    fn unique(self) -> Uniquified<'a, T>;
}

// It's impossible to impl ToOwned fpr HashSet<&Name>, because of Borrow<Self>, thus I use the
// new-type pattern to add a to_owned method by myself. Not perfect, but it is what it is.
#[derive(Debug)]
pub struct Uniquified<'a, T: Clone + Eq + Hash> {
    inner: HashSet<&'a T>,
}

impl<'a, T: Clone + Eq + Hash> Uniquified<'a, T> {
    pub fn set(&'a self) -> &'a HashSet<&'a T> {
        &self.inner
    }

    pub fn to_owned(&self) -> HashSet<T> {
        self.inner.iter().map(|x| (*x).clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<'a, S, T> Uniquify<'a, T> for S
where
    S: std::marker::Sized + IntoIterator<Item = &'a T> + 'a,
    T: Clone + Eq + Hash + 'a,
{
    fn unique(self) -> Uniquified<'a, T> {
        Uniquified {
            inner: self.into_iter().collect(),
        }
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
    query: UniQuery,
    #[serde(serialize_with = "ser_arc_nameserver_config")]
    name_server: Arc<NameServerConfig>,
    result: LookupResult,
}

impl Lookup {
    pub fn query(&self) -> &UniQuery {
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
    let query = query.into();

    let lookup_futures = query
        .into_uni_queries()
        .into_iter()
        .map(|q| single_lookup(&resolver, q));

    let lookups = stream::iter(lookup_futures)
        .buffer_unordered(resolver.opts.max_concurrent_requests)
        .inspect(|lookup| trace!("Received lookup {:?}", lookup))
        .collect::<Vec<Lookup>>()
        .await;

    lookups.into()
}

async fn single_lookup(resolver: &Resolver, query: UniQuery) -> Lookup {
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
