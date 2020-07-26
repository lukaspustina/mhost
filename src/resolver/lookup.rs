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

macro_rules! lookups_data_accessor {
    ($method:ident, $out_type:ty) => {
        pub fn $method(&self) -> Vec<&$out_type> {
            self.map_data(|rdata| rdata.$method())
        }
    };
}

macro_rules! lookups_record_accessor {
    ($method:ident, $record_type:expr) => {
        pub fn $method(&self) -> Vec<&Record> {
            self.records_by_type($record_type)
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

    lookups_data_accessor!(a, Ipv4Addr);
    lookups_data_accessor!(aaaa, Ipv6Addr);
    lookups_data_accessor!(aname, Name);
    lookups_data_accessor!(cname, Name);
    lookups_data_accessor!(mx, MX);
    lookups_data_accessor!(null, NULL);
    lookups_data_accessor!(ns, Name);
    lookups_data_accessor!(ptr, Name);
    lookups_data_accessor!(soa, SOA);
    lookups_data_accessor!(srv, SRV);
    lookups_data_accessor!(txt, TXT);
    lookups_data_accessor!(unknown, UNKNOWN);

    fn map_data<T, F: Fn(&RData) -> Option<&T>>(&self, mapper: F) -> Vec<&T> {
        map_response_records(self.map_responses())
            .map(|x| mapper(x.rdata()))
            .flatten()
            .collect()
    }

    pub fn records_by_type(&self, record_type: RecordType) -> Vec<&Record> {
        self.filter_rr_record(|record| record.record_type() == record_type)
    }

    lookups_record_accessor!(rr_a, RecordType::A);
    lookups_record_accessor!(rr_aaaa, RecordType::AAAA);
    lookups_record_accessor!(rr_aname, RecordType::ANAME);
    lookups_record_accessor!(rr_cname, RecordType::CNAME);
    lookups_record_accessor!(rr_mx, RecordType::MX);
    lookups_record_accessor!(rr_null, RecordType::NULL);
    lookups_record_accessor!(rr_ns, RecordType::NS);
    lookups_record_accessor!(rr_ptr, RecordType::PTR);
    lookups_record_accessor!(rr_soa, RecordType::SOA);
    lookups_record_accessor!(rr_srv, RecordType::SRV);
    lookups_record_accessor!(rr_txt, RecordType::TXT);

    pub fn rr_unknown(&self) -> Vec<&Record> {
        self.filter_rr_record(|record| record.record_type().is_unknown())
    }

    fn filter_rr_record<F: Fn(&Record) -> bool>(&self, filter: F) -> Vec<&Record> {
        map_response_records(self.map_responses())
            .filter(|x| filter(x))
            .collect()
    }

    pub fn record_types(&self) -> HashSet<RecordType> {
        map_response_records(self.map_responses())
            .map(|x| x.record_type())
            .collect()
    }

    fn map_responses(&self) -> impl Iterator<Item = &Response> {
        self.inner.iter().map(|x| x.result().response()).flatten()
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

macro_rules! lookup_data_accessor {
    ($method:ident, $out_type:ty) => {
        pub fn $method(&self) -> Vec<&$out_type> {
            map_response_records(self.result().response().into_iter())
                .map(|x| x.rdata().$method())
                .flatten()
                .collect()
        }
    };
}

macro_rules! lookup_record_accessor {
    ($method:ident, $record_type:expr) => {
        pub fn $method(&self) -> Vec<&Record> {
            map_response_records(self.result().response().into_iter())
                .filter(|x| x.record_type() == $record_type)
                .collect()
        }
    };
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

    lookup_data_accessor!(a, Ipv4Addr);
    lookup_data_accessor!(aaaa, Ipv6Addr);
    lookup_data_accessor!(aname, Name);
    lookup_data_accessor!(cname, Name);
    lookup_data_accessor!(mx, MX);
    lookup_data_accessor!(null, NULL);
    lookup_data_accessor!(ns, Name);
    lookup_data_accessor!(ptr, Name);
    lookup_data_accessor!(soa, SOA);
    lookup_data_accessor!(srv, SRV);
    lookup_data_accessor!(txt, TXT);
    lookup_data_accessor!(unknown, UNKNOWN);

    pub fn record_types(&self) -> HashSet<RecordType> {
        map_response_records(self.result().response().into_iter())
            .map(|x| x.record_type())
            .collect()
    }

    lookup_record_accessor!(rr_a, RecordType::A);
    lookup_record_accessor!(rr_aaaa, RecordType::AAAA);
    lookup_record_accessor!(rr_aname, RecordType::ANAME);
    lookup_record_accessor!(rr_cname, RecordType::CNAME);
    lookup_record_accessor!(rr_mx, RecordType::MX);
    lookup_record_accessor!(rr_null, RecordType::NULL);
    lookup_record_accessor!(rr_ns, RecordType::NS);
    lookup_record_accessor!(rr_ptr, RecordType::PTR);
    lookup_record_accessor!(rr_soa, RecordType::SOA);
    lookup_record_accessor!(rr_srv, RecordType::SRV);
    lookup_record_accessor!(rr_txt, RecordType::TXT);

    pub fn rr_unknown(&self) -> Vec<&Record> {
        map_response_records(self.result().response().into_iter())
            .filter(|x| x.record_type().is_unknown())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum LookupResult {
    Response(Response),
    NxDomain(NxDomain),
    Timeout,
    Error(String),
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
    let dns_request_options = DnsRequestOptions::default();
    let q = query.clone();
    let start_time = Instant::now();
    let result = resolver
        .inner
        .lookup(q.name, q.record_type.into(), dns_request_options)
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
fn map_response_records<'a, I: Iterator<Item = &'a Response>>(responses: I) -> impl Iterator<Item = &'a Record> {
    responses.map(|x| x.records()).flatten()
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
