// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashSet;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice::Iter;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use futures::stream::{self, StreamExt};
use futures::Future;
use serde::Serialize;
use tokio::task;
use tracing::{debug, field, info, instrument, trace, Span};
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::proto::xfer::DnsRequestOptions;

use crate::error::Errors;
use crate::nameserver::NameServerConfig;
use crate::resolver::{Error, MultiQuery, Resolver, ResolverResult, UniQuery};
use crate::resources::rdata::{Name, MX, NULL, SOA, SRV, TXT, UNKNOWN};
use crate::resources::{RData, Record};
use crate::utils::buffer_unordered_with_breaker::StreamExtBufferUnorderedWithBreaker;
use crate::utils::serialize::ser_arc_nameserver_config;
use crate::RecordType;
use std::fmt::Debug;
use tracing_futures::Instrument;

#[derive(Debug, Clone, Serialize)]
pub struct Lookups {
    #[serde(rename = "lookups")]
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
    pub fn new(inner: Vec<Lookup>) -> Lookups {
        Lookups { inner }
    }

    pub fn empty() -> Lookups {
        Lookups { inner: Vec::new() }
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

    pub fn has_records(&self) -> bool {
        self.inner.iter().any(|x| x.result().is_response())
    }

    pub fn responses(&self) -> Vec<&Response> {
        self.map_responses().collect()
    }

    pub fn records(&self) -> Vec<&Record> {
        self.inner.iter().flat_map(|x| x.records()).collect()
    }

    pub fn ips(&self) -> Vec<IpAddr> {
        let ipv4s = self
            .inner
            .iter()
            .flat_map(|x| x.result().response())
            .flat_map(|x| x.records())
            .flat_map(|x| x.data().a())
            .cloned()
            .map(IpAddr::V4);
        let ipv6s = self
            .inner
            .iter()
            .flat_map(|x| x.result().response())
            .flat_map(|x| x.records())
            .flat_map(|x| x.data().aaaa())
            .cloned()
            .map(IpAddr::V6);
        ipv4s.chain(ipv6s).collect()
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
            .flat_map(|x| mapper(x.data()))
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
        self.inner.iter().flat_map(|x| x.result().response())
    }

    /** Merge two Lookups into one
     *
     * This operation consumes both Lookups and creates a new one without cloning or copying the
     * contained `Lookups`.
     */
    pub fn merge(self, other: Self) -> Self {
        let mut inner = self.inner;
        let mut other = other.inner;
        inner.append(&mut other);
        Lookups { inner }
    }

    /** Combine this Lookups with another one
     *
     * This operation does not alter `this` or `other` by taking the `Lookup`'s from both, cloning
     * them, and creating a new `Lookups` with the results.
     */
    pub fn combine<T: AsRef<Self>>(&self, other: T) -> Self {
        let inner = self
            .inner
            .iter()
            .cloned()
            .chain(other.as_ref().iter().cloned())
            .collect();
        Lookups { inner }
    }
}

impl AsRef<Lookups> for Lookups {
    fn as_ref(&self) -> &Lookups {
        self
    }
}

impl Errors for Lookups {
    fn errors(&self) -> Box<dyn Iterator<Item = Box<&dyn std::error::Error>> + '_> {
        Box::new(self.inner.iter().flat_map(|l| l.result().err()).map(|x| {
            let ptr: Box<&dyn std::error::Error> = Box::new(x);
            ptr
        }))
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

    pub fn iter(&'a self) -> impl Iterator<Item = &'a T> {
        self.inner.iter().copied()
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
                .map(|x| x.data().$method())
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

    pub fn records(&self) -> Vec<&Record> {
        self.result().records()
    }

    pub fn ips(&self) -> Vec<IpAddr> {
        let ipv4s = self
            .result()
            .response()
            .into_iter()
            .flat_map(|x| x.records())
            .flat_map(|x| x.data().a())
            .cloned()
            .map(IpAddr::V4);
        let ipv6s = self
            .result()
            .response()
            .into_iter()
            .flat_map(|x| x.records())
            .flat_map(|x| x.data().aaaa())
            .cloned()
            .map(IpAddr::V6);
        ipv4s.chain(ipv6s).collect()
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
    Error(Error),
}

impl LookupResult {
    pub fn is_response(&self) -> bool {
        matches!(self, LookupResult::Response { .. })
    }

    pub fn is_nxdomain(&self) -> bool {
        matches!(self, LookupResult::NxDomain { .. })
    }

    pub fn is_err(&self) -> bool {
        matches!(self, LookupResult::Error { .. })
    }

    pub fn response_time(&self) -> Option<Duration> {
        match self {
            LookupResult::Response(x) => Some(x.response_time),
            LookupResult::NxDomain(x) => Some(x.response_time),
            LookupResult::Error(_) => None,
        }
    }

    pub fn response(&self) -> Option<&Response> {
        match self {
            LookupResult::Response(ref response) => Some(response),
            _ => None,
        }
    }

    pub fn records(&self) -> Vec<&Record> {
        match self.response() {
            Some(response) => response.records().iter().collect(),
            None => Vec::new(),
        }
    }

    pub fn nxdomain(&self) -> Option<&NxDomain> {
        match self {
            LookupResult::NxDomain(ref nxdomain) => Some(nxdomain),
            _ => None,
        }
    }

    pub fn err(&self) -> Option<&Error> {
        match self {
            LookupResult::Error(ref err) => Some(err),
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
}

#[instrument(name = "multi lookup", level = "info", skip(resolver, query), fields(r = %resolver.name_server, ns = field::Empty, ts = field::Empty))]
pub async fn lookup<T: Into<MultiQuery>>(resolver: Resolver, query: T) -> ResolverResult<Lookups> {
    let breaker = create_breaker(resolver.opts.abort_on_error, resolver.opts.abort_on_timeout);
    let query = query.into();

    let span = Span::current();
    span.record("ns", format!("{:?}", query.names).as_str());
    span.record("rs", format!("{:?}", query.record_types).as_str());

    debug!("Creating lookups");
    let lookup_futures: Vec<_> = query
        .into_uni_queries()
        .drain(..)
        .map(|q| single_lookup(resolver.clone(), q))
        .collect();
    let lookups = sliding_window_lookups(lookup_futures, breaker, resolver.opts.max_concurrent_requests);

    debug!("Spawning lookups");
    let lookups = task::spawn(lookups).instrument(span).await?;

    Ok(lookups)
}

fn create_breaker(on_error: bool, on_timeout: bool) -> Box<dyn Fn(&Lookup) -> bool + Send> {
    Box::new(move |l: &Lookup| match l.result.err() {
        Some(Error::Timeout) if on_timeout => true,
        Some(Error::Timeout) if !on_timeout => false,
        Some(_) if on_error => true,
        _ => false,
    })
}

#[instrument(name = "single lookup", level = "info", skip(resolver, query), fields(r = %resolver.name_server, n = %query.name, t = ?query.record_type))]
async fn single_lookup(resolver: Resolver, query: UniQuery) -> Lookup {
    let dns_request_options = DnsRequestOptions {
        expects_multiple_responses: resolver.opts.expects_multiple_responses,
        use_edns: true,
    };
    let q = query.clone();
    let start_time = Instant::now();

    debug!("Sending lookup request");
    let result = resolver
        .inner
        .lookup(q.name, q.record_type.into(), dns_request_options)
        .await
        .into_lookup(start_time);

    info!(
        "Received {}, response time = {:?}",
        match &result {
            LookupResult::Response(response) => format!("response with {:?} records", response.records.len()),
            LookupResult::NxDomain(_) => "nonexistent domain".to_string(),
            LookupResult::Error(err) => format!("{:?} error", err),
        },
        result.response_time(),
    );
    trace!("Received {:?}", result);

    Lookup {
        query,
        name_server: resolver.name_server.clone(),
        result,
    }
}

async fn sliding_window_lookups(
    futures: Vec<impl Future<Output = Lookup>>,
    breaker: Box<dyn Fn(&Lookup) -> bool + Send>,
    max_concurrent: usize,
) -> Lookups {
    stream::iter(futures)
        .buffered_unordered_with_breaker(max_concurrent, breaker)
        .collect::<Vec<_>>()
        .await
        .into()
}

#[doc(hidden)]
fn map_response_records<'a, I: Iterator<Item = &'a Response>>(responses: I) -> impl Iterator<Item = &'a Record> {
    responses.flat_map(|x| x.records())
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
                ResolveErrorKind::NoRecordsFound { .. } => LookupResult::NxDomain(NxDomain {
                    response_time: Instant::now() - start_time,
                }),
                _ => {
                    let err = Error::from(err);
                    LookupResult::Error(err)
                }
            },
        }
    }
}

fn instant_to_utc(valid_until: Instant) -> DateTime<Utc> {
    let now = Instant::now();
    let duration = if now >= valid_until {
        Duration::from_secs(0)
    } else {
        valid_until.duration_since(now)
    };

    Utc::now() + chrono::Duration::from_std(duration).unwrap() // Safe, because I know this is a valid duration
}
