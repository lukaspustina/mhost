// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Lookup results and aggregation.
//!
//! [`Lookup`] holds the result of a single query against a single nameserver.
//! [`Lookups`] aggregates results from multiple resolvers/queries, providing
//! typed accessors (`.a()`, `.mx()`, `.txt()`, etc.) and deduplication via
//! the [`Uniquify`] trait.

use std::collections::HashSet;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice::Iter;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use futures::stream::{self, StreamExt};
use futures::Future;
use hickory_resolver::ResolveError;
use serde::{Deserialize, Serialize};
use tokio::task;
use tracing::{debug, field, info, instrument, trace, Span};

use crate::error::Errors;
use crate::nameserver::NameServerConfig;
use crate::resolver::{Error, MultiQuery, Resolver, ResolverResult, UniQuery};
use crate::resources::rdata::{
    Name, CAA, DNSKEY, DS, HINFO, MX, NAPTR, NSEC, NSEC3, NSEC3PARAM, NULL, OPENPGPKEY, RRSIG, SOA, SRV, SSHFP, SVCB,
    TLSA, TXT, UNKNOWN,
};
use crate::resources::{RData, Record};
use crate::utils::buffer_unordered_with_breaker::StreamExtBufferUnorderedWithBreaker;
use crate::utils::serialize::{deser_arc_nameserver_config, ser_arc_nameserver_config};
use crate::RecordType;
use std::fmt::Debug;
use tracing_futures::Instrument;

/// Aggregated DNS lookup results from one or more resolvers and queries.
///
/// Provides typed accessors for each record type (e.g., `.a()`, `.mx()`, `.txt()`)
/// that return references into the contained records. Use the [`Uniquify`] trait
/// on accessor results to deduplicate across nameservers.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub fn iter(&self) -> Iter<'_, Lookup> {
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
    lookups_data_accessor!(caa, CAA);
    lookups_data_accessor!(cname, Name);
    lookups_data_accessor!(dnskey, DNSKEY);
    lookups_data_accessor!(ds, DS);
    lookups_data_accessor!(hinfo, HINFO);
    lookups_data_accessor!(https, SVCB);
    lookups_data_accessor!(mx, MX);
    lookups_data_accessor!(naptr, NAPTR);
    lookups_data_accessor!(nsec, NSEC);
    lookups_data_accessor!(nsec3, NSEC3);
    lookups_data_accessor!(nsec3param, NSEC3PARAM);
    lookups_data_accessor!(null, NULL);
    lookups_data_accessor!(ns, Name);
    lookups_data_accessor!(openpgpkey, OPENPGPKEY);
    lookups_data_accessor!(ptr, Name);
    lookups_data_accessor!(rrsig, RRSIG);
    lookups_data_accessor!(soa, SOA);
    lookups_data_accessor!(srv, SRV);
    lookups_data_accessor!(sshfp, SSHFP);
    lookups_data_accessor!(svcb, SVCB);
    lookups_data_accessor!(tlsa, TLSA);
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
    lookups_record_accessor!(rr_caa, RecordType::CAA);
    lookups_record_accessor!(rr_cname, RecordType::CNAME);
    lookups_record_accessor!(rr_dnskey, RecordType::DNSKEY);
    lookups_record_accessor!(rr_ds, RecordType::DS);
    lookups_record_accessor!(rr_hinfo, RecordType::HINFO);
    lookups_record_accessor!(rr_https, RecordType::HTTPS);
    lookups_record_accessor!(rr_mx, RecordType::MX);
    lookups_record_accessor!(rr_naptr, RecordType::NAPTR);
    lookups_record_accessor!(rr_nsec, RecordType::NSEC);
    lookups_record_accessor!(rr_nsec3, RecordType::NSEC3);
    lookups_record_accessor!(rr_nsec3param, RecordType::NSEC3PARAM);
    lookups_record_accessor!(rr_null, RecordType::NULL);
    lookups_record_accessor!(rr_ns, RecordType::NS);
    lookups_record_accessor!(rr_openpgpkey, RecordType::OPENPGPKEY);
    lookups_record_accessor!(rr_ptr, RecordType::PTR);
    lookups_record_accessor!(rr_rrsig, RecordType::RRSIG);
    lookups_record_accessor!(rr_soa, RecordType::SOA);
    lookups_record_accessor!(rr_srv, RecordType::SRV);
    lookups_record_accessor!(rr_sshfp, RecordType::SSHFP);
    lookups_record_accessor!(rr_svcb, RecordType::SVCB);
    lookups_record_accessor!(rr_tlsa, RecordType::TLSA);
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

/// Trait for deduplicating lookup results across multiple nameservers.
///
/// Call `.unique()` on a `Vec<&T>` returned by accessor methods to get a
/// deduplicated set.
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
        self.inner.iter().cloned().cloned().collect()
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

/// The result of a single DNS query against a single nameserver.
///
/// Contains the original [`UniQuery`], the [`NameServerConfig`] that was queried,
/// and the [`LookupResult`] (response, NxDomain, or error).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lookup {
    query: UniQuery,
    #[serde(
        serialize_with = "ser_arc_nameserver_config",
        deserialize_with = "deser_arc_nameserver_config"
    )]
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
    lookup_data_accessor!(caa, CAA);
    lookup_data_accessor!(cname, Name);
    lookup_data_accessor!(dnskey, DNSKEY);
    lookup_data_accessor!(ds, DS);
    lookup_data_accessor!(hinfo, HINFO);
    lookup_data_accessor!(https, SVCB);
    lookup_data_accessor!(mx, MX);
    lookup_data_accessor!(naptr, NAPTR);
    lookup_data_accessor!(nsec, NSEC);
    lookup_data_accessor!(nsec3, NSEC3);
    lookup_data_accessor!(nsec3param, NSEC3PARAM);
    lookup_data_accessor!(null, NULL);
    lookup_data_accessor!(ns, Name);
    lookup_data_accessor!(openpgpkey, OPENPGPKEY);
    lookup_data_accessor!(ptr, Name);
    lookup_data_accessor!(rrsig, RRSIG);
    lookup_data_accessor!(soa, SOA);
    lookup_data_accessor!(srv, SRV);
    lookup_data_accessor!(sshfp, SSHFP);
    lookup_data_accessor!(svcb, SVCB);
    lookup_data_accessor!(tlsa, TLSA);
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
    lookup_record_accessor!(rr_caa, RecordType::CAA);
    lookup_record_accessor!(rr_cname, RecordType::CNAME);
    lookup_record_accessor!(rr_dnskey, RecordType::DNSKEY);
    lookup_record_accessor!(rr_ds, RecordType::DS);
    lookup_record_accessor!(rr_hinfo, RecordType::HINFO);
    lookup_record_accessor!(rr_https, RecordType::HTTPS);
    lookup_record_accessor!(rr_mx, RecordType::MX);
    lookup_record_accessor!(rr_naptr, RecordType::NAPTR);
    lookup_record_accessor!(rr_nsec, RecordType::NSEC);
    lookup_record_accessor!(rr_nsec3, RecordType::NSEC3);
    lookup_record_accessor!(rr_nsec3param, RecordType::NSEC3PARAM);
    lookup_record_accessor!(rr_null, RecordType::NULL);
    lookup_record_accessor!(rr_ns, RecordType::NS);
    lookup_record_accessor!(rr_openpgpkey, RecordType::OPENPGPKEY);
    lookup_record_accessor!(rr_ptr, RecordType::PTR);
    lookup_record_accessor!(rr_rrsig, RecordType::RRSIG);
    lookup_record_accessor!(rr_soa, RecordType::SOA);
    lookup_record_accessor!(rr_srv, RecordType::SRV);
    lookup_record_accessor!(rr_sshfp, RecordType::SSHFP);
    lookup_record_accessor!(rr_svcb, RecordType::SVCB);
    lookup_record_accessor!(rr_tlsa, RecordType::TLSA);
    lookup_record_accessor!(rr_txt, RecordType::TXT);

    pub fn rr_unknown(&self) -> Vec<&Record> {
        map_response_records(self.result().response().into_iter())
            .filter(|x| x.record_type().is_unknown())
            .collect()
    }
}

#[cfg(test)]
impl Lookup {
    pub fn new_for_test(query: UniQuery, name_server: Arc<NameServerConfig>, result: LookupResult) -> Self {
        Lookup {
            query,
            name_server,
            result,
        }
    }
}

/// The outcome of a single DNS lookup: a successful response, an NxDomain, or an error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LookupResult {
    /// The nameserver returned DNS records.
    Response(Response),
    /// The queried name does not exist.
    NxDomain(NxDomain),
    /// The lookup failed with a resolver error.
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

/// A successful DNS response containing records, timing, and cache validity.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[cfg(test)]
impl Response {
    pub fn new_for_test(records: Vec<Record>, response_time: Duration) -> Self {
        Response {
            records,
            response_time,
            valid_until: Utc::now(),
        }
    }
}

/// An NxDomain response indicating the queried name does not exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NxDomain {
    response_time: Duration,
}

#[cfg(test)]
impl NxDomain {
    pub fn new_for_test(response_time: Duration) -> Self {
        NxDomain { response_time }
    }
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
    let q = query.clone();
    let start_time = Instant::now();

    debug!("Sending lookup request");
    let result = resolver
        .inner
        .lookup(q.name, q.record_type.into())
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
impl IntoLookup for std::result::Result<hickory_resolver::lookup::Lookup, ResolveError> {
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
            Err(err) => {
                // In hickory 0.25, NoRecordsFound is detected via helper method
                if err.is_no_records_found() {
                    LookupResult::NxDomain(NxDomain {
                        response_time: Instant::now() - start_time,
                    })
                } else {
                    let err = Error::from(err);
                    LookupResult::Error(err)
                }
            }
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

    Utc::now() + chrono::Duration::from_std(duration).expect("duration from Instant is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nameserver::NameServerConfig;
    use crate::resources::rdata::{MX, TXT};
    use crate::resources::{RData, Record, RecordType};
    use std::net::Ipv4Addr;

    fn make_test_lookup(query_name: &str, record_type: RecordType, ns: &str, result: LookupResult) -> Lookup {
        Lookup {
            query: UniQuery::new(query_name, record_type).unwrap(),
            name_server: Arc::new(NameServerConfig::from_str(ns).unwrap()),
            result,
        }
    }

    fn make_response(records: Vec<Record>) -> LookupResult {
        LookupResult::Response(Response {
            records,
            response_time: Duration::from_millis(45),
            valid_until: chrono::DateTime::parse_from_rfc3339("2024-01-15T10:35:00Z")
                .unwrap()
                .with_timezone(&Utc),
        })
    }

    #[test]
    fn serde_round_trip_response_a_record() {
        let record = Record::new_for_test(
            Name::from_utf8("example.com.").unwrap(),
            RecordType::A,
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );
        let lookup = make_test_lookup(
            "example.com.",
            RecordType::A,
            "udp:8.8.8.8:53",
            make_response(vec![record]),
        );
        let lookups = Lookups::new(vec![lookup]);

        let json = serde_json::to_string(&lookups).expect("serialize");
        let deserialized: Lookups = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.len(), 1);
        assert_eq!(deserialized.a().len(), 1);
        assert_eq!(*deserialized.a()[0], Ipv4Addr::new(1, 2, 3, 4));
    }

    #[test]
    fn serde_round_trip_multiple_record_types() {
        let a_record = Record::new_for_test(
            Name::from_utf8("example.com.").unwrap(),
            RecordType::A,
            300,
            RData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );
        let mx_record = Record::new_for_test(
            Name::from_utf8("example.com.").unwrap(),
            RecordType::MX,
            300,
            RData::MX(MX::new(10, Name::from_utf8("mail.example.com.").unwrap())),
        );
        let txt_record = Record::new_for_test(
            Name::from_utf8("example.com.").unwrap(),
            RecordType::TXT,
            300,
            RData::TXT(TXT::new(vec!["v=spf1 include:example.com -all".to_string()])),
        );
        let lookup_a = make_test_lookup(
            "example.com.",
            RecordType::A,
            "udp:8.8.8.8:53",
            make_response(vec![a_record]),
        );
        let lookup_mx = make_test_lookup(
            "example.com.",
            RecordType::MX,
            "udp:8.8.8.8:53",
            make_response(vec![mx_record]),
        );
        let lookup_txt = make_test_lookup(
            "example.com.",
            RecordType::TXT,
            "udp:8.8.8.8:53",
            make_response(vec![txt_record]),
        );
        let lookups = Lookups::new(vec![lookup_a, lookup_mx, lookup_txt]);

        let json = serde_json::to_string(&lookups).expect("serialize");
        let deserialized: Lookups = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.len(), 3);
        assert_eq!(deserialized.a().len(), 1);
        assert_eq!(deserialized.mx().len(), 1);
        assert_eq!(deserialized.txt().len(), 1);
    }

    #[test]
    fn serde_round_trip_nxdomain() {
        let lookup = make_test_lookup(
            "nonexistent.example.com.",
            RecordType::A,
            "udp:8.8.8.8:53",
            LookupResult::NxDomain(NxDomain {
                response_time: Duration::from_millis(30),
            }),
        );
        let lookups = Lookups::new(vec![lookup]);

        let json = serde_json::to_string(&lookups).expect("serialize");
        let deserialized: Lookups = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.len(), 1);
        assert!(deserialized.iter().next().unwrap().result().is_nxdomain());
    }

    #[test]
    fn serde_round_trip_error() {
        let lookup = make_test_lookup(
            "example.com.",
            RecordType::A,
            "udp:8.8.8.8:53",
            LookupResult::Error(Error::Timeout),
        );
        let lookups = Lookups::new(vec![lookup]);

        let json = serde_json::to_string(&lookups).expect("serialize");
        let deserialized: Lookups = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.len(), 1);
        assert!(deserialized.iter().next().unwrap().result().is_err());
    }

    #[test]
    fn serde_round_trip_nameserver_config() {
        let configs = vec![
            "udp:8.8.8.8:53",
            "tcp:1.1.1.1:53",
            "tls:8.8.8.8:853,tls_auth_name=dns.google",
        ];
        for ns_str in configs {
            let lookup = make_test_lookup("example.com.", RecordType::A, ns_str, make_response(vec![]));
            let lookups = Lookups::new(vec![lookup]);

            let json = serde_json::to_string(&lookups).expect("serialize");
            let deserialized: Lookups = serde_json::from_str(&json).expect("deserialize");

            let original_ns = deserialized.iter().next().unwrap().name_server();
            let expected_ns = NameServerConfig::from_str(ns_str).unwrap();
            assert_eq!(
                original_ns.to_string(),
                expected_ns.to_string(),
                "round-trip failed for {}",
                ns_str
            );
        }
    }
}
