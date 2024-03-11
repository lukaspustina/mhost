// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::{Arc, Mutex};

use futures::stream::{self, StreamExt};
use futures::Future;
use ipnetwork::IpNetwork;
use serde::Serialize;
use tokio::task;
use tracing::{debug, info, instrument, trace};

pub use service::{Authority, GeoLocation, LocatedResource, Location, NetworkInfo, Whois};

use crate::error::Errors;
use crate::services::whois::service::RipeStatsClientOpts;
use crate::services::{Error, Result};
use crate::utils::buffer_unordered_with_breaker::StreamExtBufferUnorderedWithBreaker;
use crate::utils::serialize::ser_to_string;
use lru_time_cache::LruCache;
use std::slice::Iter;
use std::time::Duration;

mod service;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryType {
    GeoLocation,
    NetworkInfo,
    Whois,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UniQuery {
    resource: IpNetwork,
    query_type: QueryType,
}

#[derive(Debug, Serialize)]
pub struct MultiQuery {
    resources: Vec<IpNetwork>,
    query_types: Vec<QueryType>,
}

impl MultiQuery {
    pub fn new(resources: Vec<IpNetwork>, query_types: Vec<QueryType>) -> MultiQuery {
        MultiQuery { resources, query_types }
    }

    pub fn from_iter<T: Into<IpNetwork>, I: IntoIterator<Item = T>, J: IntoIterator<Item = QueryType>>(
        resources: I,
        query_types: J,
    ) -> MultiQuery {
        let resources = resources.into_iter().map(Into::into).collect();
        let query_types = query_types.into_iter().collect();
        Self::new(resources, query_types)
    }

    pub fn single<T: Into<IpNetwork>>(resource: T, query_type: QueryType) -> MultiQuery {
        let resource = resource.into();
        Self::new(vec![resource], vec![query_type])
    }

    pub fn multi_resources<T: Into<IpNetwork>, I: IntoIterator<Item = T>>(
        resources: I,
        query_type: QueryType,
    ) -> MultiQuery {
        Self::from_iter(resources, vec![query_type])
    }

    pub fn multi_types(resource: IpNetwork, query_types: Vec<QueryType>) -> MultiQuery {
        Self::from_iter(vec![resource], query_types)
    }

    pub(crate) fn into_uni_queries(self) -> Vec<UniQuery> {
        let mut queries = Vec::new();
        for resource in self.resources.iter() {
            for query_type in self.query_types.iter() {
                queries.push(UniQuery {
                    resource: *resource,
                    query_type: query_type.clone(),
                });
            }
        }

        queries
    }

    pub fn resources(&self) -> &Vec<IpNetwork> {
        &self.resources
    }

    pub fn query_types(&self) -> &Vec<QueryType> {
        &self.query_types
    }
}

#[derive(Debug)]
pub struct WhoisClientOpts {
    max_concurrent_requests: usize,
    abort_on_error: bool,
    timeout: Duration,
    lru_size: Option<usize>,
    lru_ttl: Option<Duration>,
}

impl WhoisClientOpts {
    pub fn new(max_concurrent_requests: usize, timeout: Duration, abort_on_error: bool) -> WhoisClientOpts {
        WhoisClientOpts {
            max_concurrent_requests,
            abort_on_error,
            timeout,
            lru_size: None,
            lru_ttl: None,
        }
    }

    pub fn with_cache(
        max_concurrent_requests: usize,
        abort_on_error: bool,
        timeout: Duration,
        cache_size: usize,
        cache_ttl: Duration,
    ) -> WhoisClientOpts {
        WhoisClientOpts {
            max_concurrent_requests,
            abort_on_error,
            timeout,
            lru_size: Some(cache_size),
            lru_ttl: Some(cache_ttl),
        }
    }
}

impl Default for WhoisClientOpts {
    fn default() -> Self {
        WhoisClientOpts::new(8, Duration::from_secs(5), true)
    }
}

#[derive(Clone)]
pub struct WhoisClient {
    inner: Arc<service::RipeStatsClient>,
    opts: Arc<WhoisClientOpts>,
    lru_cache: Option<Arc<Mutex<LruCache<UniQuery, WhoisResponse>>>>,
}

impl WhoisClient {
    pub fn new(opts: WhoisClientOpts) -> WhoisClient {
        let lru_cache = match (opts.lru_size, opts.lru_ttl) {
            (Some(size), Some(ttl)) => {
                let cache = LruCache::with_expiry_duration_and_capacity(ttl, size);
                Some(Arc::new(Mutex::new(cache)))
            }
            _ => None,
        };

        let ripe_client_opts = RipeStatsClientOpts::new(opts.timeout);

        WhoisClient {
            inner: Arc::new(service::RipeStatsClient::new(ripe_client_opts)),
            opts: Arc::new(opts),
            lru_cache,
        }
    }

    #[instrument(name = "query", level = "info", skip(self, query), fields(rs = ?query.resources, ts = ?query.query_types))]
    pub async fn query(&self, query: MultiQuery) -> Result<WhoisResponses> {
        let breaker = create_breaker(self.opts.abort_on_error);

        debug!("Creating queries");
        let query_futures: Vec<_> = query
            .into_uni_queries()
            .into_iter()
            .map(|q| single_query(self.clone(), q))
            .collect();
        let queries = sliding_window_lookups(query_futures, breaker, self.opts.max_concurrent_requests);

        debug!("Spawning queries");
        let responses = task::spawn(queries).await?;

        Ok(responses)
    }
}

fn create_breaker(on_error: bool) -> Box<dyn Fn(&WhoisResponse) -> bool + Send> {
    Box::new(move |r: &WhoisResponse| r.is_err() && on_error)
}

#[instrument(name = "single query", level = "info", skip(whois, query), fields(r = %query.resource, t = ?query.query_type))]
async fn single_query(whois: WhoisClient, query: UniQuery) -> WhoisResponse {
    let response = if let Some(cache_arc) = whois.lru_cache.clone().as_ref() {
        debug!("Sending query request using cache");
        single_query_with_cache(cache_arc, whois, query).await
    } else {
        debug!("Sending query request");
        send_query(whois, query).await
    };

    info!(
        "Received {}",
        if let Some(err) = response.err() {
            format!("{:?} error", err)
        } else {
            format!("response: {:?} ", response.response_type())
        }
    );
    trace!("Received {:?}", response);

    response
}

async fn single_query_with_cache(
    cache_arc: &Arc<Mutex<LruCache<UniQuery, WhoisResponse>>>,
    whois: WhoisClient,
    query: UniQuery,
) -> WhoisResponse {
    // This extra block is necessary, to convince the compiler that the Mutex not cross a thread
    // boundary: So to keep this future `Send`
    {
        let mut cache = cache_arc.lock().unwrap();
        if let Some(v) = cache.get(&query) {
            trace!("Hit cache for whois query {:?}", query);
            return v.clone();
        }
    }

    let response = send_query(whois.clone(), query.clone()).await;

    let mut cache = cache_arc.lock().unwrap();
    trace!(
        "Inserting response {:?} into cache for whois query {:?}",
        response,
        query
    );
    cache.insert(query, response.clone());

    response
}

async fn send_query(whois: WhoisClient, query: UniQuery) -> WhoisResponse {
    let resource = query.resource;

    let result: WhoisResponse = match query.query_type {
        QueryType::GeoLocation => {
            whois
                .inner
                .geo_location(query.resource)
                .await
                .into_whois_response(|x| WhoisResponse::GeoLocation {
                    resource,
                    geo_location: x,
                })
        }
        QueryType::NetworkInfo => {
            whois
                .inner
                .network_info(query.resource)
                .await
                .into_whois_response(|x| WhoisResponse::NetworkInfo {
                    resource,
                    network_info: x,
                })
        }
        QueryType::Whois => whois
            .inner
            .whois(query.resource.to_string())
            .await
            .into_whois_response(|x| WhoisResponse::Whois { resource, whois: x }),
    }
    .or_else::<Error, _>(|err| {
        Ok(WhoisResponse::Error {
            resource,
            err: Arc::new(err),
        })
    })
    .unwrap();

    result
}

trait IntoWhoisResponse<T> {
    fn into_whois_response<F: Fn(T) -> WhoisResponse>(self, map: F) -> Result<WhoisResponse>;
}

impl<T> IntoWhoisResponse<T> for Result<service::Response<T>> {
    fn into_whois_response<F: Fn(T) -> WhoisResponse>(self, map: F) -> Result<WhoisResponse> {
        self.map(|x| x.data)
            .and_then(|x| {
                x.ok_or_else(|| Error::HttpClientErrorMessage {
                    why: "Empty data",
                    details: "Whois result data is empty".to_string(),
                })
            })
            .map(map)
    }
}

async fn sliding_window_lookups(
    futures: Vec<impl Future<Output = WhoisResponse>>,
    breaker: Box<dyn Fn(&WhoisResponse) -> bool + Send>,
    max_concurrent: usize,
) -> WhoisResponses {
    let responses = stream::iter(futures)
        .buffered_unordered_with_breaker(max_concurrent, breaker)
        .collect::<Vec<_>>()
        .await;
    WhoisResponses { inner: responses }
}

impl Default for WhoisClient {
    fn default() -> Self {
        WhoisClient::new(Default::default())
    }
}

#[derive(Debug, Serialize, Clone)]
pub enum WhoisResponseType {
    GeoLocation,
    NetworkInfo,
    Whois,
    Error,
}

#[derive(Debug, Serialize, Clone)]
pub enum WhoisResponse {
    GeoLocation {
        resource: IpNetwork,
        geo_location: GeoLocation,
    },
    NetworkInfo {
        resource: IpNetwork,
        network_info: NetworkInfo,
    },
    Whois {
        resource: IpNetwork,
        whois: Whois,
    },
    Error {
        resource: IpNetwork,
        #[serde(serialize_with = "ser_to_string")]
        err: Arc<Error>,
    },
}

macro_rules! response_data_accessor {
    ($method:ident, $out_type:ident) => {
        pub fn $method(&self) -> Option<&$out_type> {
            match *self {
                WhoisResponse::$out_type {
                    resource: _,
                    $method: ref data,
                } => Some(data),
                _ => None,
            }
        }
    };
}

macro_rules! response_is_data {
    ($method:ident, $data:ident) => {
        pub fn $method(&self) -> bool {
            self.$data().is_some()
        }
    };
}

impl WhoisResponse {
    pub fn resource(&self) -> &IpNetwork {
        match *self {
            WhoisResponse::GeoLocation { ref resource, .. } => resource,
            WhoisResponse::NetworkInfo { ref resource, .. } => resource,
            WhoisResponse::Whois { ref resource, .. } => resource,
            WhoisResponse::Error { ref resource, .. } => resource,
        }
    }

    pub fn response_type(&self) -> WhoisResponseType {
        match self {
            WhoisResponse::GeoLocation { .. } => WhoisResponseType::GeoLocation,
            WhoisResponse::NetworkInfo { .. } => WhoisResponseType::NetworkInfo,
            WhoisResponse::Whois { .. } => WhoisResponseType::Whois,
            WhoisResponse::Error { .. } => WhoisResponseType::Error,
        }
    }

    response_data_accessor!(geo_location, GeoLocation);
    response_data_accessor!(network_info, NetworkInfo);
    response_data_accessor!(whois, Whois);
    response_data_accessor!(err, Error);

    response_is_data!(is_geo_location, geo_location);
    response_is_data!(is_network_info, network_info);
    response_is_data!(is_whois, whois);
    response_is_data!(is_err, err);
}

#[derive(Debug, Serialize)]
pub struct WhoisResponses {
    #[serde(rename = "whois")]
    inner: Vec<WhoisResponse>,
}

macro_rules! responses_data_accessor {
    ($method:ident, $out_type:ty) => {
        pub fn $method(&self) -> impl Iterator<Item = &$out_type> {
            self.inner.iter().map(|x| x.$method()).flatten()
        }
    };
}

impl WhoisResponses {
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn iter(&self) -> Iter<WhoisResponse> {
        self.inner.iter()
    }

    responses_data_accessor!(geo_location, GeoLocation);
    responses_data_accessor!(network_info, NetworkInfo);
    responses_data_accessor!(whois, Whois);
    responses_data_accessor!(err, Error);
}

impl Errors for WhoisResponses {
    fn errors(&self) -> Box<dyn Iterator<Item = Box<&dyn std::error::Error>> + '_> {
        Box::new(self.inner.iter().flat_map(|l| l.err()).map(|x| {
            let ptr: Box<&dyn std::error::Error> = Box::new(x);
            ptr
        }))
    }
}

impl IntoIterator for WhoisResponses {
    type Item = WhoisResponse;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use spectral::prelude::*;

    use super::*;

    #[tokio::test]
    async fn test_1_1_1_1() {
        crate::utils::tests::logging::init();
        let whois = WhoisClient::default();

        let ip_network = IpNetwork::from_str("1.1.1.1").unwrap();
        let query = MultiQuery::multi_types(
            ip_network,
            vec![QueryType::GeoLocation, QueryType::NetworkInfo, QueryType::Whois],
        );

        let res = whois.query(query).await;

        assert_that(&res).is_ok();
        let res = res.unwrap();
        assert_that(&res.len()).is_equal_to(3);
    }

    #[tokio::test]
    async fn test_5x_1_1_1_1() {
        crate::utils::tests::logging::init();
        let whois = WhoisClient::default();

        let ip_network = IpNetwork::from_str("1.1.1.1").unwrap();
        let ip_networks = vec![ip_network, ip_network, ip_network, ip_network, ip_network];
        let query = MultiQuery::new(
            ip_networks,
            vec![QueryType::GeoLocation, QueryType::NetworkInfo, QueryType::Whois],
        );

        let res = whois.query(query).await;

        assert_that(&res).is_ok();
        let res = res.unwrap();
        assert_that(&res.len()).is_equal_to(5 * 3);
    }
}
