use std::sync::{Arc, Mutex};

use futures::stream::{self, StreamExt};
use futures::Future;
use ipnetwork::IpNetwork;
use log::{debug, trace};
use serde::Serialize;
use tokio::task;

pub use service::{Authority, GeoLocation, LocatedResource, Location, NetworkInfo, Whois};

use crate::services::{Error, Result};
use crate::utils::buffer_unordered_with_breaker::StreamExtBufferUnorderedWithBreaker;
use crate::utils::serialize::ser_to_string;
use std::slice::Iter;
use lru_time_cache::LruCache;
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
    lru_size: Option<usize>,
    lru_ttl: Option<Duration>,
}

impl WhoisClientOpts {
    pub fn new(max_concurrent_requests: usize, abort_on_error: bool) -> WhoisClientOpts {
        WhoisClientOpts {
            max_concurrent_requests,
            abort_on_error,
            lru_size: None,
            lru_ttl: None,
        }
    }

    pub fn with_cache(max_concurrent_requests: usize, abort_on_error: bool, cache_size: usize, cache_ttl: Duration) -> WhoisClientOpts {
        WhoisClientOpts {
            max_concurrent_requests,
            abort_on_error,
            lru_size: Some(cache_size),
            lru_ttl: Some(cache_ttl),
        }
    }
}

impl Default for WhoisClientOpts {
    fn default() -> Self {
        WhoisClientOpts::new(8, true)
    }
}

#[derive(Clone)]
pub struct WhoisClient {
    inner: Arc<service::RipeStatsClient>,
    opts: Arc<WhoisClientOpts>,
    lru_cache: Option<Arc<Mutex<LruCache<UniQuery, WhoisResponse>>>>
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
        WhoisClient {
            inner: Arc::new(service::RipeStatsClient::new()),
            opts: Arc::new(opts),
            lru_cache,
        }
    }

    pub async fn query(&self, query: MultiQuery) -> Result<WhoisResponses> {
        let breaker = create_breaker(self.opts.abort_on_error);

        let query_futures: Vec<_> = query
            .into_uni_queries()
            .into_iter()
            .map(|q| single_query(self.clone(), q))
            .collect();
        let queries = sliding_window_lookups(query_futures, breaker, self.opts.max_concurrent_requests);
        let responses = task::spawn(queries).await?;

        Ok(responses)
    }
}

fn create_breaker(on_error: bool) -> Box<dyn Fn(&WhoisResponse) -> bool + Send> {
    Box::new(move |r: &WhoisResponse| r.is_err() && on_error)
}

async fn single_query(whois: WhoisClient, query: UniQuery) -> WhoisResponse {
    if let Some(cache_arc) = whois.lru_cache.clone().as_ref() {
        single_query_with_cache(cache_arc, whois, query).await
    } else {
        send_query(whois, query).await
    }
}

async fn single_query_with_cache(cache_arc: &Arc<Mutex<LruCache<UniQuery, WhoisResponse>>>, whois: WhoisClient, query: UniQuery) -> WhoisResponse {
    // This extra block is necessary, to convince the compiler that the Mutex not cross a thread
    // boundary: So to keep this future `Send`
    {
        let mut cache = cache_arc.lock().unwrap();
        if let Some(v) = cache.get(&query) {
            trace!("Hit cache for whois query {:?}", query);
            return v.clone()
        }
    }

    let response = send_query(whois.clone(), query.clone()).await;

    let mut cache = cache_arc.lock().unwrap();
    trace!("Inserting response {:?} into cache for whois query {:?}", response, query);
    cache.insert(query, response.clone());

    response
}

async fn send_query(whois: WhoisClient, query: UniQuery) -> WhoisResponse {
    trace!(
        "Sending Whois query for '{}', query type {:?}.",
        &query.resource,
        &query.query_type
    );
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
    .or_else::<Error, _>(|err| Ok(WhoisResponse::Error { resource, err: Arc::new(err) }))
    .unwrap();

    debug!(
        "Whois response returned for '{}', record type {:?}: {}",
        &query.resource,
        &query.query_type,
        if result.is_err() { "error" } else { "ok" },
    );

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
            .map(|x| map(x))
    }
}

async fn sliding_window_lookups(
    futures: Vec<impl Future<Output = WhoisResponse>>,
    breaker: Box<dyn Fn(&WhoisResponse) -> bool + Send>,
    max_concurrent: usize,
) -> WhoisResponses {
    let responses = stream::iter(futures)
        .buffered_unordered_with_breaker(max_concurrent, breaker)
        .inspect(|response| trace!("Received Whois response {:?}", response))
        .collect::<Vec<_>>()
        .await;
    WhoisResponses { responses }
}

impl Default for WhoisClient {
    fn default() -> Self {
        WhoisClient::new(Default::default())
    }
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
    responses: Vec<WhoisResponse>,
}

macro_rules! responses_data_accessor {
    ($method:ident, $out_type:ty) => {
        pub fn $method(&self) -> impl Iterator<Item = &$out_type> {
            self.responses.iter().map(|x| x.$method()).flatten()
        }
    };
}

impl WhoisResponses {
    pub fn len(&self) -> usize {
        self.responses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.responses.is_empty()
    }

    pub fn iter(&self) -> Iter<WhoisResponse> {
        self.responses.iter()
    }

    responses_data_accessor!(geo_location, GeoLocation);
    responses_data_accessor!(network_info, NetworkInfo);
    responses_data_accessor!(whois, Whois);
    responses_data_accessor!(err, Error);
}

impl IntoIterator for WhoisResponses {
    type Item = WhoisResponse;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.responses.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use spectral::prelude::*;

    use super::*;

    #[tokio::test]
    async fn test_1_1_1_1() {
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
