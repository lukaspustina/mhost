use std::sync::Arc;

use futures::stream::{self, StreamExt};
use futures::Future;
use ipnetwork::IpNetwork;
use log::{debug, trace};
use serde::Serialize;
use tokio::task;

pub use service::{Authority, GeoLocation, LocatedResource, Location, NetworkInfo, Whois};

use crate::services::{Error, Result};
use crate::utils::buffer_unordered_with_breaker::StreamExtBufferUnorderedWithBreaker;

mod service;

#[derive(Debug, Clone, Serialize)]
pub enum QueryType {
    GeoLocation,
    NetworkInfo,
    Whois,
}

#[derive(Debug, Clone, Serialize)]
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
                    resource: resource.clone(),
                    query_type: query_type.clone(),
                });
            }
        }

        queries
    }
}

#[derive(Debug)]
pub struct RipeStatsOpts {
    max_concurrent_requests: usize,
    abort_on_error: bool,
}

impl RipeStatsOpts {
    pub fn new(max_concurrent_requests: usize, abort_on_error: bool) -> RipeStatsOpts {
        RipeStatsOpts {
            max_concurrent_requests,
            abort_on_error,
        }
    }
}

impl Default for RipeStatsOpts {
    fn default() -> Self {
        RipeStatsOpts::new(8, true)
    }
}

#[derive(Clone)]
pub struct RipeStats {
    client: Arc<service::RipeStatsClient>,
    opts: Arc<RipeStatsOpts>,
}

impl RipeStats {
    pub fn new(opts: RipeStatsOpts) -> RipeStats {
        RipeStats {
            client: Arc::new(service::RipeStatsClient::new()),
            opts: Arc::new(opts),
        }
    }
    pub async fn query(&self, query: MultiQuery) -> Result<RipeStatsResponses> {
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

fn create_breaker(on_error: bool) -> Box<dyn Fn(&RipeStatsResponse) -> bool + Send> {
    Box::new(move |r: &RipeStatsResponse| r.is_err() && on_error)
}

async fn single_query(ripe_stats: RipeStats, query: UniQuery) -> RipeStatsResponse {
    trace!(
        "Sending RipeStats query for '{}', query type {:?}.",
        &query.resource,
        &query.query_type
    );
    let result: RipeStatsResponse = match query.query_type {
        QueryType::GeoLocation => ripe_stats
            .client
            .geo_location(query.resource)
            .await
            .into_ripe_stats_response(|x| RipeStatsResponse::GeoLocation { geo_location: x }),
        QueryType::NetworkInfo => ripe_stats
            .client
            .network_info(query.resource)
            .await
            .into_ripe_stats_response(|x| RipeStatsResponse::NetworkInfo { network_info: x }),
        QueryType::Whois => ripe_stats
            .client
            .whois(query.resource.to_string())
            .await
            .into_ripe_stats_response(|x| RipeStatsResponse::Whois { whois: x }),
    };

    debug!(
        "RipeStats response returned for '{}', record type {:?}: {}",
        &query.resource,
        &query.query_type,
        if result.is_err() { "error" } else { "ok" },
    );

    result
}

trait IntoRipeStatsResponse<T> {
    fn into_ripe_stats_response<F: Fn(T) -> RipeStatsResponse>(self, map: F) -> RipeStatsResponse;
}

impl<T> IntoRipeStatsResponse<T> for Result<service::Response<T>> {
    fn into_ripe_stats_response<F: Fn(T) -> RipeStatsResponse>(self, map: F) -> RipeStatsResponse {
        self.map(|x| x.data)
            .and_then(|x| {
                x.ok_or_else(|| Error::HttpClientErrorMessage {
                    why: "Empty data",
                    details: "RipeStats result data is empty".to_string(),
                })
            })
            .map(|x| map(x))
            .or_else::<Error, _>(|err| Ok(RipeStatsResponse::Error { err }))
            .unwrap()
    }
}

async fn sliding_window_lookups(
    futures: Vec<impl Future<Output = RipeStatsResponse>>,
    breaker: Box<dyn Fn(&RipeStatsResponse) -> bool + Send>,
    max_concurrent: usize,
) -> RipeStatsResponses {
    let responses = stream::iter(futures)
        .buffered_unordered_with_breaker(max_concurrent, breaker)
        .inspect(|response| trace!("Received RipeStats response {:?}", response))
        .collect::<Vec<_>>()
        .await;
    RipeStatsResponses { responses }
}

impl Default for RipeStats {
    fn default() -> Self {
        RipeStats::new(Default::default())
    }
}

#[derive(Debug)]
pub enum RipeStatsResponse {
    GeoLocation { geo_location: GeoLocation },
    NetworkInfo { network_info: NetworkInfo },
    Whois { whois: Whois },
    Error { err: Error },
}

macro_rules! response_data_accessor {
    ($method:ident, $out_type:ident) => {
        pub fn $method(&self) -> Option<&$out_type> {
            match *self {
                RipeStatsResponse::$out_type { $method: ref data } => Some(data),
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

impl RipeStatsResponse {
    response_data_accessor!(geo_location, GeoLocation);
    response_data_accessor!(network_info, NetworkInfo);
    response_data_accessor!(whois, Whois);
    response_data_accessor!(err, Error);

    response_is_data!(is_geo_location, geo_location);
    response_is_data!(is_network_info, network_info);
    response_is_data!(is_whois, whois);
    response_is_data!(is_err, err);
}

#[derive(Debug)]
pub struct RipeStatsResponses {
    responses: Vec<RipeStatsResponse>,
}

impl RipeStatsResponses {
    pub fn len(&self) -> usize {
        self.responses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.responses.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spectral::prelude::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_1_1_1_1() {
        let ripe_stats = RipeStats::default();

        let ip_network = IpNetwork::from_str("1.1.1.1").unwrap();
        let query = MultiQuery::multi_types(
            ip_network,
            vec![QueryType::GeoLocation, QueryType::NetworkInfo, QueryType::Whois],
        );

        let res = ripe_stats.query(query).await;

        assert_that(&res).is_ok();
        let res = res.unwrap();
        assert_that(&res.len()).is_equal_to(3);
    }

    #[tokio::test]
    async fn test_5x_1_1_1_1() {
        let ripe_stats = RipeStats::default();

        let ip_network = IpNetwork::from_str("1.1.1.1").unwrap();
        let ip_networks = vec![
            ip_network.clone(),
            ip_network.clone(),
            ip_network.clone(),
            ip_network.clone(),
            ip_network,
        ];
        let query = MultiQuery::new(
            ip_networks,
            vec![QueryType::GeoLocation, QueryType::NetworkInfo, QueryType::Whois],
        );

        let res = ripe_stats.query(query).await;

        assert_that(&res).is_ok();
        let res = res.unwrap();
        assert_that(&res.len()).is_equal_to(5 * 3);
    }
}
