use core::str::FromStr;
use std::slice::Iter;
use std::sync::Arc;

use futures::stream::{self, StreamExt};
use futures::Future;
use nom::Err;
use tokio::task;
use tracing::{debug, trace};

use crate::nameserver::NameServerConfig;
use crate::services::{Error, Result};
use crate::utils::buffer_unordered_with_breaker::StreamExtBufferUnorderedWithBreaker;
use nom::lib::std::fmt::Formatter;
use std::fmt;
use std::time::Duration;

mod opennic;
mod parser;
mod public_dns;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ServerListSpec {
    PublicDns { spec: PublicDns },
    OpenNic { spec: OpenNic },
}

impl ServerListSpec {
    pub fn public_dns(&self) -> Option<&PublicDns> {
        match &self {
            ServerListSpec::PublicDns { spec } => Some(spec),
            _ => None,
        }
    }

    pub fn opennic(&self) -> Option<&OpenNic> {
        match &self {
            ServerListSpec::OpenNic { spec } => Some(spec),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicDns {
    country: Option<String>,
}

impl Default for PublicDns {
    fn default() -> Self {
        PublicDns { country: None }
    }
}

impl PublicDns {
    pub fn country(&self) -> Option<&String> {
        self.country.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OpenNic {
    anon: bool,
    number: usize,
    reliability: usize,
    ipv: IPV,
}

impl Default for OpenNic {
    fn default() -> Self {
        OpenNic {
            anon: false,
            number: 10,
            reliability: 95,
            ipv: IPV::All,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum IPV {
    V4,
    V6,
    All,
}

impl FromStr for IPV {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "4" => Ok(IPV::V4),
            "6" => Ok(IPV::V6),
            "all" => Ok(IPV::All),
            _ => Err(Self::Err::ParserError {
                what: s.to_string(),
                to: "IPV",
                why: "unsupported IP version".to_string(),
            }),
        }
    }
}

impl fmt::Display for IPV {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = match self {
            IPV::V4 => "4",
            IPV::V6 => "6",
            IPV::All => "all",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone)]
pub struct ServerListDownloaderOpts {
    max_concurrent_requests: usize,
    abort_on_error: bool,
    timeout: Duration,
}

impl Default for ServerListDownloaderOpts {
    fn default() -> Self {
        ServerListDownloaderOpts::new(8, true, Duration::from_secs(5))
    }
}

impl ServerListDownloaderOpts {
    pub fn new(max_concurrent_requests: usize, abort_on_error: bool, timeout: Duration) -> ServerListDownloaderOpts {
        ServerListDownloaderOpts {
            max_concurrent_requests,
            abort_on_error,
            timeout,
        }
    }
}

#[derive(Clone)]
pub struct ServerListDownloader {
    http_client: Arc<reqwest::Client>,
    opts: Arc<ServerListDownloaderOpts>,
}

impl Default for ServerListDownloader {
    fn default() -> Self {
        ServerListDownloader::new(ServerListDownloaderOpts::default())
    }
}

impl ServerListDownloader {
    pub fn new(opts: ServerListDownloaderOpts) -> ServerListDownloader {
        ServerListDownloader {
            http_client: Arc::new(reqwest::Client::new()),
            opts: Arc::new(opts),
        }
    }

    pub async fn download<I: IntoIterator<Item = ServerListSpec>>(
        &self,
        server_list_specs: I,
    ) -> Result<DownloadResponses> {
        let breaker = create_breaker(self.opts.abort_on_error);

        let futures: Vec<_> = server_list_specs
            .into_iter()
            .map(|spec| single_download(self.clone(), spec))
            .collect();
        let downloads = sliding_window_lookups(futures, breaker, self.opts.max_concurrent_requests);
        let responses = task::spawn(downloads).await?;

        Ok(responses)
    }
}

fn create_breaker(on_error: bool) -> Box<dyn Fn(&DownloadResponse) -> bool + Send> {
    Box::new(move |r: &DownloadResponse| r.is_err() && on_error)
}

async fn single_download(downloader: ServerListDownloader, server_list_spec: ServerListSpec) -> DownloadResponse {
    let res = match server_list_spec {
        ServerListSpec::OpenNic { ref spec } => {
            let list = opennic::download(downloader, spec).await;
            debug!("Download for {:?} is {}", spec, if list.is_ok() { "ok" } else { "err" });
            list
        }
        ServerListSpec::PublicDns { ref spec } => {
            let list = public_dns::download(downloader, spec).await;
            debug!("Download for {:?} is {}", spec, if list.is_ok() { "ok" } else { "err" });
            list
        }
    }
    .into();
    trace!("DownloadResponse: {:?}", res);

    res
}

async fn sliding_window_lookups(
    futures: Vec<impl Future<Output = DownloadResponse>>,
    breaker: Box<dyn Fn(&DownloadResponse) -> bool + Send>,
    max_concurrent: usize,
) -> DownloadResponses {
    let responses = stream::iter(futures)
        .buffered_unordered_with_breaker(max_concurrent, breaker)
        .inspect(|_| trace!("Downloaded nameserver configs"))
        .collect::<Vec<_>>()
        .await;

    DownloadResponses { responses }
}

#[derive(Debug)]
pub enum DownloadResponse {
    Download { nameserver_configs: Vec<NameServerConfig> },
    Error { err: Error },
}

impl DownloadResponse {
    pub fn download(&self) -> Option<&Vec<NameServerConfig>> {
        match &self {
            DownloadResponse::Download { ref nameserver_configs } => Some(nameserver_configs),
            _ => None,
        }
    }

    pub fn is_download(&self) -> bool {
        self.download().is_some()
    }

    pub fn err(&self) -> Option<&Error> {
        match &self {
            DownloadResponse::Error { ref err } => Some(err),
            _ => None,
        }
    }

    pub fn is_err(&self) -> bool {
        self.err().is_some()
    }
}

#[derive(Debug)]
pub struct DownloadResponses {
    responses: Vec<DownloadResponse>,
}

impl DownloadResponses {
    pub fn len(&self) -> usize {
        self.responses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.responses.is_empty()
    }

    pub fn iter(&self) -> Iter<DownloadResponse> {
        self.responses.iter()
    }

    pub fn nameserver_configs(&self) -> impl Iterator<Item = &NameServerConfig> {
        self.responses
            .iter()
            .map(|x| x.download())
            .flatten()
            .map(|x| x.iter())
            .flatten()
    }

    pub fn err(&self) -> impl Iterator<Item = &Error> {
        self.responses.iter().map(|x| x.err()).flatten()
    }
}

impl From<Result<Vec<NameServerConfig>>> for DownloadResponse {
    fn from(res: Result<Vec<NameServerConfig>>) -> Self {
        match res {
            Ok(nameserver_configs) => DownloadResponse::Download { nameserver_configs },
            Err(err) => DownloadResponse::Error { err },
        }
    }
}

impl FromStr for ServerListSpec {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match parser::parse_server_list_spec(s) {
            Ok((_, result)) => Ok(result),
            Err(Err::Incomplete(_)) => Err(Error::ParserError {
                what: s.to_string(),
                to: "ServerListSpec",
                why: "input is incomplete".to_string(),
            }),
            Err(Err::Error((what, why))) | Err(Err::Failure((what, why))) => Err(Error::ParserError {
                what: what.to_string(),
                to: "ServerListSpec",
                why: why.description().to_string(),
            }),
        }
    }
}
