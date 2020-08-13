use std::convert::TryFrom;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use log::trace;
use serde::Deserialize;

use crate::services::server_lists::{PublicDns, ServerListDownloader};
use crate::nameserver::NameServerConfig;
use crate::services::{Error, Result};

static BASE_URI: &str = &"https://public-dns.info/nameserver";

#[derive(Deserialize)]
pub struct NameServer {
    pub ip: String,
    pub name: String,
    pub country_id: String,
    pub city: Option<String>,
    pub version: Option<String>,
    pub error: Option<String>,
    pub dnssec: Option<bool>,
    pub reliability: f32,
    pub checked_at: String,
    pub created_at: String,
}

pub async fn download(downloader: ServerListDownloader, spec: &PublicDns) -> Result<Vec<NameServerConfig>> {
    let url = if let Some(country) = spec.country() {
        format!("{}/{}.json", BASE_URI, country)
    } else {
        format!("{}s-all.json", BASE_URI)
    };

    trace!("Downloading servers from url '{}'", &url);

    let res = downloader
        .http_client
        .get(&url)
        // TODO: This should come from opts
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| Error::HttpClientError {
            why: "call failed",
            source: e,
        })?;

    if !res.status().is_success() {
        return Err(Error::HttpClientErrorMessage {
            why: "unexpected status code",
            details: format!("status code: {}", res.status()),
        });
    }

    let body = res.text().await.map_err(|e| Error::HttpClientError {
        why: "reading body failed",
        source: e,
    })?;

    let servers = serde_json::from_str::<Vec<NameServer>>(&body).map_err(Error::from)?;
    let nameserver_configs: Vec<NameServerConfig> = servers
        .into_iter()
        .map(TryFrom::try_from)
        .map(Result::ok)
        .flatten()
        .collect();

    Ok(nameserver_configs)
}

impl TryFrom<NameServer> for NameServerConfig {
    type Error = Error;

    fn try_from(ns: NameServer) -> std::result::Result<Self, Self::Error> {
        let ip_addr = IpAddr::from_str(&ns.ip)
            .map_err(|_| Error::ParserError {
                what: ns.ip,
                to: "IpAddr",
                why: "is not a valid IP address".to_string(),
            })?;
        Ok(
            NameServerConfig::udp_with_name((ip_addr, 53), "public-dns".to_string())
        )
    }
}
