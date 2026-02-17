// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::convert::TryFrom;
use std::net::IpAddr;
use std::str::FromStr;

use serde::Deserialize;
use tracing::trace;

use crate::nameserver::NameServerConfig;
use crate::services::server_lists::{PublicDns, ServerListDownloader};
use crate::services::{Error, Result};

static BASE_URI: &str = "https://public-dns.info/nameserver";

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
        .timeout(downloader.opts.timeout)
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

    const MAX_RESPONSE_SIZE: u64 = 50 * 1024 * 1024;
    if let Some(len) = res.content_length() {
        if len > MAX_RESPONSE_SIZE {
            return Err(Error::HttpClientErrorMessage {
                why: "response too large",
                details: format!("response size {} bytes exceeds limit of {} bytes", len, MAX_RESPONSE_SIZE),
            });
        }
    }

    let body = res.text().await.map_err(|e| Error::HttpClientError {
        why: "reading body failed",
        source: e,
    })?;

    if body.len() as u64 > MAX_RESPONSE_SIZE {
        return Err(Error::HttpClientErrorMessage {
            why: "response too large",
            details: format!("response size {} bytes exceeds limit of {} bytes", body.len(), MAX_RESPONSE_SIZE),
        });
    }

    let servers = serde_json::from_str::<Vec<NameServer>>(&body).map_err(Error::from)?;
    #[allow(clippy::map_flatten)]
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
        let ip_addr = IpAddr::from_str(&ns.ip).map_err(|e| Error::ParserError {
            what: ns.ip,
            to: "IpAddr",
            why: format!("is not a valid IP address: {}", e),
        })?;
        Ok(NameServerConfig::udp_with_name((ip_addr, 53), "public-dns".to_string()))
    }
}
