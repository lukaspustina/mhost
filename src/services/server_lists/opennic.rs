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
use crate::services::server_lists::{OpenNic, ServerListDownloader};
use crate::services::{Error, Result};
use crate::utils::deserialize::des_f32_from_string;

static BASE_URI: &str = "https://api.opennic.org/geoip/?json";

#[derive(Deserialize)]
pub struct NameServer {
    pub host: String,
    pub ip: String,
    #[serde(deserialize_with = "des_f32_from_string", rename = "stat")]
    pub reliability: f32,
}

/// Cf. https://wiki.opennic.org/api/geoip
pub async fn download(downloader: ServerListDownloader, spec: &OpenNic) -> Result<Vec<NameServerConfig>> {
    trace!("Downloading servers from OpenNic");

    let params = [
        ("res", &spec.number.to_string()),
        ("pct", &spec.reliability.to_string()),
        ("ipv", &spec.ipv.to_string()),
        ("anon", &spec.anon.to_string()),
    ];

    let res = downloader
        .http_client
        .get(BASE_URI)
        .query(&params)
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
                details: format!(
                    "response size {} bytes exceeds limit of {} bytes",
                    len, MAX_RESPONSE_SIZE
                ),
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
            details: format!(
                "response size {} bytes exceeds limit of {} bytes",
                body.len(),
                MAX_RESPONSE_SIZE
            ),
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
        Ok(NameServerConfig::udp_with_name((ip_addr, 53), "opennic".to_string()))
    }
}
