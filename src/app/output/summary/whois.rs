// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::collections::HashMap;

use tabwriter::TabWriter;

use super::*;
use crate::app::output::styles::ITEMAZATION_PREFIX;
use crate::services::whois::{GeoLocation, NetworkInfo, Whois, WhoisResponse, WhoisResponses};
use ipnetwork::IpNetwork;

impl SummaryFormatter for WhoisResponses {
    fn output<W: Write>(&self, writer: &mut W, opts: &SummaryOptions) -> Result<()> {
        let mut responses_by_ip_network = responses_by_ip_network(self);
        let mut tw = TabWriter::new(vec![]);

        for (ip_network, mut responses) in responses_by_ip_network.drain() {
            output_responses(&mut tw, ip_network, &mut responses, opts)?;
        }

        let text_buffer = tw.into_inner().map_err(|_| Error::InternalError {
            msg: "finish TabWriter buffer",
        })?;
        let out = String::from_utf8(text_buffer).map_err(|_| Error::InternalError {
            msg: "convert TabWriter buffer to output",
        })?;
        write!(writer, "{}", out)?;

        Ok(())
    }
}

fn output_responses<W: Write>(
    writer: &mut W,
    ip_network: &IpNetwork,
    responses: &mut [&WhoisResponse],
    opts: &SummaryOptions,
) -> Result<()> {
    responses.sort_by(order_by_ordinal);

    let strs: Vec<_> = responses.iter_mut().map(|x| x.render(opts)).collect();
    writeln!(writer, " {} {}\t{}", &*ITEMAZATION_PREFIX, ip_network, strs.join(", "))?;

    Ok(())
}

fn responses_by_ip_network(responses: &WhoisResponses) -> HashMap<&IpNetwork, Vec<&WhoisResponse>> {
    let mut map = HashMap::new();
    for response in responses.iter() {
        let set = map.entry(response.resource()).or_insert_with(Vec::new);
        set.push(response);
    }

    map
}

impl Rendering for WhoisResponse {
    fn render(&self, opts: &SummaryOptions) -> String {
        match self {
            WhoisResponse::GeoLocation { ref geo_location, .. } => render_geo_location(geo_location, opts),
            WhoisResponse::NetworkInfo { ref network_info, .. } => render_network_info(network_info, opts),
            WhoisResponse::Whois { ref whois, .. } => render_whois(whois, opts),
            WhoisResponse::Error { .. } => "-".to_string(),
        }
    }
}

fn render_geo_location(geo_location: &GeoLocation, _opts: &SummaryOptions) -> String {
    let geo_location = geo_location
        .located_resources()
        .iter()
        .map(|resource| {
            resource
                .locations()
                .iter()
                .map(|l| format!("{}, {}", l.city(), l.country()))
                .next()
                .unwrap_or_else(|| "-".to_string())
        })
        .next()
        .unwrap_or_else(|| "-".to_string());

    format!("Location {}", styles::EMPH.paint(geo_location))
}

fn render_network_info(network_info: &NetworkInfo, _opts: &SummaryOptions) -> String {
    format!(
        "AS {}, Prefix {}",
        styles::EMPH.paint(network_info.asns().join(", ")),
        styles::EMPH.paint(network_info.prefix())
    )
}

fn render_whois(whois: &Whois, _opts: &SummaryOptions) -> String {
    format!(
        "Net name {}, Org {}, Authority {}",
        styles::EMPH.paint(whois.net_name().map(|x| x.as_str()).unwrap_or("-")),
        styles::EMPH.paint(whois.organization().map(|x| x.as_str()).unwrap_or("-")),
        styles::EMPH.paint(whois.source().map(|x| x.to_string()).unwrap_or_else(|| "-".to_string())),
    )
}
