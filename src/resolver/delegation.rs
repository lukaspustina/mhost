// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Shared delegation walking utilities for DNS trace and DNSSEC chain validation.
//!
//! Provides reusable infrastructure for walking the DNS delegation chain:
//! root server address lists, referral extraction from raw responses, and
//! server list construction with IP family filtering.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::resolver::raw::{RawQueryResult, ROOT_SERVERS, ROOT_SERVERS_V6};

/// A DNS referral extracted from raw query results.
#[derive(Debug, Clone)]
pub struct Referral {
    /// The zone name this referral points to (from the authority section).
    pub zone_name: String,
    /// NS server names mapped to their known IP addresses (glue records).
    /// Empty Vec means no glue was provided and IPs need to be resolved separately.
    pub ns_servers: HashMap<String, Vec<IpAddr>>,
}

/// Build root server address list based on IP family preferences.
///
/// Returns `(SocketAddr, Option<server_name>)` pairs. Root servers have no name (None).
pub fn root_server_addrs(ipv4_only: bool, ipv6_only: bool) -> Vec<(SocketAddr, Option<String>)> {
    let mut servers = Vec::new();
    if !ipv6_only {
        servers.extend(
            ROOT_SERVERS
                .iter()
                .map(|ip| (SocketAddr::new(IpAddr::V4(*ip), 53), None)),
        );
    }
    if !ipv4_only {
        servers.extend(
            ROOT_SERVERS_V6
                .iter()
                .map(|ip| (SocketAddr::new(IpAddr::V6(*ip), 53), None)),
        );
    }
    servers
}

/// Extract a referral from raw query results.
///
/// Scans results for non-authoritative responses containing NS records in the
/// authority section. Returns the first valid referral found, aggregating glue
/// records across all responses.
pub fn extract_referral(results: &[RawQueryResult]) -> Option<Referral> {
    let mut zone_name: Option<String> = None;
    let mut ns_servers: HashMap<String, Vec<IpAddr>> = HashMap::new();

    for rqr in results {
        let response = match &rqr.result {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Skip authoritative answers -- they're final, not referrals
        if response.is_authoritative() {
            continue;
        }

        let ns_names = response.referral_ns_names();
        if ns_names.is_empty() {
            continue;
        }

        let glue = response.glue_ips();

        // Determine zone name from authority section NS record owner
        if zone_name.is_none() {
            zone_name = response
                .authority()
                .iter()
                .find(|r| r.record_type() == hickory_resolver::proto::rr::RecordType::NS)
                .map(|r| r.name().to_ascii());
        }

        // Collect glue IPs per NS name
        for ns_name in &ns_names {
            let ips: Vec<IpAddr> = glue
                .iter()
                .filter(|(name, _)| name == ns_name)
                .map(|(_, ip)| *ip)
                .collect();
            let entry = ns_servers.entry(ns_name.to_ascii()).or_default();
            for ip in ips {
                if !entry.contains(&ip) {
                    entry.push(ip);
                }
            }
        }
    }

    let zone_name = zone_name?;
    if ns_servers.is_empty() {
        return None;
    }

    Some(Referral {
        zone_name,
        ns_servers,
    })
}

/// Build a server list from a referral, filtering by IP address preference.
///
/// Returns `(SocketAddr, Option<ns_name>)` pairs suitable for use with raw query functions.
pub fn build_server_list(
    referral: &Referral,
    ip_allowed: impl Fn(IpAddr) -> bool,
) -> Vec<(SocketAddr, Option<String>)> {
    let mut servers = Vec::new();
    for (ns_name, ips) in &referral.ns_servers {
        for ip in ips {
            if ip_allowed(*ip) {
                servers.push((SocketAddr::new(*ip, 53), Some(ns_name.clone())));
            }
        }
    }
    servers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::raw::{RawQueryResult, RawResponse};
    use hickory_resolver::proto::op::{Message, MessageType};
    use hickory_resolver::proto::rr::{rdata, RData as ProtoRData, Record as ProtoRecord};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[test]
    fn root_server_addrs_dual_stack() {
        let addrs = root_server_addrs(false, false);
        assert_eq!(addrs.len(), 26); // 13 IPv4 + 13 IPv6
        assert!(addrs.iter().all(|(_, name)| name.is_none()));
    }

    #[test]
    fn root_server_addrs_ipv4_only() {
        let addrs = root_server_addrs(true, false);
        assert_eq!(addrs.len(), 13);
        assert!(addrs.iter().all(|(addr, _)| addr.ip().is_ipv4()));
    }

    #[test]
    fn root_server_addrs_ipv6_only() {
        let addrs = root_server_addrs(false, true);
        assert_eq!(addrs.len(), 13);
        assert!(addrs.iter().all(|(addr, _)| addr.ip().is_ipv6()));
    }

    #[test]
    fn build_server_list_filters_by_ip_family() {
        let mut ns_servers = HashMap::new();
        ns_servers.insert(
            "ns1.example.com.".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V6("2001:db8::1".parse().unwrap()),
            ],
        );
        let referral = Referral {
            zone_name: "example.com.".to_string(),
            ns_servers,
        };

        let servers = build_server_list(&referral, |ip| ip.is_ipv4());
        assert_eq!(servers.len(), 1);
        assert!(servers[0].0.ip().is_ipv4());
        assert_eq!(servers[0].1, Some("ns1.example.com.".to_string()));
    }

    #[test]
    fn build_server_list_allows_all() {
        let mut ns_servers = HashMap::new();
        ns_servers.insert(
            "ns1.example.com.".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V6("2001:db8::1".parse().unwrap()),
            ],
        );
        let referral = Referral {
            zone_name: "example.com.".to_string(),
            ns_servers,
        };

        let servers = build_server_list(&referral, |_| true);
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn extract_referral_from_responses() {
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 53);

        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);
        msg.set_authoritative(false);

        let ns_record = ProtoRecord::from_rdata(
            hickory_resolver::proto::rr::Name::from_ascii("com.").unwrap(),
            172800,
            ProtoRData::NS(rdata::NS(
                hickory_resolver::proto::rr::Name::from_ascii("a.gtld-servers.net.").unwrap(),
            )),
        );
        msg.add_name_server(ns_record);

        let a_record = ProtoRecord::from_rdata(
            hickory_resolver::proto::rr::Name::from_ascii("a.gtld-servers.net.").unwrap(),
            172800,
            ProtoRData::A(rdata::A(Ipv4Addr::new(192, 5, 6, 30))),
        );
        msg.add_additional(a_record);

        let response = RawResponse::new_for_test(msg, Duration::from_millis(15));
        let results = vec![RawQueryResult {
            server,
            result: Ok(response),
        }];

        let referral = extract_referral(&results).unwrap();
        assert_eq!(referral.zone_name, "com.");
        assert!(referral.ns_servers.contains_key("a.gtld-servers.net."));
        assert_eq!(
            referral.ns_servers["a.gtld-servers.net."],
            vec![IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30))]
        );
    }

    #[test]
    fn extract_referral_skips_errors() {
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53);
        let results = vec![RawQueryResult {
            server,
            result: Err(crate::resolver::raw::RawError::Timeout(Duration::from_secs(5))),
        }];

        assert!(extract_referral(&results).is_none());
    }

    #[test]
    fn extract_referral_skips_authoritative() {
        let server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53);

        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);
        msg.set_authoritative(true);

        let response = RawResponse::new_for_test(msg, Duration::from_millis(5));
        let results = vec![RawQueryResult {
            server,
            result: Ok(response),
        }];

        assert!(extract_referral(&results).is_none());
    }
}
