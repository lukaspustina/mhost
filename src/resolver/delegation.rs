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

use crate::resolver::raw::{ROOT_SERVERS, ROOT_SERVERS_V6};

/// A DNS referral extracted from raw query results.
#[derive(Debug, Clone)]
pub struct Referral {
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
    use std::net::Ipv4Addr;

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
        let referral = Referral { ns_servers };

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
        let referral = Referral { ns_servers };

        let servers = build_server_list(&referral, |_| true);
        assert_eq!(servers.len(), 2);
    }
}
