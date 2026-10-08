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

/// Most servers a referral contributes to the next hop. A response can carry hundreds of NS and
/// glue records; each of them would be queried.
pub(crate) const MAX_REFERRAL_SERVERS: usize = 32;

/// Most NS names without glue that are resolved before the next hop.
pub(crate) const MAX_GLUELESS_NS: usize = 8;

/// Build a server list from a referral, filtering by IP address preference.
///
/// Returns `(SocketAddr, Option<ns_name>)` pairs suitable for use with raw query functions,
/// ordered by NS name and capped at [`MAX_REFERRAL_SERVERS`].
pub fn build_server_list(
    referral: &Referral,
    ip_allowed: impl Fn(IpAddr) -> bool,
) -> Vec<(SocketAddr, Option<String>)> {
    let mut ns_names: Vec<&String> = referral.ns_servers.keys().collect();
    ns_names.sort();

    ns_names
        .into_iter()
        .flat_map(|ns_name| {
            referral.ns_servers[ns_name]
                .iter()
                .filter(|ip| ip_allowed(**ip))
                .map(move |ip| (SocketAddr::new(*ip, 53), Some(ns_name.clone())))
        })
        .take(MAX_REFERRAL_SERVERS)
        .collect()
}

/// The NS names of a referral that came without glue, ordered and capped at [`MAX_GLUELESS_NS`].
pub(crate) fn glueless_names(ns_servers: &HashMap<String, Vec<IpAddr>>) -> Vec<String> {
    let mut names: Vec<String> = ns_servers
        .iter()
        .filter(|(_, ips)| ips.is_empty())
        .map(|(name, _)| name.clone())
        .collect();
    names.sort();
    names.truncate(MAX_GLUELESS_NS);
    names
}

/// Whether a referral from `current` to `next` leads closer to `qname`: `next` must lie strictly
/// below `current` and be an ancestor of (or equal to) `qname`. Anything else — a self, upward or
/// out-of-bailiwick referral — would loop or send the walk somewhere the query does not belong.
pub(crate) fn referral_makes_progress(current: &str, next: &str, qname: &str) -> bool {
    let (Ok(current), Ok(next), Ok(qname)) = (
        crate::Name::from_ascii(current),
        crate::Name::from_ascii(next),
        crate::Name::from_ascii(qname),
    ) else {
        return false;
    };
    current.zone_of(&next) && next.num_labels() > current.num_labels() && next.zone_of(&qname)
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
    fn build_server_list_is_capped_and_ordered() {
        let mut ns_servers = HashMap::new();
        for i in 0..250u8 {
            ns_servers.insert(
                format!("ns{i:03}.example.net."),
                vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, i))],
            );
        }
        let referral = Referral { ns_servers };

        let servers = build_server_list(&referral, |_| true);
        assert_eq!(servers.len(), MAX_REFERRAL_SERVERS);
        assert_eq!(servers[0].1.as_deref(), Some("ns000.example.net."));
        assert_eq!(servers, build_server_list(&referral, |_| true));
    }

    #[test]
    fn glueless_names_are_capped_and_ordered() {
        let mut ns_servers: HashMap<String, Vec<IpAddr>> = HashMap::new();
        for i in 0..100 {
            ns_servers.insert(format!("ns{i:03}.example.net."), Vec::new());
        }
        ns_servers.insert(
            "glued.example.net.".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
        );

        let names = glueless_names(&ns_servers);
        assert_eq!(names.len(), MAX_GLUELESS_NS);
        assert_eq!(names[0], "ns000.example.net.");
        assert!(!names.contains(&"glued.example.net.".to_string()));
    }

    #[test]
    fn referral_must_move_closer_to_the_query_name() {
        let progress = |current, next| referral_makes_progress(current, next, "www.example.com.");
        assert!(progress(".", "com."));
        assert!(progress("com.", "example.com."));
        assert!(progress(".", "example.com."));
        assert!(!progress("com.", "com."), "self referral");
        assert!(!progress("example.com.", "com."), "upward referral");
        assert!(!progress("com.", "evil.net."), "out of bailiwick");
        assert!(!progress("com.", "other.com."), "not an ancestor of the query name");
        assert!(!progress("com.", "not a name"), "unparsable zone");
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
