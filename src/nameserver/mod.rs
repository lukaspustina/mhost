// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Nameserver configuration and transport protocol types.
//!
//! [`NameServerConfig`] describes how to reach a DNS nameserver, supporting four
//! transport protocols: UDP, TCP, TLS (DNS-over-TLS), and HTTPS (DNS-over-HTTPS).
//! Use the factory methods ([`udp`](NameServerConfig::udp), [`tcp`](NameServerConfig::tcp),
//! [`tls`](NameServerConfig::tls), [`https`](NameServerConfig::https)) to create
//! configurations.
//!
//! The [`predefined`] submodule provides preconfigured nameservers for well-known
//! public DNS providers (Cloudflare, Google, Quad9, Mullvad, Wikimedia, DNS4EU).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use resolv_conf::ScopedIp;
use serde::Serialize;
use std::str::FromStr;

use crate::Result;
use crate::{system_config, Error};
use std::path::Path;

pub mod load;
mod parser;
pub mod predefined;

/// DNS transport protocol.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
pub enum Protocol {
    /// Plain UDP (port 53).
    Udp,
    /// Plain TCP (port 53).
    Tcp,
    /// DNS-over-TLS (port 853).
    #[cfg(feature = "dot")]
    Tls,
    /// DNS-over-HTTPS (port 443).
    #[cfg(feature = "doh")]
    Https,
}

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "udp" => Ok(Protocol::Udp),
            "tcp" => Ok(Protocol::Tcp),
            #[cfg(feature = "dot")]
            "tls" => Ok(Protocol::Tls),
            #[cfg(feature = "doh")]
            "https" => Ok(Protocol::Https),
            _ => Err(Error::ParserError {
                what: s.to_string(),
                to: "Protocol",
                why: "invalid protocol".to_string(),
            }),
        }
    }
}

/// Configuration for a DNS nameserver, including transport protocol and address.
///
/// Each variant carries the IP address, port, and an optional human-readable name.
/// The transport protocol is determined by the enum variant itself.
/// TLS and HTTPS variants additionally carry the TLS hostname for certificate validation.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub enum NameServerConfig {
    Udp {
        ip_addr: IpAddr,
        port: u16,
        name: Option<String>,
    },
    Tcp {
        ip_addr: IpAddr,
        port: u16,
        name: Option<String>,
    },
    #[cfg(feature = "dot")]
    Tls {
        ip_addr: IpAddr,
        port: u16,
        /// The TLS hostname, CN
        tls_auth_name: String,
        name: Option<String>,
    },
    #[cfg(feature = "doh")]
    Https {
        ip_addr: IpAddr,
        port: u16,
        /// The TLS hostname, CN
        tls_auth_name: String,
        name: Option<String>,
    },
}

impl NameServerConfig {
    pub fn udp<T: Into<SocketAddr>>(socket_addr: T) -> Self {
        NameServerConfig::udp_with_name(socket_addr, None)
    }

    pub fn udp_with_name<T: Into<SocketAddr>, S: Into<Option<String>>>(socket_addr: T, name: S) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Udp {
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            name: name.into(),
        }
    }

    pub fn tcp<T: Into<SocketAddr>>(socket_addr: T) -> Self {
        NameServerConfig::tcp_with_name(socket_addr, None)
    }

    pub fn tcp_with_name<T: Into<SocketAddr>, S: Into<Option<String>>>(socket_addr: T, name: S) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Tcp {
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            name: name.into(),
        }
    }

    #[cfg(feature = "dot")]
    pub fn tls<T: Into<SocketAddr>, S: Into<String>>(socket_addr: T, tls_auth_name: S) -> Self {
        NameServerConfig::tls_with_name(socket_addr, tls_auth_name, None)
    }

    #[cfg(feature = "dot")]
    pub fn tls_with_name<T: Into<SocketAddr>, S: Into<String>, U: Into<Option<String>>>(
        socket_addr: T,
        tls_auth_name: S,
        name: U,
    ) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Tls {
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            tls_auth_name: tls_auth_name.into(),
            name: name.into(),
        }
    }

    #[cfg(feature = "doh")]
    pub fn https<T: Into<SocketAddr>, S: Into<String>>(socket_addr: T, tls_auth_name: S) -> Self {
        NameServerConfig::https_with_name(socket_addr, tls_auth_name, None)
    }

    #[cfg(feature = "doh")]
    pub fn https_with_name<T: Into<SocketAddr>, S: Into<String>, U: Into<Option<String>>>(
        socket_addr: T,
        tls_auth_name: S,
        name: U,
    ) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Https {
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            tls_auth_name: tls_auth_name.into(),
            name: name.into(),
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            NameServerConfig::Udp { .. } => Protocol::Udp,
            NameServerConfig::Tcp { .. } => Protocol::Tcp,
            #[cfg(feature = "dot")]
            NameServerConfig::Tls { .. } => Protocol::Tls,
            #[cfg(feature = "doh")]
            NameServerConfig::Https { .. } => Protocol::Https,
        }
    }

    pub fn ip_addr(&self) -> IpAddr {
        match self {
            NameServerConfig::Udp { ip_addr, .. } | NameServerConfig::Tcp { ip_addr, .. } => *ip_addr,
            #[cfg(feature = "dot")]
            NameServerConfig::Tls { ip_addr, .. } => *ip_addr,
            #[cfg(feature = "doh")]
            NameServerConfig::Https { ip_addr, .. } => *ip_addr,
        }
    }

    /// Whether this nameserver is a public target: a globally routable address and a non-zero
    /// port. False for loopback, private (RFC 1918, ULA), link-local (incl. cloud metadata at
    /// 169.254.169.254), shared (CGNAT), documentation, benchmarking, multicast, broadcast,
    /// reserved and unspecified addresses, and local-use NAT64; v4-mapped, NAT64 and 6to4
    /// addresses are judged by the embedded IPv4 address.
    pub fn is_global(&self) -> bool {
        self.port() != 0 && is_global_ip(self.ip_addr())
    }

    pub fn port(&self) -> u16 {
        match self {
            NameServerConfig::Udp { port, .. } | NameServerConfig::Tcp { port, .. } => *port,
            #[cfg(feature = "dot")]
            NameServerConfig::Tls { port, .. } => *port,
            #[cfg(feature = "doh")]
            NameServerConfig::Https { port, .. } => *port,
        }
    }
}

impl fmt::Display for NameServerConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            NameServerConfig::Udp { ip_addr, port, name } => {
                format!("udp:{}:{}{}", format_ip_addr(ip_addr), port, format_name(name))
            }
            NameServerConfig::Tcp { ip_addr, port, name } => {
                format!("tcp:{}:{}{}", format_ip_addr(ip_addr), port, format_name(name))
            }
            #[cfg(feature = "dot")]
            NameServerConfig::Tls {
                ip_addr,
                port,
                tls_auth_name,
                name,
            } => format!(
                "tls:{}:{},tls_auth_name={}{}",
                format_ip_addr(ip_addr),
                port,
                tls_auth_name,
                format_name(name)
            ),
            #[cfg(feature = "doh")]
            NameServerConfig::Https {
                ip_addr,
                port,
                tls_auth_name,
                name,
            } => format!(
                "https:{}:{},tls_auth_name={}{}",
                format_ip_addr(ip_addr),
                port,
                tls_auth_name,
                format_name(name)
            ),
        };
        fmt.write_str(&str)
    }
}

fn format_ip_addr(ip_addr: &IpAddr) -> String {
    match ip_addr {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{}]", ip),
    }
}

fn format_name(name: &Option<String>) -> String {
    name.as_ref()
        .map(|name| format!(",name={}", name))
        .unwrap_or("".to_string())
}

/// A collection of [`NameServerConfig`]s, typically loaded from system configuration or predefined lists.
#[derive(Debug)]
pub struct NameServerConfigGroup {
    configs: Vec<NameServerConfig>,
}

impl NameServerConfigGroup {
    pub fn new(configs: Vec<NameServerConfig>) -> NameServerConfigGroup {
        NameServerConfigGroup { configs }
    }

    pub fn from_system_config() -> Result<Self> {
        let config_group: NameServerConfigGroup = system_config::load_from_system_config()?;
        Ok(config_group)
    }

    pub fn from_system_config_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let opts = system_config::load_from_system_config_path(path)?;
        Ok(opts)
    }

    /// Merges this `NameServerConfigGroup` with another
    pub fn merge(&mut self, other: Self) {
        self.configs.extend(other.configs)
    }

    pub fn len(&self) -> usize {
        self.configs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }
}

impl IntoIterator for NameServerConfigGroup {
    type Item = NameServerConfig;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.configs.into_iter()
    }
}

#[doc(hidden)]
impl From<resolv_conf::Config> for NameServerConfigGroup {
    fn from(config: resolv_conf::Config) -> Self {
        let tcp = config.use_vc;
        let namesservers = config
            .nameservers
            .into_iter()
            .map(|x| match x {
                ScopedIp::V4(ipv4) if tcp => NameServerConfig::tcp_with_name((ipv4, 53), "System".to_string()),
                ScopedIp::V4(ipv4) => NameServerConfig::udp_with_name((ipv4, 53), "System".to_string()),
                ScopedIp::V6(ipv6, _) if tcp => NameServerConfig::tcp_with_name((ipv6, 53), "System".to_string()),
                ScopedIp::V6(ipv6, _) => NameServerConfig::udp_with_name((ipv6, 53), "System".to_string()),
            })
            .collect();

        NameServerConfigGroup::new(namesservers)
    }
}

impl NameServerConfig {
    pub(crate) fn to_proto(&self) -> hickory_resolver::config::NameServerConfig {
        let config = self;
        use hickory_resolver::config::{ConnectionConfig, ProtocolConfig};
        let mut connection = match &config {
            NameServerConfig::Udp { .. } => ConnectionConfig::new(ProtocolConfig::Udp),
            NameServerConfig::Tcp { .. } => ConnectionConfig::new(ProtocolConfig::Tcp),
            #[cfg(feature = "dot")]
            NameServerConfig::Tls { tls_auth_name, .. } => ConnectionConfig::tls(tls_auth_name.as_str().into()),
            #[cfg(feature = "doh")]
            NameServerConfig::Https { tls_auth_name, .. } => {
                ConnectionConfig::https(tls_auth_name.as_str().into(), None)
            }
        };
        connection.port = config.port();
        hickory_resolver::config::NameServerConfig::new(config.ip_addr(), true, vec![connection])
    }
}

pub(crate) fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_global_ipv4(ip),
        IpAddr::V6(ip) => is_global_ipv6(ip),
    }
}

fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0 // "this network", incl. unspecified
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || (a == 100 && (64..128).contains(&b)) // shared address space (CGNAT)
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || ip.is_documentation()
        || (a == 198 && (18..20).contains(&b)) // benchmarking
        || ip.is_multicast()
        || a >= 240) // reserved, incl. broadcast
}

fn is_global_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_global_ipv4(v4);
    }
    let segments = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96 carries the IPv4 target in its last 32 bits.
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [.., hi, lo] = segments;
        return is_global_ipv4(Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo)));
    }
    // 6to4 2002::/16 carries the IPv4 relay target in bits 16..48.
    if segments[0] == 0x2002 {
        return is_global_ipv4(Ipv4Addr::from((u32::from(segments[1]) << 16) | u32::from(segments[2])));
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00 // unique local
        || (segments[0] & 0xffc0) == 0xfe80 // link-local
        || segments[..3] == [0x64, 0xff9b, 1] // local-use NAT64 64:ff9b:1::/48
        || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
        || (segments[0] == 0x3fff && segments[1] < 0x1000) // documentation 3fff::/20
        || segments[..3] == [0x2001, 0x0002, 0] // benchmarking 2001:2::/48
        || segments[..4] == [0x100, 0, 0, 0]) // discard-only
}

#[cfg(test)]
mod test {
    use super::*;

    use spectral::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn non_global_targets() {
        for target in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.251",
            "192.0.2.1",
            "198.18.0.1",
            "240.0.0.1",
            "[::1]",
            "[::]",
            "[fd00::1]",
            "[fe80::1]",
            "[ff02::fb]",
            "[2001:db8::1]",
            "[::ffff:7f00:1]",
            "[::ffff:a9fe:a9fe]",
            "[64:ff9b::a00:1]",
            "[64:ff9b:1::a00:1]",
            "[2001:2::1]",
            "[3fff::1]",
            "[2002:a00:1::1]",
            "[2002:7f00:1::1]",
        ] {
            let config = NameServerConfig::from_str(&format!("udp:{target}:53")).unwrap();
            assert!(!config.is_global(), "{target} must not be global");
        }
    }

    #[test]
    fn global_targets() {
        for target in [
            "8.8.8.8",
            "1.1.1.1",
            "[2001:4860:4860::8888]",
            "[::ffff:808:808]",
            "[64:ff9b::808:808]",
            "[2002:808:808::1]",
            "[3ffe:1000::1]",
            "[3fff:1000::1]",
        ] {
            let config = NameServerConfig::from_str(&format!("udp:{target}:53")).unwrap();
            assert!(config.is_global(), "{target} must be global");
        }
    }

    #[test]
    fn port_zero_is_not_global() {
        let config = NameServerConfig::udp((Ipv4Addr::new(8, 8, 8, 8), 0));
        assert!(!config.is_global());
    }

    #[cfg(feature = "dot")]
    #[test]
    fn display_tls() {
        let nsc = NameServerConfig::tls_with_name(
            (Ipv4Addr::new(104, 16, 249, 249), 853),
            "cloudflare-dns.com".to_string(),
            "Cloudflare".to_string(),
        );
        let expected = "tls:104.16.249.249:853,tls_auth_name=cloudflare-dns.com,name=Cloudflare";

        let display = nsc.to_string();

        asserting("display equals parsable string")
            .that(&display.as_str())
            .is_equal_to(expected);
    }

    #[cfg(feature = "doh")]
    #[test]
    fn display_https() {
        let nsc = NameServerConfig::https_with_name(
            (Ipv6Addr::from_str("2606:4700::6810:f8f9").unwrap(), 443),
            "cloudflare-dns.com".to_string(),
            "Cloudflare".to_string(),
        );
        let expected = "https:[2606:4700::6810:f8f9]:443,tls_auth_name=cloudflare-dns.com,name=Cloudflare";

        let display = nsc.to_string();

        asserting("display equals parsable string")
            .that(&display.as_str())
            .is_equal_to(expected);
    }

    #[test]
    fn ip_addr_accessor_ipv4() {
        let nsc = NameServerConfig::udp((Ipv4Addr::new(1, 1, 1, 1), 53));
        assert_eq!(nsc.ip_addr(), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(nsc.ip_addr().is_ipv4());
    }

    #[test]
    fn ip_addr_accessor_ipv6() {
        let nsc = NameServerConfig::tcp((Ipv6Addr::LOCALHOST, 53));
        assert_eq!(nsc.ip_addr(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(nsc.ip_addr().is_ipv6());
    }
}
