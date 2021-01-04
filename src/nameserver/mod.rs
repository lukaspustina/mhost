use std::fmt;
use std::net::{IpAddr, SocketAddr};

use nom::lib::std::str::FromStr;
use resolv_conf::ScopedIp;
use serde::Serialize;

use crate::Result;
use crate::{system_config, Error};
use std::path::Path;

pub mod load;
mod parser;
pub mod predefined;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize)]
pub enum Protocol {
    Udp,
    Tcp,
    Https,
    Tls,
}

impl FromStr for Protocol {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "udp" => Ok(Protocol::Udp),
            "tcp" => Ok(Protocol::Tcp),
            "https" => Ok(Protocol::Https),
            "tls" => Ok(Protocol::Tls),
            _ => Err(Error::ParserError {
                what: s.to_string(),
                to: "Protocol",
                why: "invalid protocol".to_string(),
            }),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub enum NameServerConfig {
    Udp {
        protocol: Protocol,
        ip_addr: IpAddr,
        port: u16,
        name: Option<String>,
    },
    Tcp {
        protocol: Protocol,
        ip_addr: IpAddr,
        port: u16,
        name: Option<String>,
    },
    Tls {
        protocol: Protocol,
        ip_addr: IpAddr,
        port: u16,
        spki: String,
        name: Option<String>,
    },
    Https {
        protocol: Protocol,
        ip_addr: IpAddr,
        port: u16,
        spki: String,
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
            protocol: Protocol::Udp,
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
            protocol: Protocol::Tcp,
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            name: name.into(),
        }
    }

    pub fn tls<T: Into<SocketAddr>, S: Into<String>>(socket_addr: T, spki: S) -> Self {
        NameServerConfig::tls_with_name(socket_addr, spki, None)
    }

    pub fn tls_with_name<T: Into<SocketAddr>, S: Into<String>, U: Into<Option<String>>>(
        socket_addr: T,
        spki: S,
        name: U,
    ) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Tls {
            protocol: Protocol::Tls,
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            spki: spki.into(),
            name: name.into(),
        }
    }

    pub fn https<T: Into<SocketAddr>, S: Into<String>>(socket_addr: T, spki: S) -> Self {
        NameServerConfig::https_with_name(socket_addr, spki, None)
    }

    pub fn https_with_name<T: Into<SocketAddr>, S: Into<String>, U: Into<Option<String>>>(
        socket_addr: T,
        spki: S,
        name: U,
    ) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Https {
            protocol: Protocol::Https,
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            spki: spki.into(),
            name: name.into(),
        }
    }

    pub fn protocol(&self) -> Protocol {
        match self {
            NameServerConfig::Udp { .. } => Protocol::Udp,
            NameServerConfig::Tcp { .. } => Protocol::Tcp,
            NameServerConfig::Https { .. } => Protocol::Https,
            NameServerConfig::Tls { .. } => Protocol::Tls,
        }
    }
}

impl fmt::Display for NameServerConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            NameServerConfig::Udp {
                protocol: _,
                ip_addr,
                port,
                name,
            } => format!("udp:{}:{}{}", format_ip_addr(ip_addr), port, format_name(name)),
            NameServerConfig::Tcp {
                protocol: _,
                ip_addr,
                port,
                name,
            } => format!("tcp:{}:{}{}", format_ip_addr(ip_addr), port, format_name(name)),
            NameServerConfig::Tls {
                protocol: _,
                ip_addr,
                port,
                spki,
                name,
            } => format!(
                "tls:{}:{},spki={}{}",
                format_ip_addr(ip_addr),
                port,
                spki,
                format_name(name)
            ),
            NameServerConfig::Https {
                protocol: _,
                ip_addr,
                port,
                spki,
                name,
            } => format!(
                "https:{}:{},spki={}{}",
                format_ip_addr(ip_addr),
                port,
                spki,
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
        .unwrap_or_else(|| "".to_string())
}

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

#[doc(hidden)]
impl From<Protocol> for trust_dns_resolver::config::Protocol {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Udp => trust_dns_resolver::config::Protocol::Udp,
            Protocol::Tcp => trust_dns_resolver::config::Protocol::Tcp,
            Protocol::Https => trust_dns_resolver::config::Protocol::Https,
            Protocol::Tls => trust_dns_resolver::config::Protocol::Tls,
        }
    }
}

#[doc(hidden)]
impl From<NameServerConfig> for trust_dns_resolver::config::NameServerConfig {
    fn from(config: NameServerConfig) -> Self {
        match config {
            NameServerConfig::Udp {
                protocol,
                ip_addr,
                port,
                name: _,
            } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: protocol.into(),
                trust_nx_responses: true,
                tls_dns_name: None,
                tls_config: None,
            },
            NameServerConfig::Tcp {
                protocol,
                ip_addr,
                port,
                name: _,
            } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: protocol.into(),
                trust_nx_responses: true,
                tls_dns_name: None,
                tls_config: None,
            },
            NameServerConfig::Tls {
                protocol,
                ip_addr,
                port,
                spki,
                name: _,
            } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: protocol.into(),
                trust_nx_responses: true,
                tls_dns_name: Some(spki),
                tls_config: None,
            },
            NameServerConfig::Https {
                protocol,
                ip_addr,
                port,
                spki,
                name: _,
            } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: protocol.into(),
                trust_nx_responses: true,
                tls_dns_name: Some(spki),
                tls_config: None,
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use spectral::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn display_tls() {
        let nsc = NameServerConfig::tls_with_name(
            (Ipv4Addr::new(104, 16, 249, 249), 853),
            "cloudflare-dns.com".to_string(),
            "Cloudflare".to_string(),
        );
        let expected = "tls:104.16.249.249:853,spki=cloudflare-dns.com,name=Cloudflare";

        let display = nsc.to_string();

        asserting("display equals parsable string")
            .that(&display.as_str())
            .is_equal_to(expected);
    }

    #[test]
    fn display_https() {
        let nsc = NameServerConfig::https_with_name(
            (Ipv6Addr::from_str("2606:4700::6810:f8f9").unwrap(), 443),
            "cloudflare-dns.com".to_string(),
            "Cloudflare".to_string(),
        );
        let expected = "https:[2606:4700::6810:f8f9]:443,spki=cloudflare-dns.com,name=Cloudflare";

        let display = nsc.to_string();

        asserting("display equals parsable string")
            .that(&display.as_str())
            .is_equal_to(expected);
    }
}
