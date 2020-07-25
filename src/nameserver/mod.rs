use std::fmt;
use std::net::{IpAddr, SocketAddr};

use resolv_conf::ScopedIp;
use serde::Serialize;
use trust_dns_resolver::config::Protocol;

use crate::system_config;
use crate::Result;

mod parser;
pub mod predefined;

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
    Tls {
        ip_addr: IpAddr,
        port: u16,
        spki: String,
        name: Option<String>,
    },
    Https {
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
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            spki: spki.into(),
            name: name.into(),
        }
    }
}

impl fmt::Display for NameServerConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            NameServerConfig::Udp { ip_addr, port, name } => format!("udp:{}:{}{}", ip_addr, port, format_name(name)),
            NameServerConfig::Tcp { ip_addr, port, name } => format!("tcp:{}:{}{}", ip_addr, port, format_name(name)),
            NameServerConfig::Tls {
                ip_addr,
                port,
                spki,
                name,
            } => format!("tls:{}:{},{}{}", ip_addr, port, spki, format_name(name)),
            NameServerConfig::Https {
                ip_addr,
                port,
                spki,
                name,
            } => format!("https:{}:{},{}{}", ip_addr, port, spki, format_name(name)),
        };
        fmt.write_str(&str)
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
        NameServerConfigGroup {
            configs,
        }
    }

    pub fn from_system_config() -> Result<Self> {
        let config_group: NameServerConfigGroup = system_config::load_from_system_config()?;
        Ok(config_group)
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
impl From<NameServerConfig> for trust_dns_resolver::config::NameServerConfig {
    fn from(config: NameServerConfig) -> Self {
        match config {
            NameServerConfig::Udp { ip_addr, port, name: _ } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                tls_config: None,
            },
            NameServerConfig::Tcp { ip_addr, port, name: _ } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                tls_config: None,
            },
            NameServerConfig::Tls {
                ip_addr,
                port,
                spki,
                name: _,
            } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: Protocol::Tls,
                tls_dns_name: Some(spki),
                tls_config: None,
            },
            NameServerConfig::Https {
                ip_addr,
                port,
                spki,
                name: _,
            } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: Protocol::Https,
                tls_dns_name: Some(spki),
                tls_config: None,
            },
        }
    }
}
