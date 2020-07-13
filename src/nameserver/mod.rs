use crate::system_config;
use crate::Result;
use resolv_conf::ScopedIp;
use serde::Serialize;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use trust_dns_resolver::config::Protocol;

pub mod predefined;

#[derive(Debug, Clone, Serialize)]
pub enum NameServerConfig {
    Udp { ip_addr: IpAddr, port: u16 },
    Tcp { ip_addr: IpAddr, port: u16 },
    Tls { ip_addr: IpAddr, port: u16, spki: String },
    Https { ip_addr: IpAddr, port: u16, spki: String },
}

impl NameServerConfig {
    pub fn udp<T: Into<SocketAddr>>(socket_addr: T) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Udp {
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
        }
    }
    pub fn tcp<T: Into<SocketAddr>>(socket_addr: T) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Tcp {
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
        }
    }
    pub fn tls<T: Into<SocketAddr>, S: Into<String>>(socket_addr: T, spki: S) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Tls {
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            spki: spki.into(),
        }
    }
    pub fn https<T: Into<SocketAddr>, S: Into<String>>(socket_addr: T, spki: S) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Https {
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            spki: spki.into(),
        }
    }

    pub fn from_system_config() -> Result<Vec<Self>> {
        let servers: NameServerGroup = system_config::load_from_system_config()?;
        Ok(servers.0)
    }
}

impl fmt::Display for NameServerConfig {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            NameServerConfig::Udp { ip_addr, port } => format!("udp:{}:{}", ip_addr, port),
            NameServerConfig::Tcp { ip_addr, port } => format!("tcp:{}:{}", ip_addr, port),
            NameServerConfig::Tls { ip_addr, port, spki } => format!("tls:{}:{},{}", ip_addr, port, spki),
            NameServerConfig::Https { ip_addr, port, spki } => format!("tls:{}:{},{}", ip_addr, port, spki),
        };
        fmt.write_str(&str)
    }
}

#[doc(hidden)]
struct NameServerGroup(Vec<NameServerConfig>);

#[doc(hidden)]
impl From<resolv_conf::Config> for NameServerGroup {
    fn from(config: resolv_conf::Config) -> Self {
        let tcp = config.use_vc;
        let namesservers = config
            .nameservers
            .into_iter()
            .map(|x| match x {
                ScopedIp::V4(ipv4) if tcp => NameServerConfig::tcp((ipv4, 53)),
                ScopedIp::V4(ipv4) => NameServerConfig::udp((ipv4, 53)),
                ScopedIp::V6(ipv6, _) if tcp => NameServerConfig::tcp((ipv6, 53)),
                ScopedIp::V6(ipv6, _) => NameServerConfig::udp((ipv6, 53)),
            })
            .collect();

        NameServerGroup(namesservers)
    }
}

#[doc(hidden)]
impl From<NameServerConfig> for trust_dns_resolver::config::NameServerConfig {
    fn from(config: NameServerConfig) -> Self {
        match config {
            NameServerConfig::Udp { ip_addr, port } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                tls_config: None,
            },
            NameServerConfig::Tcp { ip_addr, port } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                tls_config: None,
            },
            NameServerConfig::Tls { ip_addr, port, spki } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: Protocol::Tls,
                tls_dns_name: Some(spki),
                tls_config: None,
            },
            NameServerConfig::Https { ip_addr, port, spki } => trust_dns_resolver::config::NameServerConfig {
                socket_addr: SocketAddr::new(ip_addr, port),
                protocol: Protocol::Https,
                tls_dns_name: Some(spki),
                tls_config: None,
            },
        }
    }
}
