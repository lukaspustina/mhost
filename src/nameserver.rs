use std::fmt;
use std::net::{IpAddr, SocketAddr};
use trust_dns_resolver::config::Protocol;

#[derive(Debug, Clone)]
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
    pub fn tls<T: Into<SocketAddr>>(socket_addr: T, spki: String) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Tls {
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            spki,
        }
    }
    pub fn https<T: Into<SocketAddr>>(socket_addr: T, spki: String) -> Self {
        let socket_addr = socket_addr.into();
        NameServerConfig::Https {
            ip_addr: socket_addr.ip(),
            port: socket_addr.port(),
            spki,
        }
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
