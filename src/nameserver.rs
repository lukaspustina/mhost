use std::net::IpAddr;

pub enum Protocol {
    Udp,
    Tcp,
    Tls,
    Https,
}

pub enum NameServerConfig {
    Udp { ip_addr: IpAddr, port: u16 },
    Tcp { ip_addr: IpAddr, port: u16 },
    Tls { ip_addr: IpAddr, port: u16, spki: String },
    Https { ip_addr: IpAddr, port: u16, spki: String },
}

impl NameServerConfig {
    pub fn udp<T: Into<IpAddr>>(ip_addr: T, port: u16) -> Self {
        NameServerConfig::Udp {
            ip_addr: ip_addr.into(),
            port,
        }
    }
    pub fn tcp<T: Into<IpAddr>>(ip_addr: T, port: u16) -> Self {
        NameServerConfig::Tcp {
            ip_addr: ip_addr.into(),
            port,
        }
    }
    pub fn tls<T: Into<IpAddr>>(ip_addr: T, port: u16, spki: String) -> Self {
        NameServerConfig::Tls {
            ip_addr: ip_addr.into(),
            port,
            spki,
        }
    }
    pub fn https<T: Into<IpAddr>>(ip_addr: T, port: u16, spki: String) -> Self {
        NameServerConfig::Https {
            ip_addr: ip_addr.into(),
            port,
            spki,
        }
    }
}

mod internal {
    use super::NameServerConfig;
    use std::net::SocketAddr;
    use trust_dns_resolver::config::Protocol;

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
}
