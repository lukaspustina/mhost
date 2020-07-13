pub mod cloudflare {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((Ipv4Addr::new(1, 1, 1, 1), 53), "Cloudflare".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((Ipv4Addr::new(1, 1, 1, 1), 53), "Cloudflare".to_string())
    }

    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name(
            (Ipv4Addr::new(1, 1, 1, 1), 443),
            "cloudflare-dns.com",
            "Cloudflare".to_string(),
        )
    }

    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls_with_name(
            (Ipv4Addr::new(1, 1, 1, 1), 853),
            "cloudflare-dns.com",
            "Cloudflare".to_string(),
        )
    }
}

pub mod google {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((Ipv4Addr::new(8, 8, 8, 8), 53), "Google".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((Ipv4Addr::new(8, 8, 8, 8), 53), "Google".to_string())
    }
}

pub mod opennic {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((Ipv4Addr::new(185, 121, 177, 177), 53), "OpenNIC".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((Ipv4Addr::new(185, 121, 177, 177), 53), "OpenNIC".to_string())
    }
}

pub mod quad9 {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((Ipv4Addr::new(9, 9, 9, 9), 53), "Quad9".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((Ipv4Addr::new(9, 9, 9, 9), 53), "Quad9".to_string())
    }
}
