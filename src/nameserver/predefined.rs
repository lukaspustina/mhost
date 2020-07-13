use crate::nameserver::NameServerConfig;

pub fn name_server_configs() -> Vec<NameServerConfig> {
    vec![
        cloudflare::udp(),
        cloudflare::tcp(),
        cloudflare::https(),
        cloudflare::tls(),
        google::udp(),
        google::tcp(),
        opennic::udp(),
        opennic::tcp(),
        quad9::udp(),
        quad9::tcp(),
        quad9::tls(),
    ]
}

pub mod cloudflare {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    static IPV4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4, 53), "Cloudflare".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4, 53), "Cloudflare".to_string())
    }

    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4, 443), "cloudflare-dns.com", "Cloudflare".to_string())
    }

    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4, 853), "cloudflare-dns.com", "Cloudflare".to_string())
    }
}

pub mod google {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    static IPV4: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4, 53), "Google".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4, 53), "Google".to_string())
    }

    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4, 443), "dns.google", "Cloudflare".to_string())
    }

    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4, 853), "dns.google", "Cloudflare".to_string())
    }
}

pub mod opennic {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    static IPV4: Ipv4Addr = Ipv4Addr::new(185, 121, 177, 177);

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4, 53), "OpenNIC".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4, 53), "OpenNIC".to_string())
    }
}

pub mod quad9 {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    static IPV4: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4, 53), "Quad9".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4, 53), "Quad9".to_string())
    }

    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4, 853), "cloudflare-dns.com", "Cloudflare".to_string())
    }
}
