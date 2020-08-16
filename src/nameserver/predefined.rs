use crate::nameserver::NameServerConfig;

pub fn nameserver_configs() -> Vec<NameServerConfig> {
    vec![
        cloudflare::udp(),
        cloudflare::tcp(),
        cloudflare::https(),
        cloudflare::tls(),
        cloudflare::udp_2(),
        cloudflare::tcp_2(),
        cloudflare::https_2(),
        cloudflare::tls_2(),
        cloudflare::udp6(),
        cloudflare::tcp6(),
        cloudflare::https6(),
        cloudflare::tls6(),
        cloudflare::udp6_2(),
        cloudflare::tcp6_2(),
        cloudflare::https6_2(),
        cloudflare::tls6_2(),
        google::udp(),
        google::tcp(),
        google::https(),
        google::tls(),
        google::udp_2(),
        google::tcp_2(),
        google::https_2(),
        google::tls_2(),
        google::udp6(),
        google::tcp6(),
        google::https6(),
        google::tls6(),
        google::udp6_2(),
        google::tcp6_2(),
        google::https6_2(),
        google::tls6_2(),
        opennic::udp(),
        opennic::tcp(),
        opennic::udp6(),
        opennic::tcp6(),
        quad9::udp(),
        quad9::tcp(),
        quad9::https(),
        quad9::tls(),
        quad9::udp_2(),
        quad9::tcp_2(),
        quad9::https_2(),
        quad9::tls_2(),
        quad9::udp6(),
        quad9::tcp6(),
        quad9::https6(),
        quad9::tls6_2(),
        quad9::udp6_2(),
        quad9::tcp6_2(),
        quad9::https6_2(),
        quad9::tls6_2(),
    ]
}

pub mod cloudflare {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::nameserver::NameServerConfig;

    static IPV4_1: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
    static IPV4_2: Ipv4Addr = Ipv4Addr::new(1, 0, 0, 1);
    static IPV6_1: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0x0, 0x0, 0x0, 0x0, 0x1111);
    static IPV6_2: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0x0, 0x0, 0x0, 0x0, 0x1001);

    // IPv4 1
    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_1, 53), "Cloudflare 1".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_1, 53), "Cloudflare 1".to_string())
    }

    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_1, 443), "cloudflare-dns.com", "Cloudflare 1".to_string())
    }

    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_1, 853), "cloudflare-dns.com", "Cloudflare 1".to_string())
    }

    // IPv4 2
    pub fn udp_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_2, 53), "Cloudflare 2".to_string())
    }

    pub fn tcp_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_2, 53), "Cloudflare 2".to_string())
    }

    pub fn https_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_2, 443), "cloudflare-dns.com", "Cloudflare 2".to_string())
    }

    pub fn tls_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_2, 853), "cloudflare-dns.com", "Cloudflare 2".to_string())
    }

    // IPv6 1
    pub fn udp6() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6_1, 53), "Cloudflare 1".to_string())
    }

    pub fn tcp6() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6_1, 53), "Cloudflare 1".to_string())
    }

    pub fn https6() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_1, 663), "cloudflare-dns.com", "Cloudflare 1".to_string())
    }

    pub fn tls6() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_1, 853), "cloudflare-dns.com", "Cloudflare 2".to_string())
    }

    // IPv6 2
    pub fn udp6_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6_2, 53), "Cloudflare 2".to_string())
    }

    pub fn tcp6_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6_2, 53), "Cloudflare 2".to_string())
    }

    pub fn https6_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_2, 663), "cloudflare-dns.com", "Cloudflare 2".to_string())
    }

    pub fn tls6_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_2, 853), "cloudflare-dns.com", "Cloudflare 2".to_string())
    }
}

pub mod google {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::nameserver::NameServerConfig;

    static IPV4_1: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
    static IPV4_2: Ipv4Addr = Ipv4Addr::new(8, 8, 4, 4);
    static IPV6_1: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0x0, 0x0, 0x0, 0x0, 0x8888);
    static IPV6_2: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0x0, 0x0, 0x0, 0x0, 0x8844);

    // IPv4 1
    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_1, 53), "Google 1".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_1, 53), "Google 1".to_string())
    }

    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_1, 443), "dns.google", "Google 1".to_string())
    }

    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_1, 853), "dns.google", "Google 1".to_string())
    }

    // IPv4 2
    pub fn udp_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_2, 53), "Google 2".to_string())
    }

    pub fn tcp_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_2, 53), "Google 2".to_string())
    }

    pub fn https_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_2, 443), "dns.google", "Google 2".to_string())
    }

    pub fn tls_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_2, 853), "dns.google", "Google 2".to_string())
    }

    // IPv6 1
    pub fn udp6() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6_1, 53), "Google 1".to_string())
    }

    pub fn tcp6() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6_1, 53), "Google 1".to_string())
    }

    pub fn https6() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_1, 443), "dns.google", "Google 1".to_string())
    }

    pub fn tls6() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_1, 853), "dns.google", "Google 1".to_string())
    }

    // IPv6 2
    pub fn udp6_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6_2, 53), "Google 2".to_string())
    }

    pub fn tcp6_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6_2, 53), "Google 2".to_string())
    }

    pub fn https6_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_2, 443), "dns.google", "Google 2".to_string())
    }

    pub fn tls6_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_2, 853), "dns.google", "Google 2".to_string())
    }
}

pub mod opennic {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::nameserver::NameServerConfig;

    static IPV4: Ipv4Addr = Ipv4Addr::new(94, 103, 153, 176);
    static IPV6: Ipv6Addr = Ipv6Addr::new(0x2a02, 0x990, 0x219, 0x1, 0xba, 0x1337, 0xcafe, 0x3);

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4, 53), "OpenNIC".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4, 53), "OpenNIC".to_string())
    }

    pub fn udp6() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6, 53), "OpenNIC".to_string())
    }

    pub fn tcp6() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6, 53), "OpenNIC".to_string())
    }
}

pub mod quad9 {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::nameserver::NameServerConfig;

    static IPV4_1: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 9);
    static IPV4_2: Ipv4Addr = Ipv4Addr::new(149, 112, 112, 112);
    static IPV6_1: Ipv6Addr = Ipv6Addr::new(0x2620, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0xfe);
    static IPV6_2: Ipv6Addr = Ipv6Addr::new(0x2620, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9);

    // IPv4 1
    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_1, 53), "Quad9 1".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_1, 53), "Quad9 1".to_string())
    }

    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_1, 443), "dns.quad9.net", "Quad9 1".to_string())
    }

    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_1, 853), "dns.quad9.net", "Quad9 1".to_string())
    }

    // IPv4 2
    pub fn udp_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_2, 53), "Quad9 2".to_string())
    }

    pub fn tcp_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_2, 53), "Quad9 2".to_string())
    }

    pub fn https_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_2, 443), "dns.quad9.net", "Quad9 2".to_string())
    }

    pub fn tls_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_2, 853), "dns.quad9.net", "Quad9 2".to_string())
    }

    // IPv6 1
    pub fn udp6() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6_1, 53), "Quad9 1".to_string())
    }

    pub fn tcp6() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6_1, 53), "Quad9 1".to_string())
    }

    pub fn https6() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_1, 663), "dns.quad9.net", "Quad9 1".to_string())
    }

    pub fn tls6() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_1, 853), "dns.quad9.net", "Quad9 1".to_string())
    }

    // IPv6 2
    pub fn udp6_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6_2, 53), "Quad9 2".to_string())
    }

    pub fn tcp6_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6_2, 53), "Quad9 2".to_string())
    }

    pub fn https6_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_2, 663), "dns.quad9.net", "Quad9 2".to_string())
    }

    pub fn tls6_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_2, 853), "dns.quad9.net", "Quad9 2".to_string())
    }
}
