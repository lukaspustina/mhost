pub mod cloudflare {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp((Ipv4Addr::new(1, 1, 1, 1), 53))
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp((Ipv4Addr::new(1, 1, 1, 1), 53))
    }

    pub fn https() -> NameServerConfig {
        NameServerConfig::https((Ipv4Addr::new(1, 1, 1, 1), 443), "cloudflare-dns.com")
    }

    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls((Ipv4Addr::new(1, 1, 1, 1), 853), "cloudflare-dns.com")
    }
}

pub mod google {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp((Ipv4Addr::new(8, 8, 8, 8), 53))
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp((Ipv4Addr::new(8, 8, 8, 8), 53))
    }
}

pub mod opennic {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp((Ipv4Addr::new(185, 121, 177, 177), 53))
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp((Ipv4Addr::new(185, 121, 177, 177), 53))
    }
}

pub mod quad9 {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp((Ipv4Addr::new(9, 9, 9, 9), 53))
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp((Ipv4Addr::new(9, 9, 9, 9), 53))
    }
}
