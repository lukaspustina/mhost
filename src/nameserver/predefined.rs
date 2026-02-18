// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::fmt;
use std::str::FromStr;

use crate::nameserver::NameServerConfig;
use crate::Error;

/// A well-known public DNS provider with preconfigured nameserver addresses.
///
/// Each provider offers nameservers across multiple transports (UDP, TCP, TLS, HTTPS)
/// and address families (IPv4, IPv6). Use [`configs`](PredefinedProvider::configs) to
/// obtain all [`NameServerConfig`]s for a given provider.
///
/// # Example
/// ```
/// use mhost::nameserver::predefined::PredefinedProvider;
///
/// let configs = PredefinedProvider::Google.configs();
/// assert!(!configs.is_empty());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PredefinedProvider {
    /// Cloudflare DNS (1.1.1.1, 1.0.0.1)
    Cloudflare,
    /// Google Public DNS (8.8.8.8, 8.8.4.4)
    Google,
    /// Quad9 unfiltered DNS (9.9.9.10, 149.112.112.10)
    Quad9,
    /// Mullvad DNS (194.242.2.2, 193.19.108.2)
    Mullvad,
    /// Wikimedia DNS (185.71.138.138, 185.71.139.139)
    Wikimedia,
    /// DNS4EU unfiltered DNS (185.134.197.54, 185.134.196.54)
    Dns4eu,
}

impl PredefinedProvider {
    /// Returns all available predefined providers.
    pub fn all() -> &'static [PredefinedProvider] {
        &[
            PredefinedProvider::Cloudflare,
            PredefinedProvider::Google,
            PredefinedProvider::Quad9,
            PredefinedProvider::Mullvad,
            PredefinedProvider::Wikimedia,
            PredefinedProvider::Dns4eu,
        ]
    }

    /// Returns all [`NameServerConfig`]s for this provider, across all transports and address families.
    pub fn configs(&self) -> Vec<NameServerConfig> {
        match self {
            PredefinedProvider::Cloudflare => {
                let mut v = vec![
                    cloudflare::udp(),
                    cloudflare::tcp(),
                    cloudflare::udp_2(),
                    cloudflare::tcp_2(),
                    cloudflare::udp6(),
                    cloudflare::tcp6(),
                    cloudflare::udp6_2(),
                    cloudflare::tcp6_2(),
                ];
                #[cfg(feature = "doh")]
                v.extend([
                    cloudflare::https(),
                    cloudflare::https_2(),
                    cloudflare::https6(),
                    cloudflare::https6_2(),
                ]);
                #[cfg(feature = "dot")]
                v.extend([
                    cloudflare::tls(),
                    cloudflare::tls_2(),
                    cloudflare::tls6(),
                    cloudflare::tls6_2(),
                ]);
                v
            }
            PredefinedProvider::Google => {
                let mut v = vec![
                    google::udp(),
                    google::tcp(),
                    google::udp_2(),
                    google::tcp_2(),
                    google::udp6(),
                    google::tcp6(),
                    google::udp6_2(),
                    google::tcp6_2(),
                ];
                #[cfg(feature = "doh")]
                v.extend([
                    google::https(),
                    google::https_2(),
                    google::https6(),
                    google::https6_2(),
                ]);
                #[cfg(feature = "dot")]
                v.extend([
                    google::tls(),
                    google::tls_2(),
                    google::tls6(),
                    google::tls6_2(),
                ]);
                v
            }
            PredefinedProvider::Quad9 => {
                let mut v = vec![
                    quad9::udp(),
                    quad9::tcp(),
                    quad9::udp_2(),
                    quad9::tcp_2(),
                    quad9::udp6(),
                    quad9::tcp6(),
                    quad9::udp6_2(),
                    quad9::tcp6_2(),
                ];
                #[cfg(feature = "doh")]
                v.extend([
                    quad9::https(),
                    quad9::https_2(),
                    quad9::https6(),
                    quad9::https6_2(),
                ]);
                #[cfg(feature = "dot")]
                v.extend([
                    quad9::tls(),
                    quad9::tls_2(),
                    quad9::tls6(),
                    quad9::tls6_2(),
                ]);
                v
            }
            PredefinedProvider::Mullvad => {
                let mut v = vec![
                    mullvad::udp(),
                    mullvad::tcp(),
                    mullvad::udp_2(),
                    mullvad::tcp_2(),
                    mullvad::udp6(),
                    mullvad::tcp6(),
                ];
                #[cfg(feature = "doh")]
                v.extend([mullvad::https(), mullvad::https_2(), mullvad::https6()]);
                #[cfg(feature = "dot")]
                v.extend([mullvad::tls(), mullvad::tls_2(), mullvad::tls6()]);
                v
            }
            PredefinedProvider::Wikimedia => {
                let mut v = vec![
                    wikimedia::udp(),
                    wikimedia::tcp(),
                    wikimedia::udp_2(),
                    wikimedia::tcp_2(),
                    wikimedia::udp6(),
                    wikimedia::tcp6(),
                    wikimedia::udp6_2(),
                    wikimedia::tcp6_2(),
                ];
                #[cfg(feature = "doh")]
                v.extend([
                    wikimedia::https(),
                    wikimedia::https_2(),
                    wikimedia::https6(),
                    wikimedia::https6_2(),
                ]);
                #[cfg(feature = "dot")]
                v.extend([
                    wikimedia::tls(),
                    wikimedia::tls_2(),
                    wikimedia::tls6(),
                    wikimedia::tls6_2(),
                ]);
                v
            }
            PredefinedProvider::Dns4eu => {
                let mut v = vec![
                    dns4eu::udp(),
                    dns4eu::tcp(),
                    dns4eu::udp_2(),
                    dns4eu::tcp_2(),
                ];
                #[cfg(feature = "doh")]
                v.extend([dns4eu::https(), dns4eu::https_2()]);
                #[cfg(feature = "dot")]
                v.extend([dns4eu::tls(), dns4eu::tls_2()]);
                v
            }
        }
    }
}

impl fmt::Display for PredefinedProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PredefinedProvider::Cloudflare => write!(f, "cloudflare"),
            PredefinedProvider::Google => write!(f, "google"),
            PredefinedProvider::Quad9 => write!(f, "quad9"),
            PredefinedProvider::Mullvad => write!(f, "mullvad"),
            PredefinedProvider::Wikimedia => write!(f, "wikimedia"),
            PredefinedProvider::Dns4eu => write!(f, "dns4eu"),
        }
    }
}

impl FromStr for PredefinedProvider {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "cloudflare" => Ok(PredefinedProvider::Cloudflare),
            "google" => Ok(PredefinedProvider::Google),
            "quad9" => Ok(PredefinedProvider::Quad9),
            "mullvad" => Ok(PredefinedProvider::Mullvad),
            "wikimedia" => Ok(PredefinedProvider::Wikimedia),
            "dns4eu" => Ok(PredefinedProvider::Dns4eu),
            _ => Err(Error::ParserError {
                what: s.to_string(),
                to: "PredefinedProvider",
                why: "unknown provider".to_string(),
            }),
        }
    }
}

/// Returns UDP nameservers for propagation checking — one per unique IP across 6 providers.
/// Includes both IPv4 and IPv6 entries where available.
pub fn propagation_nameserver_configs() -> Vec<NameServerConfig> {
    vec![
        cloudflare::udp(),
        cloudflare::udp_2(),
        cloudflare::udp6(),
        cloudflare::udp6_2(),
        google::udp(),
        google::udp_2(),
        google::udp6(),
        google::udp6_2(),
        quad9::udp(),
        quad9::udp_2(),
        quad9::udp6(),
        quad9::udp6_2(),
        mullvad::udp(),
        mullvad::udp_2(),
        mullvad::udp6(),
        wikimedia::udp(),
        wikimedia::udp_2(),
        wikimedia::udp6(),
        wikimedia::udp6_2(),
        dns4eu::udp(),
        dns4eu::udp_2(),
    ]
}

pub fn nameserver_configs() -> Vec<NameServerConfig> {
    let mut v = vec![
        cloudflare::udp(),
        cloudflare::tcp(),
        cloudflare::udp_2(),
        cloudflare::tcp_2(),
        cloudflare::udp6(),
        cloudflare::tcp6(),
        cloudflare::udp6_2(),
        cloudflare::tcp6_2(),
        google::udp(),
        google::tcp(),
        google::udp_2(),
        google::tcp_2(),
        google::udp6(),
        google::tcp6(),
        google::udp6_2(),
        google::tcp6_2(),
        quad9::udp(),
        quad9::tcp(),
        quad9::udp_2(),
        quad9::tcp_2(),
        quad9::udp6(),
        quad9::tcp6(),
        quad9::udp6_2(),
        quad9::tcp6_2(),
        mullvad::udp(),
        mullvad::tcp(),
        mullvad::udp_2(),
        mullvad::tcp_2(),
        mullvad::udp6(),
        mullvad::tcp6(),
        wikimedia::udp(),
        wikimedia::tcp(),
        wikimedia::udp_2(),
        wikimedia::tcp_2(),
        wikimedia::udp6(),
        wikimedia::tcp6(),
        wikimedia::udp6_2(),
        wikimedia::tcp6_2(),
        dns4eu::udp(),
        dns4eu::tcp(),
        dns4eu::udp_2(),
        dns4eu::tcp_2(),
    ];
    #[cfg(feature = "doh")]
    v.extend([
        cloudflare::https(),
        cloudflare::https_2(),
        cloudflare::https6(),
        cloudflare::https6_2(),
        google::https(),
        google::https_2(),
        google::https6(),
        google::https6_2(),
        quad9::https(),
        quad9::https_2(),
        quad9::https6(),
        quad9::https6_2(),
        mullvad::https(),
        mullvad::https_2(),
        mullvad::https6(),
        wikimedia::https(),
        wikimedia::https_2(),
        wikimedia::https6(),
        wikimedia::https6_2(),
        dns4eu::https(),
        dns4eu::https_2(),
    ]);
    #[cfg(feature = "dot")]
    v.extend([
        cloudflare::tls(),
        cloudflare::tls_2(),
        cloudflare::tls6(),
        cloudflare::tls6_2(),
        google::tls(),
        google::tls_2(),
        google::tls6(),
        google::tls6_2(),
        quad9::tls(),
        quad9::tls_2(),
        quad9::tls6(),
        quad9::tls6_2(),
        mullvad::tls(),
        mullvad::tls_2(),
        mullvad::tls6(),
        wikimedia::tls(),
        wikimedia::tls_2(),
        wikimedia::tls6(),
        wikimedia::tls6_2(),
        dns4eu::tls(),
        dns4eu::tls_2(),
    ]);
    v
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

    #[cfg(feature = "doh")]
    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_1, 443), "cloudflare-dns.com", "Cloudflare 1".to_string())
    }

    #[cfg(feature = "dot")]
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

    #[cfg(feature = "doh")]
    pub fn https_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_2, 443), "cloudflare-dns.com", "Cloudflare 2".to_string())
    }

    #[cfg(feature = "dot")]
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

    #[cfg(feature = "doh")]
    pub fn https6() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_1, 443), "cloudflare-dns.com", "Cloudflare 1".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls6() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_1, 853), "cloudflare-dns.com", "Cloudflare 1".to_string())
    }

    // IPv6 2
    pub fn udp6_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6_2, 53), "Cloudflare 2".to_string())
    }

    pub fn tcp6_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6_2, 53), "Cloudflare 2".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https6_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_2, 443), "cloudflare-dns.com", "Cloudflare 2".to_string())
    }

    #[cfg(feature = "dot")]
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

    #[cfg(feature = "doh")]
    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_1, 443), "dns.google", "Google 1".to_string())
    }

    #[cfg(feature = "dot")]
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

    #[cfg(feature = "doh")]
    pub fn https_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_2, 443), "dns.google", "Google 2".to_string())
    }

    #[cfg(feature = "dot")]
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

    #[cfg(feature = "doh")]
    pub fn https6() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_1, 443), "dns.google", "Google 1".to_string())
    }

    #[cfg(feature = "dot")]
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

    #[cfg(feature = "doh")]
    pub fn https6_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_2, 443), "dns.google", "Google 2".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls6_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_2, 853), "dns.google", "Google 2".to_string())
    }
}

pub mod quad9 {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::nameserver::NameServerConfig;

    // Quad9 unfiltered endpoints
    static IPV4_1: Ipv4Addr = Ipv4Addr::new(9, 9, 9, 10);
    static IPV4_2: Ipv4Addr = Ipv4Addr::new(149, 112, 112, 10);
    static IPV6_1: Ipv6Addr = Ipv6Addr::new(0x2620, 0xfe, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10);
    static IPV6_2: Ipv6Addr = Ipv6Addr::new(0x2620, 0xfe, 0x0, 0x0, 0x0, 0x0, 0xfe, 0x10);

    // IPv4 1
    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_1, 53), "Quad9 1".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_1, 53), "Quad9 1".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_1, 443), "dns10.quad9.net", "Quad9 1".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_1, 853), "dns10.quad9.net", "Quad9 1".to_string())
    }

    // IPv4 2
    pub fn udp_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_2, 53), "Quad9 2".to_string())
    }

    pub fn tcp_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_2, 53), "Quad9 2".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_2, 443), "dns10.quad9.net", "Quad9 2".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_2, 853), "dns10.quad9.net", "Quad9 2".to_string())
    }

    // IPv6 1
    pub fn udp6() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6_1, 53), "Quad9 1".to_string())
    }

    pub fn tcp6() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6_1, 53), "Quad9 1".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https6() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_1, 443), "dns10.quad9.net", "Quad9 1".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls6() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_1, 853), "dns10.quad9.net", "Quad9 1".to_string())
    }

    // IPv6 2
    pub fn udp6_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6_2, 53), "Quad9 2".to_string())
    }

    pub fn tcp6_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6_2, 53), "Quad9 2".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https6_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_2, 443), "dns10.quad9.net", "Quad9 2".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls6_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_2, 853), "dns10.quad9.net", "Quad9 2".to_string())
    }
}

pub mod mullvad {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::nameserver::NameServerConfig;

    static IPV4_1: Ipv4Addr = Ipv4Addr::new(194, 242, 2, 2);
    static IPV4_2: Ipv4Addr = Ipv4Addr::new(193, 19, 108, 2);
    static IPV6: Ipv6Addr = Ipv6Addr::new(0x2a07, 0xe340, 0x0, 0x0, 0x0, 0x0, 0x0, 0x2);

    // IPv4 1
    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_1, 53), "Mullvad 1".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_1, 53), "Mullvad 1".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_1, 443), "dns.mullvad.net", "Mullvad 1".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_1, 853), "dns.mullvad.net", "Mullvad 1".to_string())
    }

    // IPv4 2
    pub fn udp_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_2, 53), "Mullvad 2".to_string())
    }

    pub fn tcp_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_2, 53), "Mullvad 2".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_2, 443), "dns.mullvad.net", "Mullvad 2".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_2, 853), "dns.mullvad.net", "Mullvad 2".to_string())
    }

    // IPv6
    pub fn udp6() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6, 53), "Mullvad".to_string())
    }

    pub fn tcp6() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6, 53), "Mullvad".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https6() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6, 443), "dns.mullvad.net", "Mullvad".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls6() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6, 853), "dns.mullvad.net", "Mullvad".to_string())
    }
}

pub mod wikimedia {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::nameserver::NameServerConfig;

    static IPV4_1: Ipv4Addr = Ipv4Addr::new(185, 71, 138, 138);
    static IPV4_2: Ipv4Addr = Ipv4Addr::new(185, 71, 139, 139);
    static IPV6_1: Ipv6Addr = Ipv6Addr::new(0x2001, 0x67c, 0x930, 0x0, 0x0, 0x0, 0x0, 0x1);
    static IPV6_2: Ipv6Addr = Ipv6Addr::new(0x2001, 0x67c, 0x930, 0x0, 0x0, 0x0, 0x0, 0x2);

    // IPv4 1
    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_1, 53), "Wikimedia 1".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_1, 53), "Wikimedia 1".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_1, 443), "wikimedia-dns.org", "Wikimedia 1".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_1, 853), "wikimedia-dns.org", "Wikimedia 1".to_string())
    }

    // IPv4 2
    pub fn udp_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_2, 53), "Wikimedia 2".to_string())
    }

    pub fn tcp_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_2, 53), "Wikimedia 2".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_2, 443), "wikimedia-dns.org", "Wikimedia 2".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_2, 853), "wikimedia-dns.org", "Wikimedia 2".to_string())
    }

    // IPv6 1
    pub fn udp6() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6_1, 53), "Wikimedia 1".to_string())
    }

    pub fn tcp6() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6_1, 53), "Wikimedia 1".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https6() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_1, 443), "wikimedia-dns.org", "Wikimedia 1".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls6() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_1, 853), "wikimedia-dns.org", "Wikimedia 1".to_string())
    }

    // IPv6 2
    pub fn udp6_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV6_2, 53), "Wikimedia 2".to_string())
    }

    pub fn tcp6_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV6_2, 53), "Wikimedia 2".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https6_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV6_2, 443), "wikimedia-dns.org", "Wikimedia 2".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls6_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV6_2, 853), "wikimedia-dns.org", "Wikimedia 2".to_string())
    }
}

pub mod dns4eu {
    use std::net::Ipv4Addr;

    use crate::nameserver::NameServerConfig;

    static IPV4_1: Ipv4Addr = Ipv4Addr::new(185, 134, 197, 54);
    static IPV4_2: Ipv4Addr = Ipv4Addr::new(185, 134, 196, 54);

    // IPv4 1
    pub fn udp() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_1, 53), "DNS4EU 1".to_string())
    }

    pub fn tcp() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_1, 53), "DNS4EU 1".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_1, 443), "unfiltered.joindns4.eu", "DNS4EU 1".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_1, 853), "unfiltered.joindns4.eu", "DNS4EU 1".to_string())
    }

    // IPv4 2
    pub fn udp_2() -> NameServerConfig {
        NameServerConfig::udp_with_name((IPV4_2, 53), "DNS4EU 2".to_string())
    }

    pub fn tcp_2() -> NameServerConfig {
        NameServerConfig::tcp_with_name((IPV4_2, 53), "DNS4EU 2".to_string())
    }

    #[cfg(feature = "doh")]
    pub fn https_2() -> NameServerConfig {
        NameServerConfig::https_with_name((IPV4_2, 443), "unfiltered.joindns4.eu", "DNS4EU 2".to_string())
    }

    #[cfg(feature = "dot")]
    pub fn tls_2() -> NameServerConfig {
        NameServerConfig::tls_with_name((IPV4_2, 853), "unfiltered.joindns4.eu", "DNS4EU 2".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_returns_six_providers() {
        assert_eq!(PredefinedProvider::all().len(), 6);
    }

    #[test]
    fn configs_total_matches_nameserver_configs() {
        let total: usize = PredefinedProvider::all().iter().map(|p| p.configs().len()).sum();
        assert_eq!(total, nameserver_configs().len());
    }

    #[test]
    fn from_str_round_trip() {
        for provider in PredefinedProvider::all() {
            let s = provider.to_string();
            let parsed: PredefinedProvider = s.parse().unwrap();
            assert_eq!(parsed, *provider);
        }
    }

    #[test]
    fn from_str_case_insensitive() {
        assert_eq!(
            PredefinedProvider::from_str("CLOUDFLARE").unwrap(),
            PredefinedProvider::Cloudflare
        );
        assert_eq!(
            PredefinedProvider::from_str("Google").unwrap(),
            PredefinedProvider::Google
        );
        assert_eq!(
            PredefinedProvider::from_str("QUAD9").unwrap(),
            PredefinedProvider::Quad9
        );
        assert_eq!(
            PredefinedProvider::from_str("Dns4eu").unwrap(),
            PredefinedProvider::Dns4eu
        );
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert!(PredefinedProvider::from_str("unknown_provider").is_err());
        assert!(PredefinedProvider::from_str("").is_err());
    }
}
