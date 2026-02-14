// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/// A well-known SRV service probe definition.
#[derive(Debug, Clone)]
pub struct SrvProbe {
    pub service: &'static str,
    pub protocol: &'static str,
}

impl SrvProbe {
    pub fn to_subdomain(&self) -> String {
        format!("_{}._{}", self.service, self.protocol)
    }
}

/// Returns a list of well-known SRV service probes for common services.
pub fn well_known_srv_probes() -> Vec<SrvProbe> {
    vec![
        SrvProbe {
            service: "submission",
            protocol: "tcp",
        },
        SrvProbe {
            service: "imap",
            protocol: "tcp",
        },
        SrvProbe {
            service: "imaps",
            protocol: "tcp",
        },
        SrvProbe {
            service: "pop3",
            protocol: "tcp",
        },
        SrvProbe {
            service: "pop3s",
            protocol: "tcp",
        },
        SrvProbe {
            service: "sip",
            protocol: "tcp",
        },
        SrvProbe {
            service: "sip",
            protocol: "udp",
        },
        SrvProbe {
            service: "sips",
            protocol: "tcp",
        },
        SrvProbe {
            service: "xmpp-client",
            protocol: "tcp",
        },
        SrvProbe {
            service: "xmpp-server",
            protocol: "tcp",
        },
        SrvProbe {
            service: "ldap",
            protocol: "tcp",
        },
        SrvProbe {
            service: "ldaps",
            protocol: "tcp",
        },
        SrvProbe {
            service: "kerberos",
            protocol: "tcp",
        },
        SrvProbe {
            service: "kerberos",
            protocol: "udp",
        },
        SrvProbe {
            service: "caldavs",
            protocol: "tcp",
        },
        SrvProbe {
            service: "carddavs",
            protocol: "tcp",
        },
        SrvProbe {
            service: "matrix",
            protocol: "tcp",
        },
        SrvProbe {
            service: "stun",
            protocol: "udp",
        },
        SrvProbe {
            service: "stuns",
            protocol: "tcp",
        },
        SrvProbe {
            service: "turn",
            protocol: "udp",
        },
        SrvProbe {
            service: "turns",
            protocol: "tcp",
        },
        SrvProbe {
            service: "h323cs",
            protocol: "tcp",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_subdomain_format() {
        let probe = SrvProbe {
            service: "sip",
            protocol: "tcp",
        };
        assert_eq!(probe.to_subdomain(), "_sip._tcp");
    }

    #[test]
    fn well_known_probes_not_empty() {
        let probes = well_known_srv_probes();
        assert!(probes.len() >= 20);
    }

    #[test]
    fn all_probes_have_underscore_format() {
        for probe in well_known_srv_probes() {
            let sub = probe.to_subdomain();
            assert!(sub.starts_with('_'), "Probe subdomain should start with _: {}", sub);
            assert!(sub.contains("._"), "Probe subdomain should contain ._: {}", sub);
        }
    }
}
