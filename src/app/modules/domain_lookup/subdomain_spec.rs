// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use crate::RecordType;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Apex,
    EmailAuthentication,
    EmailServices,
    TlsDane,
    Communication,
    CalendarContacts,
    Infrastructure,
    ModernProtocols,
    VerificationMetadata,
    Legacy,
    Gaming,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::Apex => write!(f, "Apex"),
            Category::EmailAuthentication => write!(f, "Email Authentication"),
            Category::EmailServices => write!(f, "Email Services"),
            Category::TlsDane => write!(f, "TLS / DANE"),
            Category::Communication => write!(f, "Communication"),
            Category::CalendarContacts => write!(f, "Calendar / Contacts"),
            Category::Infrastructure => write!(f, "Infrastructure"),
            Category::ModernProtocols => write!(f, "Modern Protocols"),
            Category::VerificationMetadata => write!(f, "Verification / Metadata"),
            Category::Legacy => write!(f, "Legacy"),
            Category::Gaming => write!(f, "Gaming"),
        }
    }
}

pub struct SubdomainEntry {
    /// Empty string for apex, otherwise the subdomain prefix (e.g. "_dmarc")
    pub subdomain: &'static str,
    pub record_type: RecordType,
    pub category: Category,
}

/// Returns the default (Tier 1+2) entries queried by `domain-lookup`.
pub fn default_entries() -> Vec<SubdomainEntry> {
    use Category::*;
    use RecordType::*;

    vec![
        // Apex records
        SubdomainEntry {
            subdomain: "",
            record_type: A,
            category: Apex,
        },
        SubdomainEntry {
            subdomain: "",
            record_type: AAAA,
            category: Apex,
        },
        SubdomainEntry {
            subdomain: "",
            record_type: MX,
            category: Apex,
        },
        SubdomainEntry {
            subdomain: "",
            record_type: NS,
            category: Apex,
        },
        SubdomainEntry {
            subdomain: "",
            record_type: SOA,
            category: Apex,
        },
        SubdomainEntry {
            subdomain: "",
            record_type: CAA,
            category: Apex,
        },
        SubdomainEntry {
            subdomain: "",
            record_type: HTTPS,
            category: Apex,
        },
        SubdomainEntry {
            subdomain: "",
            record_type: TXT,
            category: Apex,
        },
        SubdomainEntry {
            subdomain: "",
            record_type: CNAME,
            category: Apex,
        },
        SubdomainEntry {
            subdomain: "",
            record_type: SVCB,
            category: Apex,
        },
        SubdomainEntry {
            subdomain: "",
            record_type: NAPTR,
            category: Apex,
        },
        SubdomainEntry {
            subdomain: "",
            record_type: SSHFP,
            category: Apex,
        },
        // Email Authentication
        SubdomainEntry {
            subdomain: "_dmarc",
            record_type: TXT,
            category: EmailAuthentication,
        },
        SubdomainEntry {
            subdomain: "_mta-sts",
            record_type: TXT,
            category: EmailAuthentication,
        },
        SubdomainEntry {
            subdomain: "_smtp._tls",
            record_type: TXT,
            category: EmailAuthentication,
        },
        SubdomainEntry {
            subdomain: "default._bimi",
            record_type: TXT,
            category: EmailAuthentication,
        },
        // Email Services (SRV)
        SubdomainEntry {
            subdomain: "_submission._tcp",
            record_type: SRV,
            category: EmailServices,
        },
        SubdomainEntry {
            subdomain: "_submissions._tcp",
            record_type: SRV,
            category: EmailServices,
        },
        SubdomainEntry {
            subdomain: "_imap._tcp",
            record_type: SRV,
            category: EmailServices,
        },
        SubdomainEntry {
            subdomain: "_imaps._tcp",
            record_type: SRV,
            category: EmailServices,
        },
        SubdomainEntry {
            subdomain: "_pop3._tcp",
            record_type: SRV,
            category: EmailServices,
        },
        SubdomainEntry {
            subdomain: "_pop3s._tcp",
            record_type: SRV,
            category: EmailServices,
        },
        SubdomainEntry {
            subdomain: "_autodiscover._tcp",
            record_type: SRV,
            category: EmailServices,
        },
        // TLS / DANE
        SubdomainEntry {
            subdomain: "_443._tcp",
            record_type: TLSA,
            category: TlsDane,
        },
        SubdomainEntry {
            subdomain: "_25._tcp",
            record_type: TLSA,
            category: TlsDane,
        },
        // Communication
        SubdomainEntry {
            subdomain: "_sip._tcp",
            record_type: SRV,
            category: Communication,
        },
        SubdomainEntry {
            subdomain: "_sip._udp",
            record_type: SRV,
            category: Communication,
        },
        SubdomainEntry {
            subdomain: "_sips._tcp",
            record_type: SRV,
            category: Communication,
        },
        SubdomainEntry {
            subdomain: "_xmpp-client._tcp",
            record_type: SRV,
            category: Communication,
        },
        SubdomainEntry {
            subdomain: "_xmpp-server._tcp",
            record_type: SRV,
            category: Communication,
        },
        // Calendar / Contacts
        SubdomainEntry {
            subdomain: "_caldavs._tcp",
            record_type: SRV,
            category: CalendarContacts,
        },
        SubdomainEntry {
            subdomain: "_carddavs._tcp",
            record_type: SRV,
            category: CalendarContacts,
        },
        // Infrastructure
        SubdomainEntry {
            subdomain: "_ldap._tcp",
            record_type: SRV,
            category: Infrastructure,
        },
        SubdomainEntry {
            subdomain: "_kerberos._tcp",
            record_type: SRV,
            category: Infrastructure,
        },
        SubdomainEntry {
            subdomain: "_kerberos._udp",
            record_type: SRV,
            category: Infrastructure,
        },
        // Modern Protocols
        SubdomainEntry {
            subdomain: "_matrix-fed._tcp",
            record_type: SRV,
            category: ModernProtocols,
        },
        SubdomainEntry {
            subdomain: "_stun._udp",
            record_type: SRV,
            category: ModernProtocols,
        },
        SubdomainEntry {
            subdomain: "_turn._udp",
            record_type: SRV,
            category: ModernProtocols,
        },
        SubdomainEntry {
            subdomain: "_turns._tcp",
            record_type: SRV,
            category: ModernProtocols,
        },
        // Verification / Metadata
        SubdomainEntry {
            subdomain: "_atproto",
            record_type: TXT,
            category: VerificationMetadata,
        },
        SubdomainEntry {
            subdomain: "_dnslink",
            record_type: TXT,
            category: VerificationMetadata,
        },
        SubdomainEntry {
            subdomain: "_domainconnect",
            record_type: TXT,
            category: VerificationMetadata,
        },
    ]
}

/// Returns extended (Tier 3+4) entries in addition to default entries.
fn extended_entries() -> Vec<SubdomainEntry> {
    use Category::*;
    use RecordType::*;

    vec![
        // Additional DANE ports
        SubdomainEntry {
            subdomain: "_dane._tcp",
            record_type: TLSA,
            category: TlsDane,
        },
        SubdomainEntry {
            subdomain: "_465._tcp",
            record_type: TLSA,
            category: TlsDane,
        },
        SubdomainEntry {
            subdomain: "_993._tcp",
            record_type: TLSA,
            category: TlsDane,
        },
        SubdomainEntry {
            subdomain: "_995._tcp",
            record_type: TLSA,
            category: TlsDane,
        },
        SubdomainEntry {
            subdomain: "_587._tcp",
            record_type: TLSA,
            category: TlsDane,
        },
        // Additional Communication
        SubdomainEntry {
            subdomain: "_h323cs._tcp",
            record_type: SRV,
            category: Communication,
        },
        SubdomainEntry {
            subdomain: "_h323ls._udp",
            record_type: SRV,
            category: Communication,
        },
        // Plain Calendar / Contacts
        SubdomainEntry {
            subdomain: "_caldav._tcp",
            record_type: SRV,
            category: CalendarContacts,
        },
        SubdomainEntry {
            subdomain: "_carddav._tcp",
            record_type: SRV,
            category: CalendarContacts,
        },
        // Additional Infrastructure
        SubdomainEntry {
            subdomain: "_kpasswd._tcp",
            record_type: SRV,
            category: Infrastructure,
        },
        SubdomainEntry {
            subdomain: "_kpasswd._udp",
            record_type: SRV,
            category: Infrastructure,
        },
        SubdomainEntry {
            subdomain: "_ntp._udp",
            record_type: SRV,
            category: Infrastructure,
        },
        SubdomainEntry {
            subdomain: "_http._tcp",
            record_type: SRV,
            category: Infrastructure,
        },
        SubdomainEntry {
            subdomain: "_https._tcp",
            record_type: SRV,
            category: Infrastructure,
        },
        SubdomainEntry {
            subdomain: "_vlmcs._tcp",
            record_type: SRV,
            category: Infrastructure,
        },
        // Legacy
        SubdomainEntry {
            subdomain: "_finger._tcp",
            record_type: SRV,
            category: Legacy,
        },
        SubdomainEntry {
            subdomain: "_nicname._tcp",
            record_type: SRV,
            category: Legacy,
        },
        // Gaming
        SubdomainEntry {
            subdomain: "_ts3._udp",
            record_type: SRV,
            category: Gaming,
        },
        SubdomainEntry {
            subdomain: "_minecraft._tcp",
            record_type: SRV,
            category: Gaming,
        },
        // Additional Email Authentication
        SubdomainEntry {
            subdomain: "_adsp._domainkey",
            record_type: TXT,
            category: EmailAuthentication,
        },
        SubdomainEntry {
            subdomain: "_mta-sts",
            record_type: CNAME,
            category: EmailAuthentication,
        },
        // Additional Verification / Metadata
        SubdomainEntry {
            subdomain: "_acme-challenge",
            record_type: TXT,
            category: VerificationMetadata,
        },
        SubdomainEntry {
            subdomain: "_dnsauth",
            record_type: TXT,
            category: VerificationMetadata,
        },
        SubdomainEntry {
            subdomain: "_amazonses",
            record_type: TXT,
            category: VerificationMetadata,
        },
        SubdomainEntry {
            subdomain: "_github-pages-challenge",
            record_type: TXT,
            category: VerificationMetadata,
        },
        SubdomainEntry {
            subdomain: "_google",
            record_type: TXT,
            category: VerificationMetadata,
        },
    ]
}

/// Returns all entries (default + extended).
pub fn all_entries() -> Vec<SubdomainEntry> {
    let mut entries = default_entries();
    entries.extend(extended_entries());
    entries
}
