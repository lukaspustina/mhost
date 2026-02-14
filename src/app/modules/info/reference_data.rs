// Copyright 2017-2021 Lukas Pustina <lukas@pustina.de>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#[derive(Debug)]
pub struct RecordTypeInfo {
    pub name: &'static str,
    pub summary: &'static str,
    pub detail: &'static str,
    pub rfc: Option<&'static str>,
    pub rfc_url: Option<&'static str>,
}

#[derive(Debug)]
pub struct TxtSubTypeInfo {
    pub name: &'static str,
    pub prefix: &'static str,
    pub summary: &'static str,
    pub detail: &'static str,
    pub rfc: Option<&'static str>,
    pub rfc_url: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Default,
    Extended,
}

#[derive(Debug)]
pub struct SubdomainInfo {
    pub subdomain: &'static str,
    pub record_type: &'static str,
    pub category: &'static str,
    pub summary: &'static str,
    pub detail: &'static str,
    pub rfc: Option<&'static str>,
    pub rfc_url: Option<&'static str>,
    pub tier: Tier,
}

#[derive(Debug)]
pub enum InfoEntry<'a> {
    RecordType(&'a RecordTypeInfo),
    TxtSubType(&'a TxtSubTypeInfo),
    Subdomain(&'a SubdomainInfo),
}

static RECORD_TYPES: &[RecordTypeInfo] = &[
    RecordTypeInfo {
        name: "A",
        summary: "IPv4 address",
        detail: "Maps a domain name to an IPv4 address. This is the most fundamental DNS record \
                 type — every domain that hosts a website or service needs at least one A record. \
                 When you type a domain name in your browser, the A record is what ultimately \
                 provides the IP address to connect to.",
        rfc: Some("RFC 1035"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc1035"),
    },
    RecordTypeInfo {
        name: "AAAA",
        summary: "IPv6 address",
        detail: "Maps a domain name to an IPv6 address. Functionally identical to the A record \
                 but for the newer IPv6 protocol. Increasingly important as IPv6 adoption grows.",
        rfc: Some("RFC 3596"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc3596"),
    },
    RecordTypeInfo {
        name: "ANAME",
        summary: "Alias for apex domains",
        detail: "An alias record for apex (root) domains, similar to CNAME but allowed at the \
                 zone apex. Unlike CNAME, which cannot coexist with other record types, ANAME \
                 resolves to the target's IP at query time. This is a draft standard not yet \
                 widely supported by all DNS providers.",
        rfc: Some("draft-ietf-dnsop-aname"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-aname"),
    },
    RecordTypeInfo {
        name: "CAA",
        summary: "Certification Authority Authorization",
        detail: "Specifies which Certificate Authorities (CAs) are allowed to issue TLS/SSL \
                 certificates for a domain. Helps prevent unauthorized certificate issuance by \
                 restricting which CAs can create certificates. CAs are required to check CAA \
                 records before issuing certificates.",
        rfc: Some("RFC 8659"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc8659"),
    },
    RecordTypeInfo {
        name: "CNAME",
        summary: "Canonical name (alias)",
        detail: "Creates an alias from one domain name to another (the \"canonical\" name). When \
                 a DNS resolver encounters a CNAME, it restarts the lookup using the target name. \
                 Cannot coexist with other record types at the same name, and cannot be used at \
                 the zone apex.",
        rfc: Some("RFC 1035"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc1035"),
    },
    RecordTypeInfo {
        name: "HINFO",
        summary: "Host information (CPU & OS)",
        detail: "Originally intended to describe the host's CPU type and operating system. \
                 Largely obsolete for its original purpose due to security concerns. Now commonly \
                 used in \"negative\" responses per RFC 8482 to minimize ANY query abuse.",
        rfc: Some("RFC 8482"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc8482"),
    },
    RecordTypeInfo {
        name: "HTTPS",
        summary: "HTTPS service binding",
        detail: "A specialized SVCB record for HTTPS services that enables clients to discover \
                 alternative endpoints, supported protocols (HTTP/2, HTTP/3), and ECH (Encrypted \
                 Client Hello) keys. Allows browsers to connect more efficiently by learning \
                 service parameters from DNS before the first HTTP request.",
        rfc: Some("RFC 9460"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc9460"),
    },
    RecordTypeInfo {
        name: "MX",
        summary: "Mail exchange",
        detail: "Specifies the mail servers responsible for receiving email for a domain, along \
                 with priority values. Lower priority numbers indicate preferred servers. Essential \
                 for email delivery — without MX records, mail falls back to the domain's A/AAAA \
                 records.",
        rfc: Some("RFC 1035"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc1035"),
    },
    RecordTypeInfo {
        name: "NAPTR",
        summary: "Naming Authority Pointer",
        detail: "Used for URI/service discovery through a series of rewriting rules. Commonly \
                 used in ENUM (telephone number to URI mapping), SIP, and other protocols that \
                 need to transform identifiers into service endpoints. Each record contains an \
                 order, preference, flags, service, regex, and replacement.",
        rfc: Some("RFC 3403"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc3403"),
    },
    RecordTypeInfo {
        name: "NS",
        summary: "Authoritative nameserver",
        detail: "Identifies the authoritative nameservers for a DNS zone. These records tell \
                 resolvers which servers hold the definitive records for a domain. Every domain \
                 must have at least two NS records for redundancy.",
        rfc: Some("RFC 1035"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc1035"),
    },
    RecordTypeInfo {
        name: "NULL",
        summary: "Null record (opaque data)",
        detail: "A record type that can hold arbitrary binary data up to 65535 bytes. Rarely \
                 used in practice and primarily exists for experimental purposes. Some applications \
                 use NULL records for tunneling or storing opaque data in DNS.",
        rfc: Some("RFC 1035"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc1035"),
    },
    RecordTypeInfo {
        name: "OPENPGPKEY",
        summary: "OpenPGP public key",
        detail: "Publishes OpenPGP public keys in DNS, allowing email clients to discover \
                 encryption keys for a recipient via DNS rather than keyservers. The key is stored \
                 at a hashed version of the email local part. Requires DNSSEC for secure key \
                 retrieval.",
        rfc: Some("RFC 7929"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc7929"),
    },
    RecordTypeInfo {
        name: "PTR",
        summary: "Pointer (reverse DNS)",
        detail: "Maps an IP address back to a domain name (reverse DNS). Used to verify that an \
                 IP address corresponds to a claimed hostname. Essential for email deliverability, \
                 as many mail servers reject messages from IPs without valid PTR records.",
        rfc: Some("RFC 1035"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc1035"),
    },
    RecordTypeInfo {
        name: "SOA",
        summary: "Start of Authority",
        detail: "Defines key parameters for a DNS zone: the primary nameserver, the responsible \
                 party's email, and timing parameters for zone transfers and caching. Every DNS \
                 zone must have exactly one SOA record at its apex.",
        rfc: Some("RFC 1035"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc1035"),
    },
    RecordTypeInfo {
        name: "SRV",
        summary: "Service locator",
        detail: "Specifies the hostname and port for a particular service, enabling service \
                 discovery via DNS. Includes priority and weight fields for load balancing across \
                 multiple servers. Widely used for protocols like SIP, XMPP, LDAP, and Kerberos.",
        rfc: Some("RFC 2782"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc2782"),
    },
    RecordTypeInfo {
        name: "SSHFP",
        summary: "SSH fingerprint",
        detail: "Stores SSH host key fingerprints in DNS, allowing SSH clients to verify server \
                 host keys via DNSSEC rather than trust-on-first-use. Each record contains an \
                 algorithm identifier, fingerprint type, and the fingerprint data. Requires \
                 DNSSEC to be useful for verification.",
        rfc: Some("RFC 4255"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc4255"),
    },
    RecordTypeInfo {
        name: "SVCB",
        summary: "Service binding",
        detail: "A general-purpose service binding record that maps a service name to alternative \
                 endpoints with associated parameters. The base record type for HTTPS records. \
                 Supports features like alternative endpoints, protocol negotiation, and ECH \
                 configuration.",
        rfc: Some("RFC 9460"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc9460"),
    },
    RecordTypeInfo {
        name: "TLSA",
        summary: "TLS certificate association (DANE)",
        detail: "Associates a TLS certificate or public key with a domain name, enabling \
                 DNS-based Authentication of Named Entities (DANE). Allows domain owners to pin \
                 specific certificates or CAs in DNS, providing an alternative or supplement to \
                 the public CA system. Requires DNSSEC for security.",
        rfc: Some("RFC 6698"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6698"),
    },
    RecordTypeInfo {
        name: "TXT",
        summary: "Text record",
        detail: "A versatile record type that holds arbitrary text strings. Originally intended \
                 for human-readable notes, TXT records are now widely used for machine-readable \
                 data including SPF email authentication, DMARC policies, domain ownership \
                 verification, and various other protocols.",
        rfc: Some("RFC 1035"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc1035"),
    },
];

static TXT_SUB_TYPES: &[TxtSubTypeInfo] = &[
    TxtSubTypeInfo {
        name: "SPF",
        prefix: "v=spf1",
        summary: "Sender Policy Framework",
        detail: "Defines which mail servers are authorized to send email on behalf of a domain. \
                 The SPF policy lists allowed IP ranges, hostnames, and include directives. \
                 Receiving mail servers check SPF to detect forged sender addresses.",
        rfc: Some("RFC 7208"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc7208"),
    },
    TxtSubTypeInfo {
        name: "DMARC",
        prefix: "v=DMARC1",
        summary: "Domain-based Message Authentication",
        detail: "Builds on SPF and DKIM to give domain owners control over how unauthenticated \
                 mail is handled. Specifies policies (none/quarantine/reject) and reporting \
                 addresses. Published at _dmarc.<domain>.",
        rfc: Some("RFC 7489"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc7489"),
    },
    TxtSubTypeInfo {
        name: "MTA-STS",
        prefix: "v=STSv1",
        summary: "MTA Strict Transport Security",
        detail: "Tells sending mail servers that the domain requires TLS for SMTP connections. \
                 The TXT record provides a policy ID, while the full policy is hosted via HTTPS. \
                 Prevents downgrade attacks on mail transport.",
        rfc: Some("RFC 8461"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc8461"),
    },
    TxtSubTypeInfo {
        name: "TLS-RPT",
        prefix: "v=TLSRPTv1",
        summary: "SMTP TLS Reporting",
        detail: "Allows domains to request reports about TLS connection failures from sending \
                 mail servers. Specifies where failure reports should be sent. Helps domain \
                 operators detect email delivery issues.",
        rfc: Some("RFC 8460"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc8460"),
    },
    TxtSubTypeInfo {
        name: "BIMI",
        prefix: "v=BIMI1",
        summary: "Brand Indicators for Message Identification",
        detail: "Allows organizations to display their logo alongside authenticated emails in \
                 supported mail clients. Provides a URL to the brand's SVG logo and an optional \
                 VMC certificate.",
        rfc: None,
        rfc_url: Some("https://bimigroup.org/implementation-guide/"),
    },
    TxtSubTypeInfo {
        name: "Domain Verification",
        prefix: "<verifier>-<scope>-verification=<id>",
        summary: "Third-party domain ownership verification",
        detail: "Services like Google, Facebook, and others use these TXT records to verify that \
                 the person managing DNS also controls the domain. Each service provides a unique \
                 verification token.",
        rfc: None,
        rfc_url: None,
    },
];

static SUBDOMAINS: &[SubdomainInfo] = &[
    // Email Authentication — Default
    SubdomainInfo {
        subdomain: "_dmarc",
        record_type: "TXT",
        category: "Email Authentication",
        summary: "DMARC policy",
        detail: "DMARC policy record specifying how unauthenticated mail should be handled and \
                 where aggregate/forensic reports should be sent.",
        rfc: Some("RFC 7489"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc7489"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_mta-sts",
        record_type: "TXT",
        category: "Email Authentication",
        summary: "MTA-STS policy ID",
        detail: "MTA-STS policy ID record indicating the current version of the domain's \
                 MTA-STS policy hosted via HTTPS.",
        rfc: Some("RFC 8461"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc8461"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_smtp._tls",
        record_type: "TXT",
        category: "Email Authentication",
        summary: "TLS reporting",
        detail: "TLS-RPT reporting configuration telling senders where to submit reports about \
                 TLS connection failures during mail delivery.",
        rfc: Some("RFC 8460"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc8460"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "default._bimi",
        record_type: "TXT",
        category: "Email Authentication",
        summary: "Brand indicators",
        detail: "BIMI indicator record pointing to the organization's brand logo SVG and \
                 optional Verified Mark Certificate (VMC).",
        rfc: None,
        rfc_url: Some("https://bimigroup.org/implementation-guide/"),
        tier: Tier::Default,
    },
    // Email Services — Default
    SubdomainInfo {
        subdomain: "_submission._tcp",
        record_type: "SRV",
        category: "Email Services",
        summary: "Mail submission",
        detail: "Mail submission service (port 587), used by email clients to discover the \
                 outgoing mail server.",
        rfc: Some("RFC 6186"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6186"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_submissions._tcp",
        record_type: "SRV",
        category: "Email Services",
        summary: "Mail submission (TLS)",
        detail: "Mail submission over implicit TLS (port 465), the TLS-secured variant of mail \
                 submission.",
        rfc: Some("RFC 8314"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc8314"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_imap._tcp",
        record_type: "SRV",
        category: "Email Services",
        summary: "IMAP",
        detail: "IMAP mail access service, allowing email clients to discover the incoming mail \
                 server using IMAP with STARTTLS.",
        rfc: Some("RFC 6186"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6186"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_imaps._tcp",
        record_type: "SRV",
        category: "Email Services",
        summary: "IMAP (TLS)",
        detail: "IMAP over implicit TLS (port 993), the TLS-secured variant of IMAP access.",
        rfc: Some("RFC 8314"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc8314"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_pop3._tcp",
        record_type: "SRV",
        category: "Email Services",
        summary: "POP3",
        detail: "POP3 mail access service for clients that download and optionally delete mail \
                 from the server.",
        rfc: Some("RFC 6186"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6186"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_pop3s._tcp",
        record_type: "SRV",
        category: "Email Services",
        summary: "POP3 (TLS)",
        detail: "POP3 over implicit TLS (port 995), the TLS-secured variant of POP3.",
        rfc: Some("RFC 8314"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc8314"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_autodiscover._tcp",
        record_type: "SRV",
        category: "Email Services",
        summary: "Autodiscovery",
        detail: "Microsoft Exchange/Outlook autodiscovery service for automatic email client \
                 configuration.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Default,
    },
    // TLS / DANE — Default
    SubdomainInfo {
        subdomain: "_443._tcp",
        record_type: "TLSA",
        category: "TLS / DANE",
        summary: "HTTPS DANE",
        detail: "DANE record for HTTPS on port 443, pinning the TLS certificate or CA for the \
                 domain's web server.",
        rfc: Some("RFC 6698"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6698"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_25._tcp",
        record_type: "TLSA",
        category: "TLS / DANE",
        summary: "SMTP DANE",
        detail: "DANE record for SMTP on port 25, enabling authenticated TLS for mail \
                 server-to-server communication.",
        rfc: Some("RFC 7672"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc7672"),
        tier: Tier::Default,
    },
    // Communication — Default
    SubdomainInfo {
        subdomain: "_sip._tcp",
        record_type: "SRV",
        category: "Communication",
        summary: "SIP over TCP",
        detail: "Session Initiation Protocol endpoint for VoIP and video calling over TCP.",
        rfc: Some("RFC 3263"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc3263"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_sip._udp",
        record_type: "SRV",
        category: "Communication",
        summary: "SIP over UDP",
        detail: "Session Initiation Protocol endpoint for VoIP and video calling over UDP.",
        rfc: Some("RFC 3263"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc3263"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_sips._tcp",
        record_type: "SRV",
        category: "Communication",
        summary: "SIP over TLS",
        detail: "SIP over TLS for encrypted voice/video communication.",
        rfc: Some("RFC 3263"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc3263"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_xmpp-client._tcp",
        record_type: "SRV",
        category: "Communication",
        summary: "XMPP client",
        detail: "XMPP (Jabber) client connection endpoint for instant messaging.",
        rfc: Some("RFC 6120"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6120"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_xmpp-server._tcp",
        record_type: "SRV",
        category: "Communication",
        summary: "XMPP server",
        detail: "XMPP server-to-server federation endpoint.",
        rfc: Some("RFC 6120"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6120"),
        tier: Tier::Default,
    },
    // Calendar / Contacts — Default
    SubdomainInfo {
        subdomain: "_caldavs._tcp",
        record_type: "SRV",
        category: "Calendar / Contacts",
        summary: "CalDAV (TLS)",
        detail: "CalDAV over TLS, allowing calendar applications to discover the calendar server.",
        rfc: Some("RFC 6764"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6764"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_carddavs._tcp",
        record_type: "SRV",
        category: "Calendar / Contacts",
        summary: "CardDAV (TLS)",
        detail: "CardDAV over TLS, allowing contact applications to discover the address book \
                 server.",
        rfc: Some("RFC 6764"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6764"),
        tier: Tier::Default,
    },
    // Infrastructure — Default
    SubdomainInfo {
        subdomain: "_ldap._tcp",
        record_type: "SRV",
        category: "Infrastructure",
        summary: "LDAP",
        detail: "LDAP directory service, used for user authentication and directory lookups in \
                 enterprise environments.",
        rfc: Some("RFC 2782"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc2782"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_kerberos._tcp",
        record_type: "SRV",
        category: "Infrastructure",
        summary: "Kerberos TCP",
        detail: "Kerberos authentication service endpoint for single sign-on in enterprise \
                 networks.",
        rfc: Some("RFC 4120"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc4120"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_kerberos._udp",
        record_type: "SRV",
        category: "Infrastructure",
        summary: "Kerberos UDP",
        detail: "Kerberos authentication service endpoint over UDP.",
        rfc: Some("RFC 4120"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc4120"),
        tier: Tier::Default,
    },
    // Modern Protocols — Default
    SubdomainInfo {
        subdomain: "_matrix-fed._tcp",
        record_type: "SRV",
        category: "Modern Protocols",
        summary: "Matrix federation",
        detail: "Matrix federation endpoint for decentralized communication (chat, VoIP).",
        rfc: None,
        rfc_url: None,
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_stun._udp",
        record_type: "SRV",
        category: "Modern Protocols",
        summary: "STUN",
        detail: "STUN (Session Traversal Utilities for NAT) service for NAT traversal in WebRTC \
                 and VoIP.",
        rfc: Some("RFC 5389"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc5389"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_turn._udp",
        record_type: "SRV",
        category: "Modern Protocols",
        summary: "TURN",
        detail: "TURN relay service for media relay when direct peer-to-peer connections fail.",
        rfc: Some("RFC 5766"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc5766"),
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_turns._tcp",
        record_type: "SRV",
        category: "Modern Protocols",
        summary: "TURN (TLS)",
        detail: "TURN relay service over TLS for secure media relay.",
        rfc: Some("RFC 5766"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc5766"),
        tier: Tier::Default,
    },
    // Verification / Metadata — Default
    SubdomainInfo {
        subdomain: "_atproto",
        record_type: "TXT",
        category: "Verification / Metadata",
        summary: "Bluesky verification",
        detail: "AT Protocol (Bluesky) domain verification, proving ownership of a domain as a \
                 decentralized identifier.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_dnslink",
        record_type: "TXT",
        category: "Verification / Metadata",
        summary: "IPFS / content addressing",
        detail: "DNSLink record pointing to IPFS or other content-addressed resources, enabling \
                 human-readable names for distributed content.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Default,
    },
    SubdomainInfo {
        subdomain: "_domainconnect",
        record_type: "TXT",
        category: "Verification / Metadata",
        summary: "Domain Connect protocol",
        detail: "Domain Connect protocol endpoint enabling one-click DNS configuration by \
                 service providers.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Default,
    },
    // --- Extended entries ---
    // TLS / DANE — Extended
    SubdomainInfo {
        subdomain: "_dane._tcp",
        record_type: "TLSA",
        category: "TLS / DANE",
        summary: "Generic DANE",
        detail: "Generic DANE record for services not on a specific well-known port.",
        rfc: Some("RFC 6698"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6698"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_465._tcp",
        record_type: "TLSA",
        category: "TLS / DANE",
        summary: "SMTPS DANE",
        detail: "DANE record for SMTPS (implicit TLS SMTP) on port 465.",
        rfc: Some("RFC 6698"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6698"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_993._tcp",
        record_type: "TLSA",
        category: "TLS / DANE",
        summary: "IMAPS DANE",
        detail: "DANE record for IMAPS on port 993.",
        rfc: Some("RFC 6698"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6698"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_995._tcp",
        record_type: "TLSA",
        category: "TLS / DANE",
        summary: "POP3S DANE",
        detail: "DANE record for POP3S on port 995.",
        rfc: Some("RFC 6698"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6698"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_587._tcp",
        record_type: "TLSA",
        category: "TLS / DANE",
        summary: "Submission DANE",
        detail: "DANE record for mail submission on port 587.",
        rfc: Some("RFC 6698"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6698"),
        tier: Tier::Extended,
    },
    // Communication — Extended
    SubdomainInfo {
        subdomain: "_h323cs._tcp",
        record_type: "SRV",
        category: "Communication",
        summary: "H.323",
        detail: "H.323 call signaling for legacy video conferencing systems.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_h323ls._udp",
        record_type: "SRV",
        category: "Communication",
        summary: "H.323 location",
        detail: "H.323 location service for gatekeeper discovery.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Extended,
    },
    // Calendar / Contacts — Extended
    SubdomainInfo {
        subdomain: "_caldav._tcp",
        record_type: "SRV",
        category: "Calendar / Contacts",
        summary: "CalDAV (plain)",
        detail: "CalDAV without TLS (plain HTTP), the unencrypted variant.",
        rfc: Some("RFC 6764"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6764"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_carddav._tcp",
        record_type: "SRV",
        category: "Calendar / Contacts",
        summary: "CardDAV (plain)",
        detail: "CardDAV without TLS (plain HTTP), the unencrypted variant.",
        rfc: Some("RFC 6764"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc6764"),
        tier: Tier::Extended,
    },
    // Infrastructure — Extended
    SubdomainInfo {
        subdomain: "_kpasswd._tcp",
        record_type: "SRV",
        category: "Infrastructure",
        summary: "Kerberos password",
        detail: "Kerberos password change service over TCP.",
        rfc: Some("RFC 4120"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc4120"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_kpasswd._udp",
        record_type: "SRV",
        category: "Infrastructure",
        summary: "Kerberos password",
        detail: "Kerberos password change service over UDP.",
        rfc: Some("RFC 4120"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc4120"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_ntp._udp",
        record_type: "SRV",
        category: "Infrastructure",
        summary: "NTP",
        detail: "Network Time Protocol service for time synchronization.",
        rfc: Some("RFC 5905"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc5905"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_http._tcp",
        record_type: "SRV",
        category: "Infrastructure",
        summary: "HTTP service",
        detail: "Generic HTTP service discovery.",
        rfc: Some("RFC 2782"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc2782"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_https._tcp",
        record_type: "SRV",
        category: "Infrastructure",
        summary: "HTTPS service",
        detail: "Generic HTTPS service discovery.",
        rfc: Some("RFC 2782"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc2782"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_vlmcs._tcp",
        record_type: "SRV",
        category: "Infrastructure",
        summary: "KMS activation",
        detail: "Microsoft Key Management Service (KMS) for volume license activation.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Extended,
    },
    // Legacy — Extended
    SubdomainInfo {
        subdomain: "_finger._tcp",
        record_type: "SRV",
        category: "Legacy",
        summary: "Finger protocol",
        detail: "Finger protocol service for user information lookup (largely obsolete).",
        rfc: Some("RFC 1288"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc1288"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_nicname._tcp",
        record_type: "SRV",
        category: "Legacy",
        summary: "WHOIS",
        detail: "WHOIS service for domain registration information lookup.",
        rfc: Some("RFC 3912"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc3912"),
        tier: Tier::Extended,
    },
    // Gaming — Extended
    SubdomainInfo {
        subdomain: "_ts3._udp",
        record_type: "SRV",
        category: "Gaming",
        summary: "TeamSpeak 3",
        detail: "TeamSpeak 3 voice communication server discovery.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_minecraft._tcp",
        record_type: "SRV",
        category: "Gaming",
        summary: "Minecraft",
        detail: "Minecraft Java Edition server discovery.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Extended,
    },
    // Email Authentication — Extended
    SubdomainInfo {
        subdomain: "_adsp._domainkey",
        record_type: "TXT",
        category: "Email Authentication",
        summary: "ADSP (deprecated)",
        detail: "Author Domain Signing Practices, a deprecated extension to DKIM that specified \
                 signing policy. Superseded by DMARC.",
        rfc: Some("RFC 5617"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc5617"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_mta-sts",
        record_type: "CNAME",
        category: "Email Authentication",
        summary: "MTA-STS alias check",
        detail: "Checks for a CNAME alias on the MTA-STS subdomain, which may indicate delegated \
                 MTA-STS hosting.",
        rfc: Some("RFC 8461"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc8461"),
        tier: Tier::Extended,
    },
    // Verification / Metadata — Extended
    SubdomainInfo {
        subdomain: "_acme-challenge",
        record_type: "TXT",
        category: "Verification / Metadata",
        summary: "ACME DNS-01",
        detail: "ACME DNS-01 challenge records used by Let's Encrypt and other CAs to verify \
                 domain ownership during certificate issuance.",
        rfc: Some("RFC 8555"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc8555"),
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_dnsauth",
        record_type: "TXT",
        category: "Verification / Metadata",
        summary: "DNS auth tokens",
        detail: "DNS authorization tokens used by various services for domain verification.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_amazonses",
        record_type: "TXT",
        category: "Verification / Metadata",
        summary: "Amazon SES",
        detail: "Amazon Simple Email Service domain verification token.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_github-pages-challenge",
        record_type: "TXT",
        category: "Verification / Metadata",
        summary: "GitHub Pages",
        detail: "GitHub Pages domain verification token.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Extended,
    },
    SubdomainInfo {
        subdomain: "_google",
        record_type: "TXT",
        category: "Verification / Metadata",
        summary: "Google Workspace",
        detail: "Google Workspace domain verification token.",
        rfc: None,
        rfc_url: None,
        tier: Tier::Extended,
    },
];

pub fn record_types() -> &'static [RecordTypeInfo] {
    RECORD_TYPES
}

pub fn txt_sub_types() -> &'static [TxtSubTypeInfo] {
    TXT_SUB_TYPES
}

pub fn subdomains() -> &'static [SubdomainInfo] {
    SUBDOMAINS
}

pub fn find(topic: &str) -> Option<InfoEntry<'_>> {
    let topic_lower = topic.to_lowercase();

    // Search record types (case-insensitive)
    if let Some(rt) = RECORD_TYPES.iter().find(|r| r.name.to_lowercase() == topic_lower) {
        return Some(InfoEntry::RecordType(rt));
    }

    // Search TXT sub-types (case-insensitive)
    if let Some(txt) = TXT_SUB_TYPES.iter().find(|t| t.name.to_lowercase() == topic_lower) {
        return Some(InfoEntry::TxtSubType(txt));
    }

    // Search subdomains (case-insensitive, exact match)
    if let Some(sub) = SUBDOMAINS.iter().find(|s| s.subdomain.to_lowercase() == topic_lower) {
        return Some(InfoEntry::Subdomain(sub));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_record_type_a() {
        let entry = find("A").unwrap();
        assert!(matches!(entry, InfoEntry::RecordType(info) if info.name == "A"));
    }

    #[test]
    fn find_record_type_case_insensitive() {
        let entry = find("a").unwrap();
        assert!(matches!(entry, InfoEntry::RecordType(info) if info.name == "A"));
    }

    #[test]
    fn find_record_type_sshfp() {
        let entry = find("SSHFP").unwrap();
        assert!(matches!(entry, InfoEntry::RecordType(info) if info.name == "SSHFP"));
    }

    #[test]
    fn find_txt_sub_type_spf() {
        let entry = find("SPF").unwrap();
        assert!(matches!(entry, InfoEntry::TxtSubType(info) if info.name == "SPF"));
    }

    #[test]
    fn find_txt_sub_type_case_insensitive() {
        let entry = find("dmarc").unwrap();
        assert!(matches!(entry, InfoEntry::TxtSubType(info) if info.name == "DMARC"));
    }

    #[test]
    fn find_subdomain_dmarc() {
        let entry = find("_dmarc").unwrap();
        assert!(matches!(entry, InfoEntry::Subdomain(info) if info.subdomain == "_dmarc"));
    }

    #[test]
    fn find_nonexistent() {
        assert!(find("nonexistent").is_none());
    }

    #[test]
    fn record_types_not_empty() {
        assert!(!record_types().is_empty());
        // Should contain all SUPPORTED_RECORD_TYPES from cli_parser (minus ANY)
        let names: Vec<&str> = record_types().iter().map(|r| r.name).collect();
        assert!(names.contains(&"A"));
        assert!(names.contains(&"AAAA"));
        assert!(names.contains(&"MX"));
        assert!(names.contains(&"TXT"));
        assert!(names.contains(&"SSHFP"));
        assert!(names.contains(&"TLSA"));
        assert!(names.contains(&"CAA"));
    }

    #[test]
    fn txt_sub_types_not_empty() {
        assert!(!txt_sub_types().is_empty());
        let names: Vec<&str> = txt_sub_types().iter().map(|t| t.name).collect();
        assert!(names.contains(&"SPF"));
        assert!(names.contains(&"DMARC"));
    }

    #[test]
    fn subdomains_not_empty() {
        assert!(!subdomains().is_empty());
        let subs: Vec<&str> = subdomains().iter().map(|s| s.subdomain).collect();
        assert!(subs.contains(&"_dmarc"));
        assert!(subs.contains(&"_443._tcp"));
    }

    #[test]
    fn all_supported_record_types_have_info() {
        // These are the SUPPORTED_RECORD_TYPES from cli_parser.rs minus ANY (which is a
        // meta-type, not a real record type to document)
        let supported = [
            "A", "AAAA", "ANAME", "CAA", "CNAME", "HINFO", "HTTPS", "MX", "NAPTR", "NULL", "NS",
            "OPENPGPKEY", "PTR", "SOA", "SRV", "SSHFP", "SVCB", "TLSA", "TXT",
        ];
        let info_names: Vec<&str> = record_types().iter().map(|r| r.name).collect();
        for name in &supported {
            assert!(info_names.contains(name), "Missing reference data for record type {name}");
        }
    }

    #[test]
    fn subdomains_match_subdomain_spec_count() {
        // Our reference data should cover all non-apex entries from subdomain_spec
        use crate::app::modules::domain_lookup::subdomain_spec;
        let spec_entries: Vec<_> = subdomain_spec::all_entries()
            .into_iter()
            .filter(|e| !e.subdomain.is_empty())
            .collect();
        let ref_subdomains: Vec<(&str, &str)> = subdomains()
            .iter()
            .map(|s| (s.subdomain, s.record_type))
            .collect();
        for entry in &spec_entries {
            let rt_str: &str = entry.record_type.into();
            assert!(
                ref_subdomains.contains(&(entry.subdomain, rt_str)),
                "Missing reference data for subdomain {} ({})",
                entry.subdomain,
                rt_str
            );
        }
    }

    #[test]
    fn all_record_type_info_has_detail() {
        for rt in record_types() {
            assert!(!rt.detail.is_empty(), "Record type {} has empty detail", rt.name);
            assert!(!rt.summary.is_empty(), "Record type {} has empty summary", rt.name);
        }
    }

    #[test]
    fn all_subdomain_info_has_detail() {
        for sub in subdomains() {
            assert!(!sub.detail.is_empty(), "Subdomain {} has empty detail", sub.subdomain);
            assert!(!sub.summary.is_empty(), "Subdomain {} has empty summary", sub.subdomain);
        }
    }
}
