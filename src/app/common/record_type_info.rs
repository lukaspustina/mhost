#[derive(Debug)]
pub struct RecordTypeInfo {
    pub name: &'static str,
    pub summary: &'static str,
    pub detail: &'static str,
    pub rfc: Option<&'static str>,
    pub rfc_url: Option<&'static str>,
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
        name: "DNSKEY",
        summary: "DNSSEC public key",
        detail: "Holds a public key used for DNSSEC validation. Resolvers use DNSKEY records to \
                 verify RRSIG signatures over DNS record sets, establishing a chain of trust from \
                 the DNS root to the queried zone. Each key has flags indicating whether it is a \
                 Zone Signing Key (ZSK) or Key Signing Key (KSK).",
        rfc: Some("RFC 4034"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc4034"),
    },
    RecordTypeInfo {
        name: "DS",
        summary: "Delegation Signer",
        detail: "Contains a hash of a child zone's DNSKEY record, published in the parent zone \
                 to establish the DNSSEC chain of trust across zone boundaries. When a resolver \
                 follows a delegation, it uses the DS record from the parent to verify the child \
                 zone's DNSKEY.",
        rfc: Some("RFC 4034"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc4034"),
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
        name: "NSEC",
        summary: "Next Secure record",
        detail: "Provides authenticated denial of existence in DNSSEC by listing the next domain \
                 name in the zone and the record types that exist at the current name. When a \
                 queried name or type does not exist, the server returns NSEC records proving the \
                 gap. Can expose all names in a zone (zone walking).",
        rfc: Some("RFC 4034"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc4034"),
    },
    RecordTypeInfo {
        name: "NSEC3",
        summary: "Next Secure v3 (hashed)",
        detail: "An alternative to NSEC that uses hashed owner names instead of plaintext, \
                 preventing trivial zone enumeration. Provides the same authenticated denial of \
                 existence as NSEC but with improved privacy. Uses an iterated hash with a salt \
                 to obscure the original domain names.",
        rfc: Some("RFC 5155"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc5155"),
    },
    RecordTypeInfo {
        name: "NSEC3PARAM",
        summary: "NSEC3 hash parameters",
        detail: "Published at the zone apex to communicate the hash algorithm, iteration count, \
                 and salt used to generate NSEC3 records in the zone. Authoritative servers use \
                 these parameters when computing NSEC3 hashes for denial-of-existence responses.",
        rfc: Some("RFC 5155"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc5155"),
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
        name: "RRSIG",
        summary: "DNSSEC signature",
        detail: "Contains a cryptographic signature over a DNS record set (RRset), allowing \
                 resolvers to verify the authenticity and integrity of DNS responses. Each RRSIG \
                 covers one specific record type at a specific name and has an expiration time. \
                 Verified using the corresponding DNSKEY record.",
        rfc: Some("RFC 4034"),
        rfc_url: Some("https://datatracker.ietf.org/doc/html/rfc4034"),
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

pub fn record_types() -> &'static [RecordTypeInfo] {
    RECORD_TYPES
}

pub fn find(name: &str) -> Option<&'static RecordTypeInfo> {
    RECORD_TYPES.iter().find(|r| r.name.eq_ignore_ascii_case(name))
}
