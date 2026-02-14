# DNS Record Types & Well-Known Subdomains Reference

This document covers the DNS record types supported by mhost, the parsed TXT sub-types for human-readable output, and the well-known subdomains queried by the `domain-lookup` command.

## Supported DNS Record Types

| Record Type | Description | RFC |
|---|---|---|
| A | IPv4 address | [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) |
| AAAA | IPv6 address | [RFC 3596](https://datatracker.ietf.org/doc/html/rfc3596) |
| ANAME | Alias for apex domains | [draft-ietf-dnsop-aname](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-aname) |
| CAA | Certification Authority Authorization | [RFC 8659](https://datatracker.ietf.org/doc/html/rfc8659) |
| CNAME | Canonical name (alias) | [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) |
| HINFO | Host information (CPU & OS) | [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482) |
| HTTPS | HTTPS service binding | [RFC 9460](https://datatracker.ietf.org/doc/html/rfc9460) |
| MX | Mail exchange | [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) |
| NAPTR | Naming Authority Pointer | [RFC 3403](https://datatracker.ietf.org/doc/html/rfc3403) |
| NS | Authoritative nameserver | [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) |
| NULL | Null record (opaque data) | [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) |
| OPENPGPKEY | OpenPGP public key | [RFC 7929](https://datatracker.ietf.org/doc/html/rfc7929) |
| PTR | Pointer (reverse DNS) | [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) |
| SOA | Start of Authority | [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) |
| SRV | Service locator | [RFC 2782](https://datatracker.ietf.org/doc/html/rfc2782) |
| SSHFP | SSH fingerprint | [RFC 4255](https://datatracker.ietf.org/doc/html/rfc4255) |
| SVCB | Service binding | [RFC 9460](https://datatracker.ietf.org/doc/html/rfc9460) |
| TLSA | TLS certificate association (DANE) | [RFC 6698](https://datatracker.ietf.org/doc/html/rfc6698) |
| TXT | Text record | [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) |

## Parsed TXT Sub-Types

mhost parses well-known TXT record formats into structured, human-readable output.

| Sub-Type | Prefix / Detection | Description | RFC |
|---|---|---|---|
| SPF | `v=spf1` | Sender Policy Framework | [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208) |
| DMARC | `v=DMARC1` | Domain-based Message Authentication | [RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489) |
| MTA-STS | `v=STSv1` | MTA Strict Transport Security | [RFC 8461](https://datatracker.ietf.org/doc/html/rfc8461) |
| TLS-RPT | `v=TLSRPTv1` | SMTP TLS Reporting | [RFC 8460](https://datatracker.ietf.org/doc/html/rfc8460) |
| BIMI | `v=BIMI1` | Brand Indicators for Message Identification | [BIMI spec](https://bimigroup.org/implementation-guide/) |
| Domain Verification | `<verifier>-<scope>-verification=<id>` | Third-party domain ownership verification | Various |

## Well-Known Subdomains (`domain-lookup`)

The `domain-lookup` command queries the apex domain plus well-known subdomains in a single operation.

### Default entries (queried always)

| Subdomain | Record Type | Category | RFC / Reference | Notes |
|---|---|---|---|---|
| *(apex)* | A, AAAA, MX, NS, SOA, CAA, HTTPS, TXT, CNAME, SVCB, NAPTR, SSHFP | Apex | Various | Core domain records |
| `_dmarc` | TXT | Email Authentication | [RFC 7489](https://datatracker.ietf.org/doc/html/rfc7489) | DMARC policy |
| `_mta-sts` | TXT | Email Authentication | [RFC 8461](https://datatracker.ietf.org/doc/html/rfc8461) | MTA-STS policy ID |
| `_smtp._tls` | TXT | Email Authentication | [RFC 8460](https://datatracker.ietf.org/doc/html/rfc8460) | TLS reporting |
| `default._bimi` | TXT | Email Authentication | BIMI spec | Brand indicators |
| `_submission._tcp` | SRV | Email Services | [RFC 6186](https://datatracker.ietf.org/doc/html/rfc6186) | Mail submission |
| `_submissions._tcp` | SRV | Email Services | [RFC 8314](https://datatracker.ietf.org/doc/html/rfc8314) | Mail submission (TLS) |
| `_imap._tcp` | SRV | Email Services | [RFC 6186](https://datatracker.ietf.org/doc/html/rfc6186) | IMAP |
| `_imaps._tcp` | SRV | Email Services | [RFC 8314](https://datatracker.ietf.org/doc/html/rfc8314) | IMAP (TLS) |
| `_pop3._tcp` | SRV | Email Services | [RFC 6186](https://datatracker.ietf.org/doc/html/rfc6186) | POP3 |
| `_pop3s._tcp` | SRV | Email Services | [RFC 8314](https://datatracker.ietf.org/doc/html/rfc8314) | POP3 (TLS) |
| `_autodiscover._tcp` | SRV | Email Services | MS Exchange | Autodiscovery |
| `_443._tcp` | TLSA | TLS / DANE | [RFC 6698](https://datatracker.ietf.org/doc/html/rfc6698) | HTTPS DANE |
| `_25._tcp` | TLSA | TLS / DANE | [RFC 7672](https://datatracker.ietf.org/doc/html/rfc7672) | SMTP DANE |
| `_sip._tcp` | SRV | Communication | [RFC 3263](https://datatracker.ietf.org/doc/html/rfc3263) | SIP over TCP |
| `_sip._udp` | SRV | Communication | [RFC 3263](https://datatracker.ietf.org/doc/html/rfc3263) | SIP over UDP |
| `_sips._tcp` | SRV | Communication | [RFC 3263](https://datatracker.ietf.org/doc/html/rfc3263) | SIP over TLS |
| `_xmpp-client._tcp` | SRV | Communication | [RFC 6120](https://datatracker.ietf.org/doc/html/rfc6120) | XMPP client |
| `_xmpp-server._tcp` | SRV | Communication | [RFC 6120](https://datatracker.ietf.org/doc/html/rfc6120) | XMPP server |
| `_caldavs._tcp` | SRV | Calendar / Contacts | [RFC 6764](https://datatracker.ietf.org/doc/html/rfc6764) | CalDAV (TLS) |
| `_carddavs._tcp` | SRV | Calendar / Contacts | [RFC 6764](https://datatracker.ietf.org/doc/html/rfc6764) | CardDAV (TLS) |
| `_ldap._tcp` | SRV | Infrastructure | [RFC 2782](https://datatracker.ietf.org/doc/html/rfc2782) | LDAP |
| `_kerberos._tcp` | SRV | Infrastructure | [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120) | Kerberos TCP |
| `_kerberos._udp` | SRV | Infrastructure | [RFC 4120](https://datatracker.ietf.org/doc/html/rfc4120) | Kerberos UDP |
| `_matrix-fed._tcp` | SRV | Modern Protocols | Matrix spec | Matrix federation |
| `_stun._udp` | SRV | Modern Protocols | [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389) | STUN |
| `_turn._udp` | SRV | Modern Protocols | [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) | TURN |
| `_turns._tcp` | SRV | Modern Protocols | [RFC 5766](https://datatracker.ietf.org/doc/html/rfc5766) | TURN (TLS) |
| `_atproto` | TXT | Verification / Metadata | AT Protocol | Bluesky verification |
| `_dnslink` | TXT | Verification / Metadata | DNSLink spec | IPFS / content addressing |
| `_domainconnect` | TXT | Verification / Metadata | Domain Connect | Domain Connect protocol |

### Extended entries (`--all` flag)

These additional subdomains are queried when `--all` is passed:

| Subdomain | Record Type | Category | Notes |
|---|---|---|---|
| `_dane._tcp` | TLSA | TLS / DANE | Generic DANE |
| `_465._tcp` | TLSA | TLS / DANE | SMTPS DANE |
| `_993._tcp` | TLSA | TLS / DANE | IMAPS DANE |
| `_995._tcp` | TLSA | TLS / DANE | POP3S DANE |
| `_587._tcp` | TLSA | TLS / DANE | Submission DANE |
| `_h323cs._tcp` | SRV | Communication | H.323 |
| `_h323ls._udp` | SRV | Communication | H.323 location |
| `_caldav._tcp` | SRV | Calendar / Contacts | CalDAV (plain) |
| `_carddav._tcp` | SRV | Calendar / Contacts | CardDAV (plain) |
| `_kpasswd._tcp` | SRV | Infrastructure | Kerberos password |
| `_kpasswd._udp` | SRV | Infrastructure | Kerberos password |
| `_ntp._udp` | SRV | Infrastructure | NTP |
| `_http._tcp` | SRV | Infrastructure | HTTP service |
| `_https._tcp` | SRV | Infrastructure | HTTPS service |
| `_finger._tcp` | SRV | Legacy | Finger protocol |
| `_nicname._tcp` | SRV | Legacy | WHOIS |
| `_ts3._udp` | SRV | Gaming | TeamSpeak 3 |
| `_minecraft._tcp` | SRV | Gaming | Minecraft |
| `_vlmcs._tcp` | SRV | Infrastructure | KMS activation |
| `_adsp._domainkey` | TXT | Email Authentication | ADSP (deprecated) |
| `_mta-sts` | CNAME | Email Authentication | MTA-STS alias check |
| `_acme-challenge` | TXT | Verification / Metadata | ACME DNS-01 |
| `_dnsauth` | TXT | Verification / Metadata | DNS auth tokens |
| `_amazonses` | TXT | Verification / Metadata | Amazon SES |
| `_github-pages-challenge` | TXT | Verification / Metadata | GitHub Pages |
| `_google` | TXT | Verification / Metadata | Google Workspace |

## Record Type Details

### A
Maps a domain name to an IPv4 address. This is the most fundamental DNS record type — every domain that hosts a website or service needs at least one A record. When you type a domain name in your browser, the A record is what ultimately provides the IP address to connect to.

### AAAA
Maps a domain name to an IPv6 address. Functionally identical to the A record but for the newer IPv6 protocol. Increasingly important as IPv6 adoption grows.

### ANAME
An alias record for apex (root) domains, similar to CNAME but allowed at the zone apex. Unlike CNAME, which cannot coexist with other record types, ANAME resolves to the target's IP at query time. This is a draft standard not yet widely supported by all DNS providers.

### CAA
Specifies which Certificate Authorities (CAs) are allowed to issue TLS/SSL certificates for a domain. Helps prevent unauthorized certificate issuance by restricting which CAs can create certificates. CAs are required to check CAA records before issuing certificates.

### CNAME
Creates an alias from one domain name to another (the "canonical" name). When a DNS resolver encounters a CNAME, it restarts the lookup using the target name. Cannot coexist with other record types at the same name, and cannot be used at the zone apex.

### HINFO
Originally intended to describe the host's CPU type and operating system. Largely obsolete for its original purpose due to security concerns. Now commonly used in "negative" responses per RFC 8482 to minimize ANY query abuse.

### HTTPS
A specialized SVCB record for HTTPS services that enables clients to discover alternative endpoints, supported protocols (HTTP/2, HTTP/3), and ECH (Encrypted Client Hello) keys. Allows browsers to connect more efficiently by learning service parameters from DNS before the first HTTP request.

### MX
Specifies the mail servers responsible for receiving email for a domain, along with priority values. Lower priority numbers indicate preferred servers. Essential for email delivery — without MX records, mail falls back to the domain's A/AAAA records.

### NAPTR
Used for URI/service discovery through a series of rewriting rules. Commonly used in ENUM (telephone number to URI mapping), SIP, and other protocols that need to transform identifiers into service endpoints. Each record contains an order, preference, flags, service, regex, and replacement.

### NS
Identifies the authoritative nameservers for a DNS zone. These records tell resolvers which servers hold the definitive records for a domain. Every domain must have at least two NS records for redundancy.

### NULL
A record type that can hold arbitrary binary data up to 65535 bytes. Rarely used in practice and primarily exists for experimental purposes. Some applications use NULL records for tunneling or storing opaque data in DNS.

### OPENPGPKEY
Publishes OpenPGP public keys in DNS, allowing email clients to discover encryption keys for a recipient via DNS rather than keyservers. The key is stored at a hashed version of the email local part. Requires DNSSEC for secure key retrieval.

### PTR
Maps an IP address back to a domain name (reverse DNS). Used to verify that an IP address corresponds to a claimed hostname. Essential for email deliverability, as many mail servers reject messages from IPs without valid PTR records.

### SOA
The Start of Authority record defines key parameters for a DNS zone: the primary nameserver, the responsible party's email, and timing parameters for zone transfers and caching. Every DNS zone must have exactly one SOA record at its apex.

### SRV
Specifies the hostname and port for a particular service, enabling service discovery via DNS. Includes priority and weight fields for load balancing across multiple servers. Widely used for protocols like SIP, XMPP, LDAP, and Kerberos.

### SSHFP
Stores SSH host key fingerprints in DNS, allowing SSH clients to verify server host keys via DNSSEC rather than trust-on-first-use. Each record contains an algorithm identifier, fingerprint type, and the fingerprint data. Requires DNSSEC to be useful for verification.

### SVCB
A general-purpose service binding record that maps a service name to alternative endpoints with associated parameters. The base record type for HTTPS records. Supports features like alternative endpoints, protocol negotiation, and ECH configuration.

### TLSA
Associates a TLS certificate or public key with a domain name, enabling DNS-based Authentication of Named Entities (DANE). Allows domain owners to pin specific certificates or CAs in DNS, providing an alternative or supplement to the public CA system. Requires DNSSEC for security.

### TXT
A versatile record type that holds arbitrary text strings. Originally intended for human-readable notes, TXT records are now widely used for machine-readable data including SPF email authentication, DMARC policies, domain ownership verification, and various other protocols.

## Parsed TXT Sub-Type Details

### SPF
Sender Policy Framework defines which mail servers are authorized to send email on behalf of a domain. The SPF policy is expressed as a TXT record starting with `v=spf1`, listing allowed IP ranges, hostnames, and include directives. Receiving mail servers check SPF to detect forged sender addresses.

### DMARC
Domain-based Message Authentication, Reporting, and Conformance builds on SPF and DKIM to give domain owners control over how unauthenticated mail is handled. Published at `_dmarc.<domain>` as a TXT record starting with `v=DMARC1`, it specifies policies (none/quarantine/reject) and reporting addresses.

### MTA-STS
MTA Strict Transport Security tells sending mail servers that the domain requires TLS for SMTP connections. The TXT record at `_mta-sts.<domain>` (starting with `v=STSv1`) provides a policy ID, while the full policy is hosted via HTTPS. Prevents downgrade attacks on mail transport.

### TLS-RPT
SMTP TLS Reporting allows domains to request reports about TLS connection failures from sending mail servers. Published at `_smtp._tls.<domain>` as a TXT record starting with `v=TLSRPTv1`, it specifies where failure reports should be sent. Helps domain operators detect email delivery issues.

### BIMI
Brand Indicators for Message Identification allows organizations to display their logo alongside authenticated emails in supported mail clients. Published at `default._bimi.<domain>` as a TXT record starting with `v=BIMI1`, it provides a URL to the brand's SVG logo and an optional VMC certificate.

### Domain Verification
Third-party domain ownership verification records follow the pattern `<verifier>-<scope>-verification=<id>`. Services like Google, Facebook, and others use these TXT records to verify that the person managing DNS also controls the domain. Each service provides a unique verification token.

## Well-Known Subdomain Details

### Email Authentication

- **`_dmarc`** (TXT): DMARC policy record for the domain, specifying how unauthenticated mail should be handled and where aggregate/forensic reports should be sent.
- **`_mta-sts`** (TXT): MTA-STS policy ID record, indicating the current version of the domain's MTA-STS policy hosted at `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
- **`_smtp._tls`** (TXT): TLS-RPT reporting configuration, telling senders where to submit reports about TLS connection failures during mail delivery.
- **`default._bimi`** (TXT): BIMI indicator record pointing to the organization's brand logo SVG and optional Verified Mark Certificate (VMC).
- **`_adsp._domainkey`** (TXT): Author Domain Signing Practices, a deprecated extension to DKIM that specified signing policy. Superseded by DMARC.

### Email Services

- **`_submission._tcp`** (SRV): Mail submission service (port 587), used by email clients to discover the outgoing mail server.
- **`_submissions._tcp`** (SRV): Mail submission over implicit TLS (port 465), the TLS-secured variant of mail submission.
- **`_imap._tcp`** (SRV): IMAP mail access service, allowing email clients to discover the incoming mail server using IMAP with STARTTLS.
- **`_imaps._tcp`** (SRV): IMAP over implicit TLS (port 993), the TLS-secured variant of IMAP access.
- **`_pop3._tcp`** (SRV): POP3 mail access service for clients that download and optionally delete mail from the server.
- **`_pop3s._tcp`** (SRV): POP3 over implicit TLS (port 995), the TLS-secured variant of POP3.
- **`_autodiscover._tcp`** (SRV): Microsoft Exchange/Outlook autodiscovery service for automatic email client configuration.

### TLS / DANE

- **`_443._tcp`** (TLSA): DANE record for HTTPS on port 443, pinning the TLS certificate or CA for the domain's web server.
- **`_25._tcp`** (TLSA): DANE record for SMTP on port 25, enabling authenticated TLS for mail server-to-server communication.
- **`_dane._tcp`** (TLSA): Generic DANE record for services not on a specific well-known port.
- **`_465._tcp`** (TLSA): DANE record for SMTPS (implicit TLS SMTP) on port 465.
- **`_993._tcp`** (TLSA): DANE record for IMAPS on port 993.
- **`_995._tcp`** (TLSA): DANE record for POP3S on port 995.
- **`_587._tcp`** (TLSA): DANE record for mail submission on port 587.

### Communication

- **`_sip._tcp`** / **`_sip._udp`** (SRV): Session Initiation Protocol endpoints for VoIP and video calling over TCP or UDP.
- **`_sips._tcp`** (SRV): SIP over TLS for encrypted voice/video communication.
- **`_xmpp-client._tcp`** (SRV): XMPP (Jabber) client connection endpoint for instant messaging.
- **`_xmpp-server._tcp`** (SRV): XMPP server-to-server federation endpoint.
- **`_h323cs._tcp`** (SRV): H.323 call signaling for legacy video conferencing systems.
- **`_h323ls._udp`** (SRV): H.323 location service for gatekeeper discovery.

### Calendar / Contacts

- **`_caldavs._tcp`** (SRV): CalDAV over TLS, allowing calendar applications to discover the calendar server.
- **`_carddavs._tcp`** (SRV): CardDAV over TLS, allowing contact applications to discover the address book server.
- **`_caldav._tcp`** (SRV): CalDAV without TLS (plain HTTP), the unencrypted variant.
- **`_carddav._tcp`** (SRV): CardDAV without TLS (plain HTTP), the unencrypted variant.

### Infrastructure

- **`_ldap._tcp`** (SRV): LDAP directory service, used for user authentication and directory lookups in enterprise environments.
- **`_kerberos._tcp`** / **`_kerberos._udp`** (SRV): Kerberos authentication service endpoints for single sign-on in enterprise networks.
- **`_kpasswd._tcp`** / **`_kpasswd._udp`** (SRV): Kerberos password change service.
- **`_ntp._udp`** (SRV): Network Time Protocol service for time synchronization.
- **`_http._tcp`** / **`_https._tcp`** (SRV): Generic HTTP/HTTPS service discovery.
- **`_vlmcs._tcp`** (SRV): Microsoft Key Management Service (KMS) for volume license activation.

### Modern Protocols

- **`_matrix-fed._tcp`** (SRV): Matrix federation endpoint for decentralized communication (chat, VoIP).
- **`_stun._udp`** (SRV): STUN (Session Traversal Utilities for NAT) service for NAT traversal in WebRTC and VoIP.
- **`_turn._udp`** / **`_turns._tcp`** (SRV): TURN relay service for media relay when direct peer-to-peer connections fail. The `_turns` variant uses TLS.

### Verification / Metadata

- **`_atproto`** (TXT): AT Protocol (Bluesky) domain verification, proving ownership of a domain as a decentralized identifier.
- **`_dnslink`** (TXT): DNSLink record pointing to IPFS or other content-addressed resources, enabling human-readable names for distributed content.
- **`_domainconnect`** (TXT): Domain Connect protocol endpoint, enabling one-click DNS configuration by service providers.
- **`_acme-challenge`** (TXT): ACME DNS-01 challenge records used by Let's Encrypt and other CAs to verify domain ownership during certificate issuance.
- **`_dnsauth`** (TXT): DNS authorization tokens used by various services for domain verification.
- **`_amazonses`** (TXT): Amazon Simple Email Service domain verification token.
- **`_github-pages-challenge`** (TXT): GitHub Pages domain verification token.
- **`_google`** (TXT): Google Workspace domain verification token.
