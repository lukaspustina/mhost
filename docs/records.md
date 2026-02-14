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
