---
id: usage_examples
title: Usage Examples
sidebar_label: Examples
slug: /usage_examples
---

mhost has many commands, each with a short alias: `lookup` (`l`), `domain-lookup` (`domain`), `discover` (`d`), `check` (`c`), `trace` (`t`), `dnssec`, `propagation` (`prop`), `verify` (`v`), `diff`, `info`, `server-lists`, and `completions`.

## Simple Lookup

```sh
mhost l github.com
```

![Default lookup for github.com.](/img/default-lookup-github.png)

Uses your system nameservers and queries the default record types (A, AAAA, CNAME, MX). Quick, clean, done.

### More nameservers, more answers

```sh
mhost -p l github.com
```

![Default lookup with predefined servers for github.com.](/img/default-lookup-predefined-servers-github.png)

`-p` adds 84 predefined public nameservers from Cloudflare, Google, Quad9, Mullvad, Wikimedia, and DNS4EU -- all four protocols, IPv4 and IPv6. More servers means more confidence that you're seeing the full picture.

### Thousands of nameservers

```sh
mhost server-lists public-dns -o servers.txt
mhost --limit 6000 --max-concurrent-servers 1000 --timeout 1 -f servers.txt l www.github.com
```

![Default lookup with servers list for github.com.](/img/default-lookup-servers-list-github.png)

The `server-lists` command downloads community-maintained lists of public resolvers. Then just point mhost at the file and let it rip. These settings are intentionally aggressive -- mhost defaults are much more cautious.

### All four protocols at once

```sh
mhost \
  -s 1.1.1.1 \
  -s tcp:1.1.1.1 \
  -s tls:1.1.1.1:853,tls_auth_name=cloudflare-dns.com \
  -s https:1.1.1.1:443,tls_auth_name=cloudflare-dns.com,name=Cloudflare \
  l github.com
```

![Default lookup with all protocols for github.com.](/img/default-lookup-all-protocols-github.png)

Nameserver spec format: `protocol:host:port,tls_auth_name=hostname,name=label`

### All record types + WHOIS

```sh
mhost -p l --all -w github.com
```

![Multi lookup for all available records of github.com.](/img/multi-lookup-all-records-github.png)

Query all 20+ record types and include WHOIS information for every IP address in the results -- AS numbers, network prefixes, organizations, countries, and geolocation. Great for understanding who's hosting what.

## Profile an Entire Domain

```sh
mhost -p domain-lookup example.com         # ~42 well-known entries
mhost -p domain-lookup --all example.com   # ~68 entries (extended set)
```

One command to rule them all. Queries the apex plus dozens of well-known subdomains in parallel: email auth (DMARC, MTA-STS, BIMI, TLS-RPT), SRV services (IMAP, SMTP, CalDAV, XMPP, Matrix, LDAP, Kerberos, ...), DANE/TLSA records, ACME challenges, AT Protocol, DNSLink, and more. It's a complete domain health snapshot.

## Discover Subdomains

```sh
mhost -p d github.com
```

![Discover github.com.](/img/discover-github.png)

mhost doesn't just try one thing -- it chains 10+ discovery strategies automatically, each feeding results into the next:

1. Standard DNS record lookups
2. Certificate Transparency logs (crt.sh)
3. TXT record mining for referenced domains
4. SRV service probing
5. Wildcard detection via random subdomain probes
6. Zone transfer (AXFR) attempts
7. NSEC walking
8. Wordlist brute force (424 built-in entries, or supply your own with `-w`)
9. Subdomain permutation on discovered names
10. Recursive discovery on found subdomains (`--depth 1..3`)
11. Reverse DNS lookups on discovered IPs

### Explore autonomous systems

```sh
mhost -p l --all -w github.com
mhost -p l --all 140.82.121.0/24
```

![Discover AS of github.com.](/img/discover-as-github.png)

## Validate DNS Configuration

```sh
mhost -p c github.com
```

![Check github.com.](/img/check-github.png)

The `check` command runs 13 lints against a domain's DNS records:

| Lint | What it checks |
|------|---------------|
| SOA | Start of Authority record validity |
| NS | NS delegation, lame delegation, network diversity |
| CNAME | CNAME usage rules |
| MX | Null MX, duplicate preferences, target resolution |
| SPF | SPF record syntax and policy |
| DMARC | DMARC policy validation |
| CAA | Certificate Authority Authorization tags |
| TTL | TTL consistency across records |
| DNSSEC | DNSSEC presence and configuration |
| HTTPS/SVCB | Service binding record well-formedness |
| AXFR | Zone transfer exposure |
| Open Resolver | Open resolver detection |
| Delegation | Delegation consistency |

Disable any lint individually: `--no-soa`, `--no-spf`, `--no-dnssec`, etc.

## Trace the Delegation Chain

```sh
mhost trace example.com
mhost trace -t AAAA --show-all-servers example.com
```

Unlike `dig +trace` which queries one server per hop, mhost's `trace` queries **all nameservers at each delegation level in parallel**. It detects referral divergence (where different root/TLD servers disagree), reports per-server latency, and resolves missing glue records automatically.

## Visualize the DNSSEC Trust Chain

```sh
mhost dnssec example.com
```

Ever wondered if DNSSEC is actually set up correctly from root to leaf? The `dnssec` command walks the entire delegation chain, querying DNSKEY, DS, and RRSIG records at every level, and renders a color-coded trust chain tree. You'll see key roles (KSK vs ZSK), algorithm strength, signature expiry dates, and whether DS records actually match the DNSKEYs they point to. No more guessing -- just follow the chain.

```sh
mhost dnssec --show-partial-results example.com   # Watch each level as it resolves
```

## Look Up SRV Services

```sh
mhost l -s smtp:tcp:example.com
```

The `-s` flag parses SRV service specs directly. Instead of manually constructing `_smtp._tcp.example.com`, just tell mhost the service, protocol, and domain in a human-readable format.

## Check DNS Propagation

```sh
mhost -p propagation example.com
mhost -p prop --all example.com
```

You just changed a DNS record. Now the waiting game begins -- or does it? Fire this off and see exactly which resolvers have picked up your change and which are still serving stale data. Uses the predefined nameserver set (Cloudflare, Google, Quad9, Mullvad, Wikimedia, DNS4EU).

## Diff Records Between Nameservers

```sh
mhost diff --left 8.8.8.8 --right 1.1.1.1 --all example.com
```

Spot the differences before your users do. Compare what two different nameserver sets return for the same domain. You can also diff against saved JSON snapshots -- perfect for tracking changes over time:

```sh
# Save a snapshot
mhost lookup -s 8.8.8.8 -q -t A,AAAA,MX example.com --output json > before.json

# Later, diff snapshot against live DNS
mhost diff --left-from-file before.json --right 1.1.1.1 example.com

# Or compare two snapshots offline
mhost diff --left-from-file before.json --right-from-file after.json example.com
```

## Verify DNS Against a Zone File

```sh
mhost verify example.com.zone
```

Compares every record in a BIND zone file against live DNS and reports matches, mismatches, and missing records. Non-zero exit code on mismatch for CI/CD integration.

```sh
# Verify against your authoritative nameserver
mhost -s ns1.example.com verify example.com.zone

# Check propagation to public resolvers
mhost -p verify example.com.zone

# Strict mode: also flag TTL differences
mhost verify --strict example.com.zone

# Only check mail-related records
mhost verify --only-type MX,TXT example.com.zone

# CI one-liner
mhost verify zones/example.com.zone || notify_team "DNS drift detected"
```

## Look Up Record Type Info

```sh
mhost info            # List all supported types
mhost info MX         # Details about MX records
mhost info SPF        # Details about SPF TXT sub-type
mhost info _dmarc     # Details about the _dmarc well-known subdomain
```

Built-in reference with summaries, details, and RFC references for every supported record type, TXT sub-type, and well-known subdomain.

## JSON Output

Every command supports `--output json` for machine-readable output:

```sh
mhost -q --output json l --all example.com | jq .
mhost -q --output json trace example.com | jq '.hops[] | .zone_name'
mhost -q --output json c example.com | jq '.results[] | select(.status != "Ok")'
```

## mdive -- Interactive TUI

`mdive` is an interactive terminal UI that makes DNS exploration feel less like debugging and more like browsing. Type a domain, watch records stream in from multiple servers in real time, then drill into anything that looks interesting.

```sh
mdive example.com                        # Dive right in
mdive -p example.com                     # Use 84 public resolvers
mdive -s 8.8.8.8 -s 1.1.1.1 example.com # Pick your own nameservers
```

**What you get:**

- **Live, sortable record table** -- apex plus dozens of well-known subdomains across 10 categories, with progressive streaming and a real-time progress bar
- **Drill-down navigation** -- press Enter to dive into subdomains, `l` to follow CNAMEs, Backspace to go back. It's like `cd` and `cd ..`, but for DNS.
- **Five discovery strategies** -- press `d` to launch CT log searches, wordlist brute force, SRV probing, TXT mining, and permutation -- or `a` to run them all at once
- **DNS health checks** -- press `c` to run 13 lints with color-coded pass/warning/fail results
- **WHOIS and geolocation** -- press `w` to see AS numbers, network prefixes, organizations, and countries for every IP
- **Server response dashboard** -- press `s` for per-server latency stats (protocol, OK/error counts, min/avg/max timing)
- **Stats panel** -- press `S` for record type distribution, query health, DNSSEC status, and response time ranges
- **Human-readable toggle** -- press `h` to switch between raw DNS wire format and human-friendly values
- **Regex filtering** -- press `/` and type a pattern to filter across names, types, and values. Press `C` to clear.
- **10 category toggles** -- use `1`-`0` to toggle record categories (email auth, email services, TLS/DANE, communication, calendar/contacts, infrastructure, modern protocols, verification, legacy, gaming). Press `a` for all, `n` for none.
- **Grouping modes** -- press Tab to cycle between grouping by category, record type, name, or server
- **Vi-style navigation** -- `j`/`k`, `gg`/`G`, PgUp/PgDn, digit-prefixed jumps (`22gg`), and `o` for a detail popup on any record
