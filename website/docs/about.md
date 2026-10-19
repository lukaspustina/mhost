---
id: about
title: About mhost
sidebar_label: About mhost
slug: /
---

**mhost** is what `host` and `dig` would be if they were built today. It queries many DNS servers in parallel, aggregates their answers, and tells you what's actually going on -- across UDP, TCP, DNS-over-TLS, and DNS-over-HTTPS, with 20+ record types, and 84 pre-configured public resolvers ready to go.

But lookups are just the beginning. mhost can profile an entire domain in one shot, hunt down subdomains using 10+ strategies, lint your DNS configuration, trace delegation chains from the root, visualize DNSSEC trust chains, check propagation across the globe, diff records between nameservers, and verify live DNS against your zone files -- all from a single binary. If DNS touches it, mhost probably has a command for it.

## Two binaries, one toolkit

**`mhost`** is the CLI workhorse -- built for scripts, pipelines, and those "let me just check one thing" moments that turn into deep investigations. **`mdive`** is the interactive TUI that turns DNS exploration into something that actually feels fun -- drill into subdomains, chase CNAME chains, discover hidden records, and navigate it all with vi-style keybindings without ever leaving your terminal.

## Commands

| Command | Alias | What it does |
|---------|-------|--------------|
| `lookup` | `l` | Look up DNS records for a domain, IP, CIDR block, or SRV service spec |
| `domain-lookup` | `domain` | Profile a domain -- apex + 68 well-known subdomains in one shot |
| `discover` | `d` | Hunt down subdomains using 10+ strategies (CT logs, wordlists, AXFR, NSEC walking, ...) |
| `check` | `c` | Lint DNS configuration against 13 checks (SOA, NS, SPF, DMARC, DNSSEC, ...) |
| `trace` | `t` | Trace the delegation path from root servers, querying all servers at each hop |
| `dnssec` | -- | Visualize the DNSSEC trust chain from root to target with color-coded key roles |
| `propagation` | `prop` | Check whether a DNS change has reached all major public resolvers |
| `verify` | `v` | Verify live DNS matches a BIND zone file -- catch drift before it bites |
| `diff` | -- | Compare DNS records between nameservers or JSON snapshots |
| `info` | -- | Built-in encyclopedia for record types, TXT sub-types, and well-known subdomains |
| `server-lists` | -- | Download public nameserver lists for large-scale queries |
| `completions` | -- | Generate shell completions for bash, zsh, and fish |

## Key features

- **Parallel multi-server queries** -- throw queries at up to 10,000 nameservers concurrently, with 84 built-in public resolvers from 6 providers. More servers, more confidence.
- **All four protocols** -- UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH). Because it's not 2005 anymore.
- **20+ record types** -- A, AAAA, MX, TXT, CNAME, NS, SOA, CAA, SRV, HTTPS, SVCB, TLSA, SSHFP, NAPTR, HINFO, OPENPGPKEY, PTR, ANAME, DNSSEC types (DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM), and more
- **WHOIS and geolocation** -- get AS numbers, network prefixes, organizations, and countries for every IP in your results with a single `-w` flag
- **Subdomain discovery** -- 10+ strategies chained automatically: CT logs, wordlists, AXFR, NSEC walking, SRV probing, TXT mining, permutation, recursive discovery, and reverse DNS on found IPs
- **DNS configuration linting** -- 13 checks covering SOA, NS delegation, MX, SPF, DMARC, CAA, DNSSEC, HTTPS/SVCB, TTL consistency, zone transfer exposure, open resolver detection, and delegation consistency
- **Delegation tracing** -- unlike `dig +trace` (one server per hop), mhost queries all nameservers at each delegation level in parallel, detects referral divergence, and resolves missing glue records automatically
- **DNSSEC visualization** -- walk the trust chain from root to target zone with color-coded key roles (KSK/ZSK), algorithm strength, signature expiry, and DS-to-DNSKEY linkage
- **Propagation checking** -- verify DNS changes across Cloudflare, Google, Quad9, Mullvad, Wikimedia, and DNS4EU
- **Record diffing** -- compare live DNS between nameservers, against saved JSON snapshots, or any combination. Spot the differences before your users do.
- **Zone file verification** -- compare live DNS against BIND zone files with non-zero exit codes for CI/CD integration. Catch drift before it bites.
- **Interactive TUI (mdive)** -- drill-down navigation, real-time discovery, WHOIS/geolocation, health checks, server stats, regex filtering, 10 record categories, human-readable toggle, and vi-style keybindings. It's like a file manager, but for DNS.
- **JSON output** -- every command supports `--output json`. Pipe it, `jq` it, automate it.
- **Reusable Rust library** -- async builder API, typed DNS records, lint functions, no CLI dependencies when built as library-only. Build your own DNS tools on top.

## Postcardware

You're free to use `mhost`. If you find it useful, I would highly appreciate you sending me a postcard from your hometown mentioning how you use `mhost`. My work address is

```plain
     Lukas Pustina
     CenterDevice GmbH
     Rheinwerkallee 3
     53227 Bonn
     Germany
```
