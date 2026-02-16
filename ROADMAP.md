# mhost — Roadmap

## What's been done (v0.6.0)

<details>
<summary>Commands</summary>

- **lookup** — DNS record lookups across multiple nameservers in parallel
- **domain-lookup** — Full domain profile (apex + ~40-65 well-known subdomains) in one operation
- **discover** — Subdomain discovery via 10+ strategies (wordlists, CT logs, SRV probing, TXT mining, AXFR, NSEC walking, permutation, reverse DNS, recursive)
- **check** — DNS configuration validation with 13 lints (SOA, NS, CNAME chain depth, MX, SPF, DMARC, CAA, TTL, DNSSEC chain validation, HTTPS/SVCB, AXFR exposure, open resolver, delegation consistency)
- **propagation** — DNS propagation checking across predefined public resolvers with divergence detection
- **diff** — Compare DNS records between two nameserver sets, JSON snapshots, or a mix of both
- **trace** — Parallel iterative resolution from root servers with per-server latency and referral divergence detection
- **dnssec** — DNSSEC trust chain visualization: walks delegation from root to target zone, renders color-coded tree with key roles, algorithm strength, signature expiry, and DS→DNSKEY linkage
- **info** — DNS record type and well-known subdomain documentation
- **completions** — Shell completion generation (bash, zsh, fish)
- **server-lists** — Download public nameserver lists
</details>

<details>
<summary>Infrastructure</summary>

- Global `-4`/`-6` flags for IPv4-only / IPv6-only filtering across all commands
- DNS over UDP, TCP, TLS (DoT), and HTTPS (DoH)
- 20+ DNS record types including individual DNSSEC types (DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM) with typed rdata structs
- Shared library modules: `dnssec_validation` (severity/finding model, per-record classifiers, collection validators), `delegation` (root servers, referral extraction, server list building)
- `ResolverGroupBuilder` with fluent API and `PredefinedProvider` enum
- Semantic resolver error types (Timeout, QueryRefused, ServerFailure, etc.)
- Summary and JSON output for all commands
- 84 predefined unfiltered DNS server configurations across 6 providers
- Full `Serialize` + `Deserialize` on all DNS types — JSON round-trip for snapshots
- Full module-level documentation, `cargo doc --no-deps` builds clean
</details>

---

## Up next

### DNS snapshot and timeline diff

Save a domain's full DNS profile to disk and diff against it later — useful for migration validation, provider switches, and change tracking.

**Done:**
- `mhost lookup -s 8.8.8.8 -q -t A,AAAA,MX example.com --output json > before.json` — snapshot via existing lookup JSON output
- `mhost diff --left-from-file before.json --right 1.1.1.1 example.com` — compare snapshot against live DNS
- `mhost diff --left-from-file before.json --right-from-file after.json example.com` — compare two snapshots offline
- Full `Deserialize` support for the entire `Lookups` serialization chain (round-trip JSON)

**Remaining:**
- `mhost watch` / monitoring mode (see below)
- Dedicated `mhost snapshot` convenience command (optional — lookup + json already works)

### DNS monitoring / watch mode

Continuously poll DNS and report changes — for migrations, TTL changes, and incident response.

- `mhost watch example.com A --interval 30s` — poll and print only on change
- `mhost watch example.com --all --interval 1m` — watch all record types
- `--exit-on-change` for scripting (exit 0 on first detected change)
- Shows timestamp and delta: record added/removed/modified, TTL change, SOA serial bump

### Resolver benchmarking

Statistical analysis of resolver latency over many rounds.

- `mhost bench example.com --rounds 100` — query N times across configured resolvers
- Per-resolver statistics: min, max, mean, median, p95, p99, stddev
- `--resolvers 8.8.8.8,1.1.1.1` for head-to-head comparison
- Summary output as a sorted table (fastest to slowest)

### Export DNS records to infrastructure formats

Export discovered/looked-up records into formats ready for another provider or IaC tool.

- `--export zone` — RFC 1035 zone file syntax
- `--export terraform` — HCL for `dns_*_record_set` resources
- Works with `lookup` and `domain-lookup`

---

## Ideas

Longer-term possibilities — not prioritized, may require significant design work.

- **Interactive TUI mode** — Terminal UI (ratatui) for exploring DNS interactively: type a domain, see records update live, drill into subdomains, navigate the delegation tree. May warrant its own crate/binary built on the mhost library.

- **DNS-over-QUIC (DoQ)** — RFC 9250 transport support alongside UDP/TCP/DoT/DoH. Depends on hickory-dns DoQ maturity.

- **Zone file import and pre-deployment validation** — Parse BIND-style zone files and validate with the existing check lints *before* deploying. Shift-left DNS validation.

- **Configuration profiles** — `~/.config/mhost/profiles.toml` with named resolver sets, default options, and per-domain overrides for managing multiple environments.

- **Geolocation-aware propagation** — Group propagation results by geographic region (Americas, Europe, Asia-Pacific) using provider metadata.

- **DNS response explainer** — `mhost explain` to decode raw DNS responses, dig output, or packet captures into plain-English explanations.

- **Progress indicators** — `indicatif` progress bars for long-running discover operations (CT logs + wordlist + recursive depth).
