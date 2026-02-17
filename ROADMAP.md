# mhost — Roadmap

## What's been done (v0.8.0)

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
- DNS snapshot and timeline diff: save lookup JSON, diff against live DNS or another snapshot via `--left-from-file` / `--right-from-file`
- Full module-level documentation, `cargo doc --no-deps` builds clean
- Usage examples in `mhost --help` output
- Actionable error messages: Display-formatted error counts with `--timeout` hint on timeout errors
- HTTP response size limits enforce post-read body length checks (chunked encoding bypass fix)
- Range validation on all CLI numeric parameters including hidden `--max-worker-threads`
- Distinct ASCII-mode prefixes for attention (`!`) vs error (`x`)
</details>

<details>
<summary>mdive TUI</summary>

- **WHOIS panel** — Press `w` to fetch and display WHOIS data (network, ASN, organization, geo-location) for all unique IPs in current results. Cached per query, scrollable popup with j/k navigation.
- **Discovery strategies** — Press `d` to open interactive discovery panel with 5 strategies: CT Logs, Wordlist (424 entries with wildcard filtering), SRV Probing (22 probes), TXT Mining (SPF/DMARC extraction), and Permutation. Run individually or all at once with `a`. Results stream into the main table in real time with per-strategy status indicators.
- **Lints / health checks** — Press `c` to show DNS health checks popup. Runs 9 lint categories (CNAME, NS, MX, HTTPS/SVCB, SPF, DMARC, CAA, TTL, DNSSEC) synchronously from existing lookup data. Color-coded results (green OK, yellow warning, red failed), scrollable with j/k.
- **Summary / stats panel** — Press `S` to toggle a 2-line panel showing record type distribution, unique record count, query health breakdown (OK/NX/errors), responding server count, response time range, and DNSSEC status badge.
- **Per-server response times** — Press `s` to open servers popup showing a per-server stats table with protocol, OK/error counts, and min/avg/max latency. Sorted by average response time.
- **DNSSEC status indicator** — Stats panel shows a color-coded DNSSEC badge (signed/partial/broken/unsigned) derived from the existing lint infrastructure. Computed once at query completion for efficiency.
- **Drill-down and query history** — Enter drills into subdomain names, `l`/`→` drills into hostname targets (CNAME, MX, NS, SRV, SOA, SVCB/HTTPS, NAPTR, PTR). Full state snapshots pushed to a history stack. `←`/`Backspace` restores previous state instantly.
- **Free-text filter / search** — `/` enters search mode with case-insensitive regex matching across name, type, value, and human-readable columns.
- **Grouping modes** — Press `Tab` to cycle between four grouping modes: Category (default), Type, Name, and Server. Mode preserved in drill-down history.
- **`--ascii` mode** — Full ASCII fallbacks for all Unicode glyphs (arrows, progress bar, check marks, circle indicators, dashes).
- **Rendering throttle** — Capped at ~30 fps to avoid excessive redraws during rapid DNS batch arrivals.
</details>

---

## Up next

### DNS zone file verification

Verify that live DNS matches a source-of-truth BIND zone file. `mhost verify zone.db` parses the zone file, performs live lookups for each (name, type) pair, and reports matches, mismatches, missing records, and extras. Non-zero exit code on mismatch for CI/CD integration. See [design document](docs/verify.sdd.md) for full details.

### Geolocation-aware propagation

Group propagation results by geographic region (Americas, Europe, Asia-Pacific) using provider metadata.

### Resolver benchmarking

Statistical analysis of resolver latency over many rounds.

- `mhost bench example.com --rounds 100` — query N times across configured resolvers
- Per-resolver statistics: min, max, mean, median, p95, p99, stddev
- `--resolvers 8.8.8.8,1.1.1.1` for head-to-head comparison
- Summary output as a sorted table (fastest to slowest)

---

## Ideas

Longer-term possibilities — not prioritized, may require significant design work.

- **Propagation view** — Query the same records across all 84 predefined servers and show agreement/disagreement. Flag inconsistencies inline or in a dedicated panel.
- **DNS trace visualization** — Show full resolution path from root → TLD → authoritative, with referrals. Interactive `dig +trace`. Use mhost trace functionality.
- **CNAME chain following** — Automatically resolve and display the full CNAME chain inline. (Manual drill-down via `l`/`→` on CNAME records is already available.)
- **Discrepancy highlighting** — When different nameservers return different answers for the same query, flag it visually. The single most useful diagnostic signal.
- **TTL countdown / staleness** — Show when records were fetched and how much TTL remains. Indicate when a re-query might give different results.
- **Tree view** — Show the subdomain hierarchy as a tree with record counts per node.
- **Side-by-side domain comparison** — Split screen to compare two domains or the same domain at two points in time.

- **Export DNS records to infrastructure formats** — Export discovered/looked-up records into formats ready for another provider or IaC tool. `--export zone` (RFC 1035 zone file syntax), `--export terraform` (HCL for `dns_*_record_set` resources). Works with `lookup` and `domain-lookup`.

- **DNS-over-QUIC (DoQ)** — RFC 9250 transport support alongside UDP/TCP/DoT/DoH. Depends on hickory-dns DoQ maturity.

- ~~**Zone file import and pre-deployment validation**~~ — Promoted to planned: see [DNS zone file verification](#dns-zone-file-verification) above and [design document](docs/verify.sdd.md).

- **Configuration profiles** — `~/.config/mhost/profiles.toml` with named resolver sets, default options, and per-domain overrides for managing multiple environments.

- **DNS response explainer** — `mhost explain` to decode raw DNS responses, dig output, or packet captures into plain-English explanations.

- **Progress indicators** — `indicatif` progress bars for long-running discover operations (CT logs + wordlist + recursive depth).

---

## Won't do

- **DNS monitoring / watch mode** — Continuously poll DNS and report changes. Better served by dedicated monitoring tools (e.g., Prometheus + dns_exporter) rather than a CLI utility.
