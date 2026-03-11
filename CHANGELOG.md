# Changelog

## v0.11.2

### Security

- Update `aws-lc-sys` to 0.38.0 — fixes PKCS7_verify signature validation bypass, certificate chain validation bypass, and AES-CCM timing side-channel (GHSA alerts 59–61)
- Update `quinn-proto` to 0.11.14 — fixes unauthenticated remote DoS via QUIC transport parameter parsing (GHSA alert 62)

## v0.11.1

### Bug Fixes

- Gate `SerJsonError` variant behind `serde_json` feature — fixes compilation failure in library-only build (`--no-default-features`) introduced when `serde_json` was made optional in v0.11.0
- Gate `classify_chain_depth`, `des_f32_from_string`, and `ser_to_string` behind their respective feature flags to eliminate dead-code warnings in library-only build
- Allow `unused_mut` on predefined provider config builders where mutability is conditionally needed by `doh`/`dot` feature extensions

## v0.11.0

### Library: DoT and DoH are now opt-in features

DNS-over-TLS and DNS-over-HTTPS support are now gated behind two new Cargo features:

- **`dot`** — enables DNS-over-TLS (`hickory-resolver/tls-ring`)
- **`doh`** — enables DNS-over-HTTPS (`hickory-resolver/https-ring`)

Both features are included unconditionally by `app-lib`, so CLI and TUI builds are unaffected. A library-only build (`default-features = false`) no longer pulls in `ring` (a large C/asm TLS crypto crate) when only plain UDP/TCP lookups are needed.

The feature gates cover `Protocol::Tls/Https`, `NameServerConfig::Tls/Https`, all factory methods, parser arms, predefined server lists, and `From` impls. The 84 predefined nameserver configs automatically include TLS/HTTPS entries only when the respective feature is active.

### Library: `serde_json` and `lru_time_cache` are now opt-in

`serde_json` is gated behind `app-lib` (used for JSON output in CLI/TUI). `lru_time_cache` is gated behind `services` (used for WHOIS caching). Neither is a dependency in a library-only build.

### Architecture

- Move `Statistics` `Display` impls from the core library into the app layer (`app-lib`), keeping the core library free of formatting concerns

## v0.10.0

### Library: DNS lints available without app features

The 9 pure DNS lint checks (CAA, CNAME, DMARC, DNSSEC, HTTPS/SVCB, MX, NS, SPF, TTL) are now exposed as `mhost::lints::*` in the core library, usable without any `app-*` feature gate. Library consumers can run DNS configuration lints on `Lookups` results without pulling in `reqwest` or the full app dependency chain.

### Improvements

- Add short aliases for subcommands: `lookup`/`l`, `check`/`c`, `discover`/`d`, `verify`/`v`
- Validate `--output-options` arguments with clear error messages instead of silently ignoring invalid options
- Print "Found failures/warnings/No issues" summary before "Finished" line in `check` output
- Show help on missing subcommand consistently exits with status 0
- PageUp/PageDown in mdive TUI now scroll by actual visible table height instead of hardcoded 10 rows
- mdive status bar shows `HUMAN`/`RAW` badge indicating current view mode

### Security

- Cap TCP DNS response buffer at 16 KB to prevent excessive memory allocation from untrusted servers
- Validate country codes at URL construction time in public-dns.info server list downloader
- Enforce connect timeouts (10s), request timeouts, and redirect limits (max 3) on all HTTP clients

### Bug Fixes

- Raise HTTP response size limit from 10 MB to 50 MB for `get-server-lists` (public-dns.info now returns ~29 MB)
- Log resolver errors in `sliding_window_lookups` at `debug!` level instead of silently dropping them

### Architecture

- Restructure `src/app/` into layered feature gates: `app-lib` (shared), `app-cli` (CLI), `app-tui` (TUI). TUI no longer depends on CLI
- Extract 9 pure lints from `app/common/lints/` into ungated `src/lints/` core library module
- Deduplicate CLI lint files by importing shared analysis functions from core library

### Tests

- Add unit tests for SOA rdata, resolver error classification, Record equality, SPF lints, rdata formatting, TXT parsing
- Add lit tests for `dnssec` and `verify` CLI commands
- Fix 4 failing CLI integration tests (updated example.com zone fixture, stale output patterns)

## v0.9.0

### New: `verify` command

Verify that live DNS matches a BIND zone file -- catch drift before it bites.

- `mhost verify example.com.zone` — parse a BIND zone file, look up every (name, type) pair against live DNS, report matches, mismatches, missing, and extra records
- `--strict` — treat TTL differences as mismatches
- `--only-type` / `--ignore-type` — filter which record types to verify
- `--ignore-extra` / `--ignore-soa` — suppress extra-record reporting or SOA serial comparison
- `--origin` — override the zone origin ($ORIGIN)
- Wildcard records detected and reported as skipped (can't be verified via simple lookups)
- Non-zero exit code on mismatch for CI/CD integration
- SOA serial comparison between zone file and live DNS

### Improvements

- Add `--ascii` flag to mdive TUI for terminals without Unicode support
- Distinguish error (`x`) and attention (`!`) prefixes in ASCII mode
- Throttle mdive TUI rendering to ~30 fps to reduce redraws during rapid batch arrivals
- Defer DNSSEC status recomputation to query completion for efficiency
- Improve error count output with Display formatting and `--timeout` hint on timeout errors
- Add range validation to hidden `--max-worker-threads` parameter
- Add usage examples to `mhost --help` output

### Security

- Add post-read body size checks to prevent chunked encoding bypass of HTTP response size limits

### Architecture

- Feature-gate `reqwest` behind `services` feature for leaner library-only builds
- Remove protocol redundancy in internal resolver configuration

### Code quality

- Add unit tests for modules with zero test coverage
- Replace real email addresses in WHOIS test fixtures with example.com

### Documentation

- Add `verify` command documentation to README with examples
- Add `dnssec` command to README command table and reference
- Overhaul README structure: centered header, feature comparison table, audience section, collapsible reference sections
- Update roadmap to reflect shipped verify command

## v0.8.0

### New: mdive interactive TUI

First full-featured release of `mdive`, the interactive DNS exploration terminal.

- **Concurrent multi-server queries** — Fan out lookups across all configured resolvers in parallel with real-time table population
- **CLI integration** — Accept domain name as argument for immediate query on launch; share resolver configuration flags with `mhost` (`--predefined`, `--system`, `--nameserver`, `-4`/`-6`, etc.)
- **Human-readable view** — Toggle between raw and human-readable record values with TTL formatting
- **Free-text search/filter** — `/` enters regex search mode with case-insensitive matching across all columns
- **Drill-down navigation** — Enter drills into subdomains, `l`/`→` follows hostname targets (CNAME, MX, NS, SRV, SOA, SVCB/HTTPS, NAPTR, PTR). Full state history with `←`/`Backspace` to go back
- **Grouping modes** — Tab cycles between Category, Type, Name, and Server grouping
- **Discovery strategies** — Interactive panel (`d`) with CT Logs, Wordlist, SRV Probing, TXT Mining, and Permutation strategies. Run individually or all at once
- **DNS health checks** — Popup (`c`) running 9 lint categories with color-coded results
- **WHOIS panel** — Popup (`w`) showing network, ASN, organization, and geo-location for all unique IPs
- **Per-server stats** — Popup (`s`) with per-server response time table (protocol, OK/error counts, min/avg/max latency)
- **Stats panel** — Expandable status bar (`S`) showing record distribution, query health, and DNSSEC status badge
- **DNSSEC indicator** — Color-coded badge (signed/partial/broken/unsigned) in stats panel

### Improvements

- Improve human-readable formatting for HTTPS/SVCB records and simple values

### Bug fixes

- Fix TUI security, architecture, and UX issues found during code review

### Documentation

- Add comprehensive mdive TUI documentation to README
- Add DNS zone file verification design document

## v0.7.0

### New features

- `dnssec` command — DNSSEC trust chain visualization: walks delegation from root to target zone, renders color-coded tree with key roles, algorithm strength, signature expiry, and DS→DNSKEY linkage
- `diff --left-from-file` / `--right-from-file` — compare saved JSON snapshots against live DNS or other snapshots for migration validation and change tracking
- Full `Deserialize` support on all DNS types (`Record`, `RData`, `RecordType`, `Lookups`, etc.) enabling JSON round-trip for snapshots
- DNSSEC chain validation checks added to `check` command lints
- Human-readable DNSSEC record output with typed structs (DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM)

### Bug fixes

- Fix diff command not accepting domain name after `--left`/`--right` flags
- Fix lit test failures from typed DNSSEC record changes
- Use dual-stack root servers by default in trace command

### Documentation

- Rename TODO.md to ROADMAP.md and consolidate content
- Reorganize roadmap priorities

## v0.6.0

### New commands

- `trace` command — trace the DNS delegation path from root servers to authoritative nameservers, querying all servers at each hop in parallel with referral divergence detection
- `diff` command — compare DNS records between two nameserver sets to debug inconsistencies or verify migrations
- `propagation` command — check DNS record propagation across predefined public resolvers with SOA-serial-based detection
- `completions` command — generate shell completions for bash, zsh, or fish on demand

### New features

- Global `-4`/`--ipv4-only` and `-6`/`--ipv6-only` flags to restrict queries and results by address family
- `ResolverGroupBuilder` and `PredefinedProvider` for ergonomic library usage
- Three-tier CLI help: bare `mhost` shows commands only, `--help` adds global options, `<command> --help` shows command details
- 4 new DNS health check lints: AXFR zone transfer exposure, open resolver detection, delegation consistency, CNAME chain depth (deep and circular chain detection)

### Bug fixes

- Fix lame delegation lint to warn on IPv6-only failures instead of false positives

### Code quality

- Extract shared record rendering from lookups into dedicated `records.rs` module
- Reorder check lints by semantic category (structural, email, security, advanced)

### Documentation

- Comprehensive README rewrite covering all commands, library API, and JSON output examples
- Library doc comments with quick-start builder API and manual construction examples

## v0.5.0

### New features

- `info` command — reference guide for DNS record types, TXT sub-types, and well-known subdomains
- `domain-lookup` command — combined forward + reverse DNS lookup for a full domain profile in one operation
- CAA record type support (certificate authority authorization)
- TLSA record type support (DANE/TLS authentication)
- 8 new discovery strategies: CT log mining, TXT record mining, SRV probing, permutation generation, zone transfer attempts, wildcard detection, NSEC walking, SOA/NS enumeration
- Expanded default discovery wordlist from 83 to 424 entries
- 7 new DNS health checks: NS lame delegation, NS network diversity, MX hygiene (Null MX, duplicate preferences, target resolution), DMARC policy validation, CAA tag validation, TTL sanity, DNSSEC presence, HTTPS/SVCB well-formedness
- Enhanced human-readable summary output for all DNS record types

### Bug fixes

- Fix blocking mutex in async context
- Fix `--all` flag panic with new record types
- Fix unimplemented panics for SSHFP/TLSA/NAPTR/HINFO/OPENPGPKEY output
- Fix confusing CLI flag names
- Fix flaky lookup_predefined lit test

### Code quality

- Remove panicking `.unwrap()` calls from output rendering path
- Add 50MB response size limit for CT log queries
- Robustify WHOIS date parsing with fallback for missing fields
- Add CLI argument bounds validation
- Remove lazy_static dependency
- Reduce boilerplate with `print_check_results!`, `iana_enum!`, and `check_result_builders!` macros
- Improve error handling and preserve error context throughout

### Documentation

- Comprehensive README rewrite with all new features and commands
- Updated CLAUDE.md with expanded architecture, CLI commands table, and test guidelines

## v0.4.1

- Fix release workflow not uploading .deb package to GitHub release
- Use glob patterns for artifact upload for robustness
- Add artifact listing step for release debugging

## v0.4.0

### Major upgrades

- **Migrate DNS resolver from trust-dns-resolver v0.20 to hickory-resolver v0.25** — the trust-dns
  project was renamed to hickory-dns. This brings TLS/HTTPS improvements, updated DNSSEC support,
  and continued upstream maintenance.
- **Migrate CLI parser from clap v2 to clap v4** — modernized argument parsing with improved help
  formatting, value parsers, and typed argument actions.
- **Migrate nom from v5 to v7** — parser combinators updated from macro-based to function-based API.

### Dependency upgrades

- reqwest 0.11 to 0.13 (with hickory-dns feature)
- thiserror 1 to 2
- indexmap 1 to 2
- ipnetwork 0.17 to 0.21
- hostname 0.3 to 0.4
- rand 0.8 to 0.9
- yansi 0.5 to 1.0
- tracing-log 0.1 to 0.2
- clap_complete 2 to 4

### DNS server updates

- Switch Quad9 from filtered (9.9.9.9) to unfiltered (9.9.9.10) endpoints
- Remove stale hardcoded OpenNIC volunteer server IPs
- Add Mullvad DNS (privacy-focused, Sweden)
- Add Wikimedia DNS
- Add DNS4EU unfiltered (EU-based)
- Fix Cloudflare IPv6 TLS display name bug
- Fix Quad9 duplicate/missing IPv6 TLS entry

### Build and infrastructure

- Rust edition 2018 to 2021
- Slim tokio features (dropped unused: sync, signal, process, io-std, parking_lot, test-util)
- Modernize GitHub Actions CI workflows (dtolnay/rust-toolchain, actions/checkout@v4)
- Modernize release workflow (softprops/action-gh-release@v2, fix deprecated set-output syntax)
- Upgrade Docker action versions (login-action@v3, build-push-action@v6)
- Replace third-party musl action with native musl cross-compilation
- Fix clippy warnings
- Add separate Homebrew tap repository with automated formula updates
- Improve Homebrew formula (offline test, explicit tag URL)

## v0.3.2

- Release process improvements

## v0.3.1

- Maintenance release

## v0.3.0

- Initial public release with DNS over UDP, TCP, TLS, and HTTPS support
- Multi-server concurrent lookups
- Domain/subdomain discovery
- DNS configuration linting
- WHOIS integration
- JSON and summary output formats
