# CLAUDE.md — mhost

## Project Overview

**mhost** (v0.5.0) is a modern, high-performance DNS lookup utility written in Rust. It is both a CLI tool and a reusable library. Think of it as an advanced replacement for the classic `host` / `dig` commands.

- **Author**: Lukas Pustina
- **License**: MIT / Apache-2.0
- **Rust edition**: 2021
- **Repository**: https://github.com/lukaspustina/mhost.git

## Key Features

- Multi-server concurrent DNS lookups (queries many nameservers in parallel, aggregates results)
- DNS over UDP, TCP, TLS (DoT), and HTTPS (DoH)
- 20 DNS record types: A, AAAA, ANAME, ANY, CAA, CNAME, HINFO, HTTPS, MX, NAPTR, NS, NULL, OPENPGPKEY, PTR, SOA, SRV, SSHFP, SVCB, TLSA, TXT, plus DNSSEC records
- Domain/subdomain discovery via 10+ strategies (wordlists, CT logs, SRV probing, TXT mining, AXFR, NSEC walking, permutation, reverse DNS, recursive)
- DNS configuration validation with 10 lints (SOA, NS, CNAME, MX, SPF, DMARC, CAA, TTL, DNSSEC, HTTPS/SVCB)
- Domain lookup command for full DNS profile in one operation (~40-65 well-known subdomain/record combinations)
- WHOIS integration (via RIPEStats API)
- Output as human-readable summary tables or JSON
- Predefined unfiltered DNS servers: 84 configurations across 6 providers (Cloudflare, Google, Quad9, Mullvad, Wikimedia, DNS4EU)
- Built-in wordlist of 424 subdomain entries for discovery
- Info command for DNS record type and well-known subdomain documentation

## Build & Test Commands

```sh
cargo build                # Build everything (default feature = "app")
cargo build --lib          # Build library only
cargo check                # Type-check without full compilation
cargo test --lib           # Run library unit tests (224 tests, fast, no network needed)
cargo test                 # Run all tests including CLI integration tests (slower, needs network)
cargo clippy               # Lint
cargo fmt                  # Format
```

### Test guidelines

- **`cargo test --lib`** is the reliable quick check — 224 unit tests, no network needed.
- **`cargo test`** also runs lit-based CLI integration tests (`tests/cli_output_tests.rs`) that make real DNS queries via `8.8.8.8`. These may fail due to DNS timeouts or changed records.
- **Every new rdata type or RecordType variant must have unit tests.** Each rdata module has a `#[cfg(test)] mod tests` block covering constructor/accessor round-trips and any enum conversions (`From<u8>`, `Display`).
- **`RecordType::from_str` must cover all variants.** If you add a new `RecordType` variant, add it to `FromStr`, `all()`, and the `from_str_all_standard_types` test. The `display_round_trip` test will catch omissions.
- **`RData` accessor tests** in `src/resources/rdata/mod.rs` verify each variant's accessor returns `Some` and unrelated accessors return `None`.
- **Lit tests** live in `tests/lit/*.output`. Use regex patterns (`[[\d+]]`, `[[s*]]`) instead of hardcoded counts for values that change when record types are added (e.g., request counts, record type counts). Avoid asserting on specific subdomains from wordlist discovery — these are flaky due to DNS timeouts.

## Architecture

```
src/
├── bin/mhost.rs              # CLI entry point
├── lib.rs                    # Library root, public API exports
├── error.rs                  # Top-level Error type (thiserror)
│
├── resolver/                 # Core DNS resolver abstractions
│   ├── mod.rs               #   Resolver, ResolverGroup, ResolverConfig, ResolverOpts
│   ├── query.rs             #   UniQuery, MultiQuery
│   ├── lookup.rs            #   Lookup results, Lookups aggregator, Uniquify trait
│   ├── predefined.rs        #   Predefined resolver groups (Google, Cloudflare, etc.)
│   └── error.rs             #   Resolver-specific errors
│
├── nameserver/              # Nameserver configuration
│   ├── mod.rs              #   NameServerConfig enum (Udp/Tcp/Tls/Https)
│   ├── parser.rs           #   String parsing for nameserver specs (uses nom)
│   ├── predefined.rs       #   Predefined public nameservers (Cloudflare, Google, Quad9, Mullvad, Wikimedia, DNS4EU)
│   └── load.rs             #   Load nameserver configs from files
│
├── resources/               # DNS record types and data
│   ├── record_type.rs      #   RecordType enum (A, AAAA, CAA, CNAME, HINFO, HTTPS, MX, NAPTR, NS, OPENPGPKEY,
│   │                       #     PTR, SOA, SRV, SSHFP, SVCB, TLSA, TXT, DNSSEC, etc.)
│   ├── record.rs           #   Record struct
│   └── rdata/              #   Record-specific data types
│       ├── mod.rs          #     RData enum and accessors
│       ├── caa.rs          #     CAA record data
│       ├── hinfo.rs        #     HINFO record data
│       ├── mx.rs           #     MX record data
│       ├── naptr.rs        #     NAPTR record data
│       ├── openpgpkey.rs   #     OPENPGPKEY record data
│       ├── soa.rs          #     SOA record data
│       ├── srv.rs          #     SRV record data
│       ├── sshfp.rs        #     SSHFP record data
│       ├── svcb.rs         #     SVCB/HTTPS record data
│       ├── tlsa.rs         #     TLSA record data
│       ├── txt.rs          #     TXT record data
│       └── parsed_txt/     #     Parsed TXT subtypes (SPF, DMARC, BIMI, MTA-STS, TLS-RPT)
│
├── services/                # External service integrations
│   ├── whois/              #   WHOIS via RIPEStats API
│   └── server_lists/       #   Download public DNS server lists (public-dns.info, OpenNIC)
│
├── statistics/              # Result aggregation & statistics traits
│
├── app/                     # CLI application layer (behind "app" feature flag)
│   ├── cli_parser.rs       #   clap v4 argument definitions (builder API)
│   ├── app_config.rs       #   Consolidated AppConfig from CLI args
│   ├── resolver.rs         #   App-level resolver setup
│   ├── console.rs          #   User console output
│   ├── logging.rs          #   tracing/logging setup
│   ├── output/             #   Output formatting (json.rs, summary/, styles.rs)
│   └── modules/            #   Command implementations:
│       ├── lookup/         #     DNS record lookups (+ service_spec.rs for SRV)
│       ├── domain_lookup/  #     Domain-wide lookup of apex + well-known subdomains
│       ├── discover/       #     Subdomain discovery (+ wordlist.rs, ct_logs.rs, srv_probing.rs,
│       │                   #       txt_mining.rs, permutation.rs)
│       ├── check/          #     DNS validation lints:
│       │   └── lints/      #       cnames.rs, soa.rs, spf.rs, dmarc.rs, ns.rs, mx.rs,
│       │                   #       caa.rs, ttl.rs, dnssec_lint.rs, https_svcb.rs
│       ├── info/           #     DNS record type info display
│       └── get_server_lists/ #   Download nameserver lists
│
├── system_config.rs         # Parse /etc/resolv.conf
├── estimate.rs              # Estimation utilities
├── diff.rs                  # Diff utilities
└── utils/                   # Helpers (serialize, deserialize, buffer_unordered_with_breaker)
```

## CLI Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `lookup` | `l` | Look up arbitrary DNS records of a domain name, IP address, or CIDR block |
| `domain-lookup` | `domain` | Look up a domain's apex records and ~40-65 well-known subdomains in one operation |
| `discover` | `d` | Discover host names and subdomains using 10+ strategies |
| `check` | `c` | Validate DNS configuration using 10 lints |
| `info` | -- | Show information about DNS record types and well-known subdomains |
| `server-lists` | -- | Download public nameserver lists |

## Key Dependencies

| Crate | Purpose |
|---|---|
| `hickory-resolver` 0.25 | Core DNS resolution (DoT, DoH, DNSSEC) |
| `tokio` 1 | Async runtime (rt-multi-thread, macros, time, fs, io-util, net) |
| `futures` 0.3 | Async combinators (join_all, streams) |
| `reqwest` 0.13 | HTTP client (DoH, WHOIS, server list downloads) |
| `clap` 4 | CLI argument parsing, builder API (app feature only) |
| `clap_complete` 4 | Shell completion generation (build-time) |
| `nom` 7 | Parser combinators for nameserver string parsing |
| `serde` / `serde_json` | Serialization |
| `yansi` 1.0 | Colored terminal output |
| `thiserror` 2 | Error derive macros |
| `tracing` | Structured logging |
| `rand` 0.9 | Random name generation for wildcard detection |
| `ipnetwork` 0.21 | IP network/CIDR handling |

## Feature Flags

- **`app`** (default): Enables the CLI binary and pulls in clap, anyhow, tabwriter, tracing-subscriber, etc.
- Without `app`: Library-only build with minimal dependencies.

## Release Process

Releases are automated via GitHub Actions (`.github/workflows/release.yml`):

1. Update `Cargo.toml` version and `CHANGELOG.md`
2. Commit and tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
3. Push: `git push origin master --tags`
4. The workflow automatically:
   - Builds .deb, .rpm, and static Linux musl binary
   - Creates a GitHub Release with all artifacts
   - Pushes Docker image to Docker Hub (`lukaspustina/mhost`)
   - Dispatches to `lukaspustina/homebrew-mhost` tap to update the Homebrew formula

**Homebrew tap**: Separate repo at `lukaspustina/homebrew-mhost` — auto-updated on release via `repository_dispatch`. Requires `HOMEBREW_TAP_TOKEN` secret (fine-grained PAT with Contents write access to the tap repo).

**Secrets required**: `DOCKER_HUB_USERNAME`, `DOCKER_HUB_TOKEN`, `HOMEBREW_TAP_TOKEN`

## Design Notes

- **Async-first**: All DNS lookups are async via tokio. `ResolverGroup` fans out queries concurrently.
- **Library vs App separation**: The `app` module is feature-gated. Library code in `resolver/`, `nameserver/`, `resources/`, `services/` has no CLI dependencies.
- **Build script** (`build.rs`): Generates shell completions (Bash, Fish, Zsh) via `clap_complete` at compile time.
- **Predefined servers use unfiltered endpoints** — no content filtering/blocking by default.
- **CLI argument validation**: All numeric CLI arguments have range bounds enforced via custom `ValueParser` functions in `cli_parser.rs`.
- **Styles**: Terminal styling uses `yansi` 1.0 with plain `static` constants (no `lazy_static`). Runtime-dependent prefixes (affected by `--ascii` mode) are functions in `styles.rs`.

## Common Patterns

- `ResolverGroup::from_system_config(opts)` to create resolvers from OS config
- `MultiQuery::multi_record(name, record_types)` to build queries
- `resolvers.lookup(query).await` returns `Lookups` which has `.a()`, `.aaaa()`, `.mx()`, `.caa()`, `.tlsa()`, `.svcb()`, `.https()`, `.sshfp()`, `.naptr()`, `.hinfo()`, `.openpgpkey()`, etc.
- `.unique()` on lookup results to deduplicate across nameservers
- Statistics via `.statistics()` trait method on result types
