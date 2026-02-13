# CLAUDE.md — mhost

## Project Overview

**mhost** (v0.3.1) is a modern, high-performance DNS lookup utility written in Rust. It is both a CLI tool and a reusable library. Think of it as an advanced replacement for the classic `host` / `dig` commands.

- **Author**: Lukas Pustina
- **License**: MIT / Apache-2.0
- **Rust edition**: 2018
- **Repository**: https://github.com/lukaspustina/mhost.git

## Key Features

- Multi-server concurrent DNS lookups (queries many nameservers in parallel, aggregates results)
- DNS over UDP, TCP, TLS (DoT), and HTTPS (DoH)
- Domain/subdomain discovery via wordlists
- DNS configuration validation (linting) against RFCs
- WHOIS integration (via RIPEStats API)
- Output as human-readable summary tables or JSON

## Build & Test Commands

```sh
cargo build                # Build everything (default feature = "app")
cargo build --lib          # Build library only
cargo check                # Type-check without full compilation
cargo test --lib           # Run library unit tests (83 tests, fast, no network needed)
cargo test                 # Run all tests including CLI integration tests (slower, may need network)
cargo clippy               # Lint
cargo fmt                  # Format
```

**Note**: The CLI integration tests (`tests/cli_output_tests.rs`) use the `lit` crate for CLI output testing and may fail if external DNS queries time out. `cargo test --lib` is the reliable quick check.

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
│   ├── predefined.rs       #   Predefined public nameservers
│   └── load.rs             #   Load nameserver configs from files
│
├── resources/               # DNS record types and data
│   ├── record_type.rs      #   RecordType enum (A, AAAA, MX, SOA, SRV, TXT, etc.)
│   ├── record.rs           #   Record struct
│   └── rdata/              #   Record-specific data types (mx, soa, srv, txt, parsed_txt/)
│
├── services/                # External service integrations
│   ├── whois/              #   WHOIS via RIPEStats API
│   └── server_lists/       #   Download public DNS server lists (public-dns.info, OpenNIC)
│
├── statistics/              # Result aggregation & statistics traits
│
├── app/                     # CLI application layer (behind "app" feature flag)
│   ├── cli_parser.rs       #   clap v2 argument definitions
│   ├── app_config.rs       #   Consolidated AppConfig from CLI args
│   ├── resolver.rs         #   App-level resolver setup
│   ├── console.rs          #   User console output
│   ├── logging.rs          #   tracing/logging setup
│   ├── output/             #   Output formatting (json.rs, summary/, styles.rs)
│   └── modules/            #   Command implementations:
│       ├── lookup/         #     DNS record lookups (+ service_spec.rs for SRV)
│       ├── discover/       #     Subdomain discovery (+ wordlist.rs)
│       ├── check/          #     DNS validation lints (lints/cnames.rs, soa.rs, spf.rs)
│       └── get_server_lists/ #   Download nameserver lists
│
├── system_config.rs         # Parse /etc/resolv.conf
├── estimate.rs              # Estimation utilities
├── diff.rs                  # Diff utilities
└── utils/                   # Helpers (serialize, deserialize, buffer_unordered_with_breaker)
```

## Key Dependencies

| Crate | Purpose |
|---|---|
| `trust-dns-resolver` 0.20 | Core DNS resolution (DoT, DoH, DNSSEC) |
| `tokio` 1 (full) | Async runtime |
| `futures` 0.3 | Async combinators (join_all, streams) |
| `reqwest` 0.11 | HTTP client (DoH, WHOIS, server list downloads) |
| `clap` 2 | CLI argument parsing (app feature only) |
| `nom` 5 | Parser combinators for nameserver string parsing |
| `serde` / `serde_json` | Serialization |
| `yansi` 0.5 | Colored terminal output |
| `thiserror` | Error derive macros |
| `tracing` | Structured logging |

## Feature Flags

- **`app`** (default): Enables the CLI binary and pulls in clap, anyhow, tabwriter, tracing-subscriber, etc.
- Without `app`: Library-only build with minimal dependencies.

## Design Notes

- **Async-first**: All DNS lookups are async via tokio. `ResolverGroup` fans out queries concurrently.
- **Library vs App separation**: The `app` module is feature-gated. Library code in `resolver/`, `nameserver/`, `resources/`, `services/` has no CLI dependencies.
- **Build script** (`build.rs`): Generates shell completions (Bash, Fish, Zsh) via clap at compile time.
- The library API is self-described as "PoC state" — functional but the author considers the design WIP.

## Common Patterns

- `ResolverGroup::from_system_config(opts)` to create resolvers from OS config
- `MultiQuery::multi_record(name, record_types)` to build queries
- `resolvers.lookup(query).await` returns `Lookups` which has `.a()`, `.aaaa()`, `.mx()`, etc.
- `.unique()` on lookup results to deduplicate across nameservers
- Statistics via `.statistics()` trait method on result types
