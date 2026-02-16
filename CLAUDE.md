# CLAUDE.md — mhost

## Git Commits

- Do NOT add a `Co-Authored-By` line for Claude in commit messages.

## Project Overview

**mhost** (v0.7.0) is a modern, high-performance DNS lookup utility written in Rust. It is both a CLI tool and a reusable library. Think of it as an advanced replacement for the classic `host` / `dig` commands.

- **Author**: Lukas Pustina
- **License**: MIT / Apache-2.0
- **Rust edition**: 2021
- **Repository**: https://github.com/lukaspustina/mhost.git

## Key Features

- Multi-server concurrent DNS lookups (queries many nameservers in parallel, aggregates results)
- DNS over UDP, TCP, TLS (DoT), and HTTPS (DoH)
- 20 DNS record types: A, AAAA, ANAME, ANY, CAA, CNAME, HINFO, HTTPS, MX, NAPTR, NS, NULL, OPENPGPKEY, PTR, SOA, SRV, SSHFP, SVCB, TLSA, TXT, plus DNSSEC records
- Domain/subdomain discovery via 10+ strategies (wordlists, CT logs, SRV probing, TXT mining, AXFR, NSEC walking, permutation, reverse DNS, recursive)
- DNS configuration validation with 13 lints (SOA, NS, CNAME, MX, SPF, DMARC, CAA, TTL, DNSSEC, HTTPS/SVCB, AXFR, open resolver, delegation)
- Domain lookup command for full DNS profile in one operation (~40-65 well-known subdomain/record combinations)
- WHOIS integration (via RIPEStats API)
- Output as human-readable summary tables or JSON (full `Serialize` + `Deserialize` round-trip on all types)
- DNS snapshot and timeline diff: save lookup JSON, diff against live DNS or another snapshot via `--left-from-file` / `--right-from-file`
- Predefined unfiltered DNS servers: 84 configurations across 6 providers (Cloudflare, Google, Quad9, Mullvad, Wikimedia, DNS4EU)
- Built-in wordlist of 424 subdomain entries for discovery
- Info command for DNS record type and well-known subdomain documentation

## Build & Test Commands

```sh
cargo build                # Build everything (default feature = "app")
cargo build --lib          # Build library only
cargo build --features tui # Build with TUI (mdive binary)
cargo check                # Type-check without full compilation
cargo test --lib           # Run library unit tests (397 tests, fast, no network needed)
cargo test                 # Run all tests including CLI integration tests (slower, needs network)
cargo clippy               # Lint
cargo fmt                  # Format

# mdive TUI
cargo run --bin mdive --features tui -- example.com
cargo build --bin mdive --features tui --no-default-features  # TUI-only (pulls in app via dependency)
```

### Test guidelines

- **`cargo test --lib`** is the reliable quick check — 393 unit tests, no network needed.
- **`cargo test`** also runs lit-based CLI integration tests (`tests/cli_output_tests.rs`) that make real DNS queries via `8.8.8.8`. These may fail due to DNS timeouts or changed records.
- **Every new rdata type or RecordType variant must have unit tests.** Each rdata module has a `#[cfg(test)] mod tests` block covering constructor/accessor round-trips and any enum conversions (`From<u8>`, `Display`).
- **`RecordType::from_str` must cover all variants.** If you add a new `RecordType` variant, add it to `FromStr`, `all()`, and the `from_str_all_standard_types` test. The `display_round_trip` test will catch omissions.
- **`RData` accessor tests** in `src/resources/rdata/mod.rs` verify each variant's accessor returns `Some` and unrelated accessors return `None`.
- **Lit tests** live in `tests/lit/*.output`. Use regex patterns (`[[\d+]]`, `[[s*]]`) instead of hardcoded counts for values that change when record types are added (e.g., request counts, record type counts). Avoid asserting on specific subdomains from wordlist discovery — these are flaky due to DNS timeouts.

## Architecture

```
src/
├── bin/mhost.rs              # CLI entry point
├── bin/mdive/                # TUI interactive DNS explorer (behind "tui" feature flag)
│   ├── main.rs              #   TUI entry point, event loop, key mapping
│   ├── app.rs               #   App state, Action enum, update logic
│   ├── ui.rs                #   Ratatui rendering (main table, popups, status bar)
│   ├── dns.rs               #   DNS query spawning (domain lookup, WHOIS)
│   ├── discovery.rs         #   Discovery strategy spawning (CT logs, wordlist, SRV, TXT mining, permutation)
│   └── lints.rs             #   DNS health check integration for TUI
│
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
│   ├── common/             #   Shared utilities used by both mhost CLI and mdive TUI
│   │   ├── mod.rs          #     Module exports
│   │   ├── ordinal.rs      #     Ordinal trait for record type ordering
│   │   ├── rdata_format.rs #     Record data formatting (format_rdata, format_rdata_human)
│   │   ├── record_type_info.rs #  Record type info lookup
│   │   ├── reference_data.rs #   Reference data for record types, subdomains, TXT sub-types
│   │   ├── resolver_args.rs #    ResolverArgs: CLI-to-resolver config bridge
│   │   ├── styles.rs       #     Record type colors/bold (shared by CLI and TUI)
│   │   └── subdomain_spec.rs #   SubdomainEntry, Category, default_entries()
│   ├── output/             #   Output formatting
│   │   ├── mod.rs          #     OutputConfig, OutputFormat, Output, Ordinal trait
│   │   ├── json.rs         #     JSON output formatter
│   │   ├── styles.rs       #     Shared output styles (prefixes, colors for status indicators)
│   │   ├── records.rs      #     Rendering impls for all DNS record types (shared across commands)
│   │   └── summary/        #     Summary (human-readable) output formatters
│   │       ├── mod.rs      #       SummaryOptions, SummaryFormat, SummaryFormatter, Rendering trait
│   │       ├── lookups.rs  #       SummaryFormatter for Lookups (lookup-specific output)
│   │       ├── diff.rs     #       SummaryFormatter for DiffResults
│   │       ├── propagation.rs #    SummaryFormatter for PropagationResults
│   │       └── whois.rs    #       SummaryFormatter for WhoisResponse
│   └── modules/            #   Command implementations:
│       ├── lookup/         #     DNS record lookups (+ service_spec.rs for SRV)
│       ├── domain_lookup/  #     Domain-wide lookup of apex + well-known subdomains
│       ├── discover/       #     Subdomain discovery (+ wordlist.rs, ct_logs.rs, srv_probing.rs,
│       │                   #       txt_mining.rs, permutation.rs)
│       ├── check/          #     DNS validation lints:
│       │   └── lints/      #       cnames.rs, soa.rs, spf.rs, dmarc.rs, ns.rs, mx.rs,
│       │                   #       caa.rs, ttl.rs, dnssec_lint.rs, https_svcb.rs,
│       │                   #       axfr.rs, open_resolver.rs, delegation.rs
│       ├── propagation/    #     DNS propagation checking
│       ├── diff/           #     DNS record diff between nameservers
│       ├── info/           #     DNS record type info display
│       ├── completions/    #     Shell completion generation
│       └── get_server_lists/ #   Download nameserver lists
│
├── system_config.rs         # Parse /etc/resolv.conf
├── estimate.rs              # Estimation utilities
├── diff.rs                  # Diff utilities
└── utils/                   # Helpers (serialize/deserialize incl. NameServerConfig serde, buffer_unordered_with_breaker)
```

## CLI Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `lookup` | `l` | Look up arbitrary DNS records of a domain name, IP address, or CIDR block |
| `domain-lookup` | `domain` | Look up a domain's apex records and ~40-65 well-known subdomains in one operation |
| `discover` | `d` | Discover host names and subdomains using 10+ strategies |
| `check` | `c` | Validate DNS configuration using 13 lints |
| `propagation` | `prop` | Check DNS propagation across predefined public resolvers |
| `diff` | -- | Compare DNS records between two nameserver sets or JSON snapshots |
| `info` | -- | Show information about DNS record types and well-known subdomains |
| `completions` | -- | Generate shell completions for bash, zsh, or fish |
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
| `ratatui` 0.30 | Terminal UI framework (tui feature only) |
| `crossterm` 0.28 | Cross-platform terminal manipulation (tui feature only) |

## Feature Flags

- **`app`** (default): Enables the CLI binary and pulls in clap, anyhow, tabwriter, tracing-subscriber, etc.
- **`tui`**: Enables the `mdive` interactive TUI binary. Depends on `app` and additionally pulls in `ratatui`, `crossterm`, and `regex`.
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

## Output Module Structure

The `app/output/` module has a layered design separating shared concerns from command-specific formatting:

- **`output/mod.rs`** — Top-level `OutputConfig` (JSON vs Summary), `Output` dispatcher, `Ordinal` trait for record type ordering.
- **`output/styles.rs`** — Shared output chrome: status prefixes (`ok_prefix()`, `attention_prefix()`, `itemization_prefix()`), status colors (`OK`, `ATTENTION`, `ERROR`). Used by all summary formatters.
- **`output/records.rs`** — `Rendering` trait impls for all DNS record/rdata types (`Record`, `MX`, `SOA`, `TXT`, `SVCB`, etc.) plus a private `styles` submodule with per-record-type colors. This is a **shared rendering layer** — not tied to any single command. Used by lookups, propagation, diff, and any future command that displays DNS records.
- **`output/summary/mod.rs`** — Defines `SummaryOptions`, `SummaryFormat`, `SummaryFormatter` trait, and the `Rendering` trait. Each command implements `SummaryFormatter` in its own file under `summary/`.
- **`output/summary/{lookups,diff,propagation,whois}.rs`** — Per-command `SummaryFormatter` impls. These contain only command-specific output logic (headers, grouping, tables), delegating record rendering to the shared `Rendering` impls in `records.rs`.

**Key rule**: DNS record rendering (`impl Rendering for X`) belongs in `records.rs`, not in command-specific files. Command files should only contain `SummaryFormatter` impls and command-specific presentation logic.

**Visibility note**: `records.rs` is a sibling of `summary/` (both children of `output/`), so it accesses `SummaryOptions` fields via their public accessor methods (`opts.human()`, `opts.condensed()`), not direct field access.

**TUI rendering**: The mdive TUI uses `app/common/rdata_format.rs` for record data formatting and `app/common/styles.rs` for record type colors, rather than the summary-specific `Rendering` trait in `records.rs`.

## mdive — Interactive TUI

`mdive` is an interactive terminal UI for DNS exploration, built with `ratatui` and `crossterm` behind the `tui` feature flag.

**Binary**: `src/bin/mdive/main.rs` — separate from `mhost` CLI but shares the library and `app/common/` modules.

**Module structure**:
- `main.rs` — Entry point, tokio event loop, key-to-action mapping, task spawning orchestration
- `app.rs` — `App` state struct, `Action` enum (30+ variants), `update()` state machine, `Popup` enum, `RecordRow`, `DiscoveryState`
- `ui.rs` — All ratatui rendering: main table, input bar, category toggles, stats panel, status bar, 6 popup types (Record Detail, Help, Servers, WHOIS, Lints, Discovery), `render_scrollable_popup` helper
- `dns.rs` — Spawns domain lookup and WHOIS queries as `spawn_local` tasks; accepts `Arc<ResolverGroup>`
- `discovery.rs` — Spawns 5 discovery strategies (CT Logs, Wordlist, SRV Probing, TXT Mining, Permutation) + wildcard check; accepts `Arc<ResolverGroup>`
- `lints.rs` — Runs DNS health check lints against accumulated lookups

**Key design decisions**:
- **Generation-tagged actions**: Every DNS/discovery action carries a `generation: u64` tag. Stale results from previous queries are silently discarded.
- **Shared ResolverGroup via Arc**: Built once per query, stored in `App`, shared across domain lookup and all discovery tasks. Eliminates redundant resolver construction.
- **Task cancellation**: DNS and discovery task `JoinHandle`s are stored in `App` and `.abort()`ed when a new query starts.
- **Progressive results**: DNS and discovery queries send `Batch` actions as results arrive, so the table populates incrementally.
- **Vi-style navigation**: `j/k` movement, `gg`/`G` jumps, digit-prefixed commands, count buffer with 1s timeout.

## Common Patterns

- `ResolverGroup::from_system_config(opts)` to create resolvers from OS config
- `MultiQuery::multi_record(name, record_types)` to build queries
- `resolvers.lookup(query).await` returns `Lookups` which has `.a()`, `.aaaa()`, `.mx()`, `.caa()`, `.tlsa()`, `.svcb()`, `.https()`, `.sshfp()`, `.naptr()`, `.hinfo()`, `.openpgpkey()`, etc.
- `.unique()` on lookup results to deduplicate across nameservers
- Statistics via `.statistics()` trait method on result types
