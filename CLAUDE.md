# CLAUDE.md — mhost

## Rules

- Do NOT add a `Co-Authored-By` line for Claude in commit messages.
- Don't add heavy dependencies for minor convenience — check if existing deps already cover the need.
- Don't mix formatting-only changes with functional changes in the same commit.
- Don't modify unrelated modules "while you're in there" — keep changes scoped.
- Don't add speculative flags, config options, or abstractions without a current caller.
- Don't bypass failing checks (`--no-verify`, `#[allow(...)]`) without explaining why.
- Don't hide behavior changes inside refactor commits — separate them.
- Don't include PII, real email addresses, or real domains (other than example.com) in test data, docs, or commits.
- If uncertain about an implementation detail, leave a concrete `TODO("reason")` rather than a hidden guess.
- Don't change the `-p` short flag mapping — it intentionally means `--predefined` globally and `--show-partial-results` in subcommands. This is accepted CLI design.

## Engineering Principles

- **Performance**: Prioritize efficient algorithms and data structures. Benchmark critical paths, avoid unnecessary allocations and copies.
- **Efficiency**: Make use of mhost async, multi-query capabilities to parallelize lookups across multiple nameservers and record types simultaneously.
- **Rust patterns**: Use idiomatic Rust constructs (enums, traits, iterators) for clarity and safety. Leverage type system to prevent invalid states.
- **KISS**: Simplest solution that works. Three similar lines beat a premature abstraction.
- **YAGNI**: Don't build for hypothetical future requirements — solve the current problem.
- **DRY + Rule of Three**: Tolerate duplication until the third occurrence, then extract.
- **SRP**: Each module/struct has one reason to change. Split when responsibilities diverge.
- **Fail Fast**: Validate at boundaries, return errors early, don't silently swallow failures.
- **Secure by Default**: Sanitize external input, no PII in logs, prefer safe APIs.
- **Determinism**: Same input → same output. Pin randomness in tests, avoid time-dependent logic where possible.
- **Reversibility**: Prefer changes that are easy to undo. Feature flags over big-bang migrations, small commits over monolithic ones.

## Project Overview

**mhost** is a modern DNS lookup utility and reusable Rust library — an advanced replacement for `host`/`dig`. Two binaries: `mhost` (CLI) and `mdive` (interactive TUI).

Feature flags (layered):
- **`app-lib`** — shared app layer (`app/common/`): lints, discovery strategies, rendering, styles. Pulls in `anyhow`, `humantime`, `services`.
- **`app-cli`** (default) — CLI binary (`mhost`). Depends on `app-lib`. Adds `clap`, `tabwriter`, `tracing-subscriber`, etc.
- **`app-tui`** — TUI binary (`mdive`). Depends on `app-lib`. Adds `ratatui`, `crossterm`, `regex`.
- **`app`** / **`tui`** — backward-compatibility aliases for `app-cli` / `app-tui`.

Without any `app-*` feature: library-only build with minimal dependencies.

- **Author**: Lukas Pustina | **License**: MIT / Apache-2.0 | **Edition**: 2021
- **Repository**: https://github.com/lukaspustina/mhost.git

mhost provides and all functionality must adhere to these core principles:

- high performance
- high efficiency
- high stability
- high security

## Roadmap

The roadmap of this project is in file ROADMAP.md. It contains a prioritized list of features, improvements, and bug fixes planned for future releases. The roadmap is a living document and may be updated as the project evolves.

## Build & Test

```sh
cargo build                        # Build everything (default feature = "app-cli")
cargo build --lib                  # Build library only
cargo build --features app-tui     # Build with TUI (mdive binary)
cargo check                        # Type-check without full compilation
cargo test --lib                   # Unit tests (fast, no network needed)
cargo test                         # All tests incl. CLI integration tests (slower, needs network)
cargo clippy                       # Lint
cargo fmt                          # Format
cargo run --bin mdive --features app-tui -- example.com  # Run mdive
```

### Test guidelines

- **`cargo test --lib`** is the reliable quick check — no network needed.
- **`cargo test`** also runs lit-based CLI integration tests (`tests/cli_output_tests.rs`) that make real DNS queries via `8.8.8.8`. These may fail due to DNS timeouts or changed records.
- **Every new rdata type or RecordType variant must have unit tests.** Each rdata module has a `#[cfg(test)] mod tests` block covering constructor/accessor round-trips and any enum conversions (`From<u8>`, `Display`).
- **`RecordType::from_str` must cover all variants.** If you add a new `RecordType` variant, add it to `FromStr`, `all()`, and the `from_str_all_standard_types` test. The `display_round_trip` test will catch omissions.
- **`RData` accessor tests** in `src/resources/rdata/mod.rs` verify each variant's accessor returns `Some` and unrelated accessors return `None`.
- **Lit tests** live in `tests/lit/*.output`. Use regex patterns (`[[\d+]]`, `[[s*]]`) instead of hardcoded counts for values that change when record types are added (e.g., request counts, record type counts). Avoid asserting on specific subdomains from wordlist discovery — these are flaky due to DNS timeouts.

## Architecture

```
┌─────────────────────────┐   ┌────────────────────────────┐   ┌────────────────────────────┐
│  Library (no app deps)  │   │  Shared app (app-lib)      │   │  CLI (app-cli)             │
│                         │   │  app/common/               │   │  app/mhost/                │
│  resolver/              │──▶│    lints/ (9 shared lints)  │◀──│    cli_parser.rs           │
│  nameserver/            │   │    discover/ (strategies)   │   │    app_config.rs           │
│  resources/ (rdata)     │   │    records.rs (Rendering)   │   │    modules/ (commands)     │
│  services/ (whois) [S]  │   │    styles.rs (prefixes)     │   │    output/ (CLI rendering) │
│  statistics/            │   │    rendering.rs (trait+opts) │   │      summary/             │
│  diff, estimate, utils  │   │    rdata_format.rs          │   │      json.rs              │
└─────────────────────────┘   │    name_builder.rs          │   └────────────────────────────┘
                              │    ordinal.rs               │
                              │    record_type_info.rs      │   ┌────────────────────────────┐
                              │    reference_data.rs        │   │  TUI (app-tui)             │
                              │    resolver_args.rs         │   │  app/mdive/                │
                              │    subdomain_spec.rs        │   │    app.rs (state + update)  │
                              └────────────────────────────┘   │    ui.rs  (rendering)       │
                                        ▲                      │    dns.rs (queries)         │
                                        └──────────────────────│    discovery.rs             │
                                                               │    lints.rs                 │
                                                               └────────────────────────────┘

Binary entry points: src/bin/mhost.rs, src/bin/mdive.rs
[S] = feature="services" (included by "app-lib"; provides reqwest + HTTP services)
```

**Dependency rules**:
- Library code (`resolver/`, `nameserver/`, `resources/`, `services/`) never imports from `app/`.
- `app/common/` (feature `app-lib`) is the shared layer between CLI and TUI — put reusable lints, discovery strategies, formatting, rendering traits, and reference data here.
- `app/mhost/` (feature `app-cli`) contains CLI-specific code: parser, config, command modules, output formatters.
- `app/mdive/` (feature `app-tui`) contains TUI-specific code: state management, UI rendering, async task orchestration.
- `app/mdive/` imports from `app/common/` for shared business logic. It does **not** import from `app/mhost/output/`.
- CLI-only lints (SOA serial consistency, AXFR exposure, open resolver, delegation) live in `app/mhost/modules/check/lints/` because they require network access during checks. The 9 shared pure lints (CAA, CNAME, DMARC, DNSSEC, HTTPS/SVCB, MX, NS, SPF, TTL) live in `app/common/lints/`.

**Output module** (`app/mhost/output/`):
- `records.rs` and `styles.rs` are re-export stubs for backward compatibility. The canonical implementations live in `app/common/records.rs` and `app/common/styles.rs`.
- `summary/{lookups,diff,propagation,verify,whois}.rs` — Per-command `SummaryFormatter` impls containing CLI-specific presentation logic.
- `json.rs` — JSON output formatting.
- The `Rendering` trait and `SummaryOptions` are defined in `app/common/rendering.rs`.

**Other re-export stubs** (canonical implementations live in `app/common/`):
- `app/mhost/modules/domain_lookup/subdomain_spec.rs` → `app/common/subdomain_spec.rs`
- `app/mhost/modules/info/reference_data.rs` → `app/common/reference_data.rs`

**mdive TUI design**:
- **Generation-tagged actions**: Every DNS/discovery action carries a `generation: u64` tag. Stale results from previous queries are silently discarded.
- **Shared ResolverGroup via Arc**: Built once per query, shared across domain lookup and all discovery tasks.
- **Task cancellation**: `JoinHandle`s stored in `App` and `.abort()`ed when a new query starts.
- **Progressive results**: Queries send `Batch` actions as results arrive, populating the table incrementally.
- **Vi-style navigation**: `j/k`, `gg`/`G`, digit-prefixed commands, count buffer with 1s timeout.

## Error Handling

The codebase uses a layered error strategy:

- **Library layer** (`src/error.rs`, `src/resolver/error.rs`): `thiserror`-derived enums. Each module defines its own `Error` enum with structured variants and `#[from]` conversions. The top-level `mhost::Error` wraps module-level errors.
- **App layer** (`app/mhost/`, `app/mdive/`): `anyhow::Result` for ad-hoc context via `.context()`. App code converts library errors into `anyhow` at module boundaries.
- **`PartialResult` pattern** (`app/mhost/modules/mod.rs`): CLI command modules use `PartialResult<T> = Result<T, PartialError>` where `PartialError::Failed(ExitStatus)` signals a non-fatal command failure (e.g., check found warnings) vs `PartialError::Err(anyhow::Error)` for unexpected errors. `PartialResultExt::into_result()` converts back to `anyhow::Result<ExitStatus>` for the top-level handler in `bin/mhost.rs`.

**Conventions**: Return errors early (fail fast). Use `.context("what failed")` in app code. Don't silently swallow errors — log at `debug!` minimum. Library code never uses `anyhow`.

## Common Patterns

- `ResolverGroup::from_system_config(opts)` — create resolvers from OS config.
- `MultiQuery::multi_record(name, record_types)` — build multi-record queries.
- `resolvers.lookup(query).await` — returns `Lookups` with typed accessors (`.a()`, `.mx()`, `.caa()`, etc.).
- `.unique()` on lookup results — deduplicate across nameservers.
- `.statistics()` trait method — aggregate stats on result types.
- **Async-first**: All DNS lookups are async via tokio. `ResolverGroup` fans out queries concurrently.
- **Build script** (`build.rs`): Generates shell completions (Bash, Fish, Zsh) via `clap_complete` at compile time.
- **Predefined servers** use unfiltered endpoints — no content filtering/blocking by default.
- **CLI argument validation**: All numeric CLI arguments have range bounds enforced via custom `ValueParser` functions in `cli_parser.rs`.
- **Styles**: Terminal styling uses `yansi` 1.0 with plain `static` constants. Runtime-dependent prefixes (affected by `--ascii` mode) are functions in `styles.rs`.

## Release Process

Releases are automated via GitHub Actions (`.github/workflows/release.yml`):

1. Update `Cargo.toml` version and `CHANGELOG.md`
2. Commit and tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
3. Push: `git push origin master --tags`
4. Workflow builds .deb, .rpm, musl binary; creates GitHub Release; pushes Docker image (`lukaspustina/mhost`); dispatches to `lukaspustina/homebrew-mhost` tap.

**Secrets required**: `DOCKER_HUB_USERNAME`, `DOCKER_HUB_TOKEN`, `HOMEBREW_TAP_TOKEN` (fine-grained PAT with Contents write on tap repo).
