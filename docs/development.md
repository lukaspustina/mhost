# mhost: architecture, patterns, release

Loaded on demand from `CLAUDE.md`.

## Architecture

```
┌─────────────────────────┐   ┌────────────────────────────┐   ┌────────────────────────────┐
│  Library (no app deps)  │   │  Shared app (app-lib)      │   │  CLI (app-cli)             │
│                         │   │  app/common/               │   │  app/mhost/                │
│  resolver/              │──▶│    lints/ (re-export stub)  │◀──│    cli_parser.rs           │
│  nameserver/            │   │    discover/ (strategies)   │   │    app_config.rs           │
│  resources/ (rdata)     │   │    records.rs (Rendering)   │   │    modules/ (commands)     │
│  services/ (whois) [S]  │   │    styles.rs (prefixes)     │   │    output/ (CLI rendering) │
│  lints/ (9 pure lints)  │   │    rendering.rs (trait+opts) │   │      summary/             │
│  statistics/            │   │    rdata_format.rs          │   │      json.rs              │
│  diff, estimate, utils  │   │    name_builder.rs          │   └────────────────────────────┘
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

**Output module** (`app/mhost/output/`):
- `records.rs` and `styles.rs` are re-export stubs for backward compatibility. The canonical implementations live in `app/common/records.rs` and `app/common/styles.rs`.
- `summary/{lookups,diff,propagation,verify,whois}.rs` — Per-command `SummaryFormatter` impls containing CLI-specific presentation logic.
- `json.rs` — JSON output formatting.
- The `Rendering` trait and `SummaryOptions` are defined in `app/common/rendering.rs`.

**Other re-export stubs** (canonical implementations live in `app/common/` or the core library):
- `app/common/lints/` → `crate::lints` (9 pure lint modules, extracted to core library)
- `app/mhost/modules/domain_lookup/subdomain_spec.rs` → `app/common/subdomain_spec.rs`
- `app/mhost/modules/info/reference_data.rs` → `app/common/reference_data.rs`

**mdive TUI design**:
- **Generation-tagged actions**: Every DNS/discovery action carries a `generation: u64` tag. Stale results from previous queries are silently discarded.
- **Shared ResolverGroup via Arc**: Built once per query, shared across domain lookup and all discovery tasks.
- **Task cancellation**: `JoinHandle`s stored in `App` and `.abort()`ed when a new query starts.
- **Progressive results**: Queries send `Batch` actions as results arrive, populating the table incrementally.
- **Vi-style navigation**: `j/k`, `gg`/`G`, digit-prefixed commands, count buffer with 1s timeout.

## Error handling

The codebase uses a layered error strategy:

- **Library layer** (`src/error.rs`, `src/resolver/error.rs`): `thiserror`-derived enums. Each module defines its own `Error` enum with structured variants and `#[from]` conversions. The top-level `mhost::Error` wraps module-level errors.
- **App layer** (`app/mhost/`, `app/mdive/`): `anyhow::Result` for ad-hoc context via `.context()`. App code converts library errors into `anyhow` at module boundaries.
- **`PartialResult` pattern** (`app/mhost/modules/mod.rs`): CLI command modules use `PartialResult<T> = Result<T, PartialError>` where `PartialError::Failed(ExitStatus)` signals a non-fatal command failure (e.g., check found warnings) vs `PartialError::Err(anyhow::Error)` for unexpected errors. `PartialResultExt::into_result()` converts back to `anyhow::Result<ExitStatus>` for the top-level handler in `bin/mhost.rs`.

## Common patterns

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

## Network tests

- **`cargo test --lib` is NOT network-free**, despite what the old Makefile claimed: seven of
  its tests talk to the network, and all seven were failing on 2026-08-19 — five whois tests
  calling `stat.ripe.net`, and two parser tests resolving `dns.google` and `tls.cloudflare-dns.com`
  through the host's resolver. `just test-offline` names and skips exactly those.

## Release process

Releases are automated via GitHub Actions (`.github/workflows/release.yml`):

1. Update `Cargo.toml` version and `CHANGELOG.md`
2. Commit and tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
3. Push: `git push origin master --tags`
4. Workflow builds .deb, .rpm, musl binary; creates GitHub Release; pushes Docker image (`lukaspustina/mhost`); dispatches to `lukaspustina/homebrew-mhost` tap.
5. **crates.io is manual**: `cargo publish` from the tagged commit — no workflow does it. 0.11.4 was never published because of this; library consumers (netray) resolve from crates.io, not from the tag.
6. A `v*` tag also deploys mhost.pustina.de via `website.yml`. A new top-level file the crate ships needs a `/`-anchored `include` entry: unanchored ones match at any depth.

**Secrets required**: `DOCKER_HUB_USERNAME`, `DOCKER_HUB_TOKEN`, `HOMEBREW_TAP_TOKEN` (fine-grained PAT with Contents write on tap repo).
