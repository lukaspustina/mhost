# CLAUDE.md — mhost

DNS lookup utility and reusable Rust library (a `host`/`dig` replacement): binaries `mhost` (CLI)
and `mdive` (TUI). Roadmap: `ROADMAP.md`. Architecture diagram, output/re-export stubs, mdive
design, error layers, common API patterns, network-test history and the release process:
`docs/development.md`.

## Rules

- Don't change the `-p` short flag mapping: `--predefined` globally, `--show-partial-results` in
  subcommands. Accepted CLI design.
- No heavy dependencies for minor convenience — check whether existing deps cover it.
- Performance, efficiency, stability and security are the product: efficient algorithms, no
  needless allocations, use the async multi-query fan-out across nameservers and record types,
  validate at boundaries, deterministic tests (pinned randomness, no time dependence).

## Features

`app-lib` (shared `app/common/`, pulls `anyhow`, `humantime`, `services`) ← `app-cli` (default,
`mhost`) and `app-tui` (`mdive`); `app`/`tui` are aliases. No `app-*` feature: library-only build.

## Dependency rules

- Library code (`resolver/`, `nameserver/`, `resources/`, `services/`, `lints/`) never imports
  from `app/`; it uses `thiserror` enums per module, never `anyhow`. App code uses `anyhow` with
  `.context("what failed")`; never swallow an error silently (log at `debug!` minimum).
- The 9 pure lints live ungated in `src/lints/`; network-needing CLI lints in
  `app/mhost/modules/check/lints/`.
- Shared CLI/TUI logic goes to `app/common/`; `app/mdive/` never imports `app/mhost/output/`.
- No hickory type in the public API: hickory conversions are crate-private inherent fns
  (`from_proto`, `to_proto`, `Error::from_net`), never `From` impls. `resolver::raw` and
  `resolver::delegation` are `pub(crate)`, `app-cli` only.
- hickory 0.26 semantics relied on (`resolver/lookup.rs` `IntoLookup`): answers plus matching
  authority/additional and NS glue; error rcodes reported as Nx; unrequested DNSSEC records are
  stripped unless DO is set — fetch RRSIGs with `raw::raw_dnssec_query`.
- A raw query result is usable only when `Ok`, NOERROR and carrying the queried type: a lame
  server's REFUSED/SERVFAIL arrives as `Ok`, so never classify by `is_err()` alone.
- A `udp:` nameserver stays UDP-only in hickory; truncated answers retry once over
  `Resolver::tcp_retry` (`single_lookup`). Never add a TCP `ConnectionConfig`: hickory then drops
  UDP after one timeout.
- Untrusted input: CLI-printed DNS data goes through `app::common::records::term_safe`; `check`
  probes only global nameserver addresses (`nameserver::is_global_ip`);
  `ResolverGroupBuilder::deny_non_global` guards consumers taking nameservers from callers.
- Numeric CLI arguments get range bounds via `ValueParser` functions in `cli_parser.rs`.
- Docs site: `website/` (Docusaurus, `just site-*`); its checks in `src/website_tests/` compile only
  under `cfg(mhost_repo)`, set by `build.rs` when a `justfile` exists.

## Build and test

- `just adlc-verify` is the gate (fmt-check, clippy, offline lib + doc tests); `[exceptions] no-ci`
  makes the local hooks the gate. `just --list` for the rest.
- Seven lib tests need the network and carry `#[ignore = "needs network"]`: `just test-lib` and the
  cron workflow run them (`--include-ignored`), `just test-offline` and `ci.yml` do not.
  `just test` adds lit CLI tests querying `8.8.8.8`; they may fail on DNS timeouts.
- Fake-nameserver tests (`src/resolver/tcp_fallback_tests/fake_ns.rs`) bind loopback UDP/TCP
  sockets; run cargo outside a sandbox that forbids local binding.
- A new rdata type or `RecordType` variant gets unit tests in its module (constructor/accessor
  round-trips, enum conversions) and is added to `FromStr`, `all()` and
  `from_str_all_standard_types`; `RData` accessor tests in `src/resources/rdata/mod.rs` cover it.
- Lit tests (`tests/lit/*.output`): regex patterns (`[[\d+]]`, `[[s*]]`) for counts that change
  with record types; never assert on wordlist-discovered subdomains.
- crates.io publishing is manual (`cargo publish` from the tag); no workflow does it.
