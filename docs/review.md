# mhost — Dev Review Findings

Generated: 2026-02-17 | Last updated: 2026-02-17

## Progress

| Category                | Fixed | Won't Fix | Open | Total |
|-------------------------|------:|----------:|-----:|------:|
| Architecture & Code     |     8 |         5 |    0 |    13 |
| Security                |     3 |         4 |    0 |     7 |
| Test Coverage           |     8 |         1 |    0 |     9 |
| UX / CLI / TUI          |     8 |         5 |    0 |    13 |
| Documentation           |    11 |         0 |    0 |    11 |
| **Total**               |**38** |    **15** | **0**|**53** |

## Status Legend

- [ ] Open
- [x] Fixed
- [-] Won't fix (with reason)

---

## 1. Architecture & Code Quality

### HIGH

- [x] **A-1**: Lint code fully duplicated between `app/common/lints/` and `app/mhost/modules/check/lints/` — all 9 shared lint modules have identical logic + identical tests copied in both locations. mdive imports from the CLI path instead of `app/common/`. — Fixed: CLI lint files now import shared functions from `app::common::lints`, keeping only pipeline structs + CLI-specific async logic. ~61 duplicated tests removed.
- [x] **A-2**: `CheckResult` enum defined in two places (`app/common/lints/mod.rs` and `app/mhost/modules/check/lints/mod.rs`). — Fixed: CLI mod.rs now re-exports `CheckResult` from `app::common::lints`.

### MEDIUM

- [x] **A-3**: TUI imports `is_ascii` from `app::output::styles` instead of `app::common::styles`, violating the documented dependency rule. (`src/app/mdive/ui.rs:14`) — Fixed as part of D-8 mdive import rewiring.
- [-] **A-4**: `App` struct is a God Object with 37+ fields covering input, filter, query, navigation, popup, discovery, whois, stats, and history state. (`src/app/mdive/app.rs:492-550`) — Won't fix: refactoring TUI state into sub-structs is significant churn for marginal benefit; the single struct keeps all state co-located for the event loop.
- [-] **A-5**: `ingest_batch()` and `rebuild_rows()` share ~120 lines of duplicated record-to-row transformation logic. (`src/app/mdive/app.rs:1306-1587`) — Won't fix: the two code paths serve different purposes (incremental append vs full rebuild) and extracting shared logic would add indirection without clear benefit.
- [x] **A-6**: Errors silently dropped in `sliding_window_lookups` via `.map(|l| l.ok())` — no logging when all resolvers fail. (`src/resolver/mod.rs:384-398`) — Replaced with `filter_map` that logs each error at `debug!` level, plus a summary log when all lookups fail.

### LOW

- [-] **A-7**: `Errors` trait double-boxes references: `Box<&dyn Error>` adds unnecessary heap allocation. (`src/error.rs:52-54`) — Won't fix: the trait is rarely called and changing it would require updating all implementors for negligible performance gain.
- [-] **A-8**: `NameServerConfig` enum has 4 variants sharing `ip_addr`, `port`, `name` — could be a struct with `Protocol` field. (`src/nameserver/mod.rs:71-96`) — Won't fix: the enum variants have different associated data (TLS auth name, HTTPS hostname) making a flat struct less type-safe.
- [x] **A-9**: `#[allow(dead_code)]` on public `RecordType` enum — unnecessary for pub items. (`src/resources/record_type.rs:22`)
- [x] **A-10**: `#[allow(dead_code)]` on public `Lookups::new` constructor. (`src/resolver/lookup.rs:72`)
- [x] **A-11**: `unwrap()` in library code for chrono Duration conversion — should be `expect()`. (`src/resolver/lookup.rs:691`)
- [-] **A-12**: `indexmap` always compiled but only used in `diff.rs`. (`Cargo.toml:48`) — Won't fix: feature-gating a small, common dependency adds complexity for negligible binary size savings.
- [x] **A-13**: Debug/release behavior differs for `exit_subcommand_invalid` (returns Ok in debug, CliParsingFailed in release). (`src/bin/mhost.rs:42-51`) — Fixed: removed cfg split; always returns `ExitStatus::Ok` since showing help is a successful operation (consistent with `--help`).

---

## 2. Security

### MEDIUM

- [x] **S-1**: TCP DNS response buffer sized by untrusted server — `read_u16()` from remote server controls allocation (up to 64KB per response). (`src/resolver/raw.rs:302-308`) — Added 16KB cap with error on oversized responses.
- [x] **S-2**: Country parameter interpolated into URL path — `public-dns:XX` format string in URL. Parser restricts to alphanumeric, but no defense-in-depth at URL construction. (`src/services/server_lists/public_dns.rs:36-39`) — Added validation at URL construction: max 3 ASCII alphanumeric chars.
- [x] **S-3**: HTTP clients use `Client::new()` without default timeouts or redirect limits — missing `connect_timeout`, no redirect policy. (`src/services/whois/service.rs:367`, `src/services/server_lists/mod.rs:156`) — Both clients now use `Client::builder()` with `timeout`, `connect_timeout(10s)`, and `redirect(Policy::limited(3))`.

### LOW

- [-] **S-4**: Unbounded file reads: `--resolv-conf`, zone files, wordlist files, nameserver files — no size limits. (`src/system_config.rs:24-26`, `src/app/common/discover/wordlist.rs:449`, `src/nameserver/load.rs:29`) — Won't fix: local files are trusted input; user controls what files they pass.
- [-] **S-5**: Nameserver file entries each trigger DNS resolution — large file causes query amplification. (`src/nameserver/load.rs:29-64`) — Won't fix: user-supplied file, user controls content.
- [-] **S-6**: CT log / server list response size check bypassed by chunked transfer encoding. (`src/app/common/discover/ct_logs.rs:41-58`) — Won't fix: low risk; responses come from known public services.
- [-] **S-7**: `lru_time_cache` 0.11 last published 2019 — potentially unmaintained. (`Cargo.toml`) — Won't fix: small, stable dependency with no known vulnerabilities.

---

## 3. Test Coverage

### HIGH

- [x] **T-1**: `rdata/soa.rs` has zero tests — CLAUDE.md mandates all rdata types have unit tests. (`src/resources/rdata/soa.rs`) — Added 4 tests: constructor/accessor round-trip, negative timers, equality, inequality on serial.
- [x] **T-2**: `resolver/error.rs` untested — error classification (`From<ProtoError>` -> Timeout/Refused/ServFail) is a critical correctness boundary. (`src/resolver/error.rs`) — Added 11 tests: all ProtoError variants, ResolveError delegation, JoinError cancelled, and Display messages.
- [x] **T-3**: `Record` custom PartialEq/Hash (ignoring TTL) untested, `associated_name()` untested. (`src/resources/record.rs`) — Added 12 tests: equality/inequality, hash with TTL ignored, and associated_name for A, CNAME, MX, NS, PTR, SRV, SOA, HTTPS.

### MEDIUM

- [x] **T-4**: `check_spf()` has no tests in either `app/common/lints/spf.rs` or `app/mhost/modules/check/lints/spf.rs`. — Added 7 tests: num_spf zero/one/multiple, parsed valid/invalid/identical/differing.
- [x] **T-5**: `format_rdata()` — pure function producing string output for every RData variant — untested. (`src/app/common/rdata_format.rs`) — Added 18 tests covering A, AAAA, CNAME, MX, TXT, SRV, SOA, CAA (normal + critical), SVCB, HINFO, NULL, OPT, ZERO, OPENPGPKEY, NS, PTR, TLSA, DNSKEY, DS.
- [x] **T-6**: No CLI lit tests for `verify`, `dnssec`, or `get-server-lists` commands. (`tests/lit/`) — Added lit tests for `dnssec` (cloudflare.com) and `verify` (example.com with fixture zone file). `get-server-lists` intentionally skipped (hits external HTTP endpoints).
- [x] **T-7**: `TXT::as_string()` missing multi-chunk and edge case tests. (`src/resources/rdata/txt.rs`) — Added 7 tests: single chunk, multi-chunk concatenation, empty, empty chunks, is_spf empty, txt_data round-trip.
- [x] **T-8**: `ParsedTxt::from_str()` dispatch ordering untested. (`src/resources/rdata/parsed_txt/mod.rs`) — Added 9 tests: dispatch for SPF, DMARC, MTA-STS, TLS-RPT, BIMI, domain verification, MS Office 365, unparseable error, DMARC-before-domain-verification ordering.
- [-] **T-9**: No Serde round-trip tests despite most types deriving `Serialize`/`Deserialize`. — Won't fix: compiler-generated derives are virtually never wrong; testing them is busywork.

---

## 4. UX / CLI / TUI

### HIGH

- [x] **U-1**: Subcommand aliases undocumented — work via `infer_subcommands(true)` prefix matching, not explicit `.alias()`. Adding any subcommand with same prefix breaks them. (`src/app/mhost/cli_parser.rs`) — Added explicit `.alias()` for lookup(l), check(c), discover(d), verify(v). Existing: propagation(prop), trace(t).
- [-] **U-2**: `-p` flag collision — globally means `--predefined`, in subcommands means `--show-partial-results`. (`cli_parser.rs:155` vs `cli_parser.rs:404,575,645`) — Won't fix: accepted as intentional CLI design.
- [x] **U-3**: `--output-options` not validated — unknown values silently ignored, options undiscoverable. (`cli_parser.rs:275-293`) — Added validation in `SummaryOptions::try_from` and `JsonOptions::try_from`; unknown options now produce clear error messages listing valid values.

### MEDIUM

- [-] **U-4**: `--no-system-lookups` vs `--no-system-nameservers` — nearly identical names, unclear distinction in help text. (`cli_parser.rs:93-106`) — Won't fix: renaming would be a breaking change; the distinction is documented in `--help`.
- [-] **U-5**: `check` has 12 `--no-*` flags but no `--only` flag to select specific checks. (`cli_parser.rs:391-495`) — Won't fix: new feature scope; defer to roadmap.
- [x] **U-6**: Output phase ordering inconsistent — `check` puts `+ Finished.` before results, `lookup` puts it after. — Fixed: moved `print_finished()` after status message in check's `summary_output()`. Updated 3 lit tests.
- [-] **U-7**: Statistics line uses terse abbreviations ("RR", "Nx") without explanation. (`src/app/mhost/console.rs:213`) — Won't fix: standard DNS abbreviations; expanding them would hurt information density.
- [x] **U-8**: mdive: No visual indicator for human/raw view toggle state. (`src/app/mdive/ui.rs`) — Fixed: added HUMAN/RAW badge to status bar next to mode indicator.

### LOW

- [x] **U-9**: Typo: "coloons" -> "colons" in nameserver help. (`cli_parser.rs:142`)
- [x] **U-10**: Example domains inconsistent — some use `lukas.pustina.de`, others `example.com`. (`cli_parser.rs:400,570,716`) — Replaced all occurrences with `example.com`.
- [x] **U-11**: Error message says "json options" for summary format (copy-paste error). (`app_config.rs:145`)
- [-] **U-12**: `-s` means `--nameserver` globally but `--service` in `lookup` subcommand. (`cli_parser.rs:139,748`) — Won't fix: same intentional short-flag reuse pattern as U-2.
- [x] **U-13**: Page up/down hardcoded to 10 rows regardless of terminal height. (`src/app/mdive/app.rs:900-915`) — Fixed: added `visible_table_rows` field to App, set from draw_table() area height, used in PageUp/PageDown.
- [-] **U-14**: `show_commands()` fragile string truncation depending on clap's exact output format. (`cli_parser.rs:959-973`) — Won't fix: low impact; only affects info command help rendering.

---

## 5. Documentation

### HIGH

- [x] **D-1**: Architecture diagram uses pre-refactor paths — shows `app/cli_parser.rs` instead of `app/mhost/cli_parser.rs`. `bin/mdive/` doesn't exist; TUI modules are at `src/app/mdive/`. (CLAUDE.md) — Replaced diagram with accurate three-layer layout showing `app/common/`, `app/mhost/`, `app/mdive/`.
- [x] **D-2**: Feature flag names wrong — documents `app`/`tui` but actual features are `app-cli`/`app-tui`. Claims `tui` depends on `app` but `app-tui` depends on `app-lib`, not `app-cli`. (CLAUDE.md) — Updated to document `app-lib`/`app-cli`/`app-tui` with correct dependency chain, noted `app`/`tui` as aliases.

### MEDIUM

- [x] **D-3**: `records.rs` and `styles.rs` described as output-module files, but canonical locations are now `app/common/`. (CLAUDE.md) — Updated output module section to note re-export stubs and canonical locations.
- [x] **D-4**: `app-lib` feature layer not documented at all. (CLAUDE.md) — Added `app-lib` to feature flags section and architecture diagram.
- [x] **D-5**: Truncated sentence in "Efficiency" principle: "parallelize lookups across" stops mid-sentence. (CLAUDE.md line 18)
- [x] **D-6**: Stale HTML comment in README trace section. (README.md ~line 345) — Removed malformed `<mdive-discovery-view-full-github!-- TODO:...` text.
- [x] **D-7**: ROADMAP.md header says "v0.8.0" but project is at v0.9.0. (ROADMAP.md)
- [x] **D-8**: `app-tui` feature has implicit dependency on `app-cli` through `crate::app::modules` imports — building `--no-default-features --features app-tui` would fail. Latent build bug. (Cargo.toml + `src/app/mdive/`) — Rewired all mdive imports from `app::modules::*` to `app::common::*`. Also fixed `ui.rs` importing `is_ascii` from output (A-3). Verified `--no-default-features --features app-tui` now compiles.

### LOW

- [x] **D-9**: Common-vs-CLI lint split undocumented (9 shared + 4 CLI-only). (CLAUDE.md) — Documented in Block 4 CLAUDE.md architecture update.
- [x] **D-10**: No error handling patterns documented (`thiserror` in lib, `anyhow` in app, `PartialResult` pattern). (CLAUDE.md) — Fixed: added "Error Handling" section to CLAUDE.md documenting the three-layer strategy (thiserror in library, anyhow in app, PartialResult for CLI command modules).
- [x] **D-11**: "84 pre-configured public resolvers" count hardcoded in multiple places — will drift. (README.md, CLI help) — Fixed: replaced exact "84" with "80+" in README.md prose; kept exact count only in the Predefined Nameservers detail section next to the provider table where it's easy to keep in sync.
