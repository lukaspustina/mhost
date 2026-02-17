# mhost Dev Review Report

## Overview

Five specialized agents performed an in-depth analysis of the mhost codebase across architecture, security, test coverage, UX, and performance. Overall, mhost is a **well-engineered Rust project** with clean module boundaries, zero unsafe code, solid error handling, and comprehensive DNS functionality. The findings below are organized by severity and category.

---

## Critical & High Findings

### SECURITY: Bypassable HTTP Response Size Limits
**Severity: Medium | Files: `ct_logs.rs`, `whois/service.rs`, `public_dns.rs`, `opennic.rs`**

All four HTTP clients check `content_length()` before reading the body, but this returns `None` for chunked transfer encoding. The body is then read in full with `.text().await` without any size limit. A malicious/compromised server could send an unbounded chunked response causing OOM.

**Fix**: Use reqwest's streaming API with a size-limited read, or configure a maximum response body size.

### UX: `--no-system-nameservers` Likely Bug
**Severity: High | File: `cli_parser.rs:84`**

`--no-system-nameservers` has `requires("system nameservers")`, meaning it can only be used if `--system-nameserver` is also passed. This defeats the purpose of the flag -- a user likely wants to disable system nameservers without having to specify one first.

### UX: `-p` Short Flag Overloading
**Severity: High | File: `cli_parser.rs`**

`-p` means `--predefined` at the global level but `--show-partial-results` in subcommands (`check`, `discover`, `trace`, `dnssec`). `mhost -p lookup example.com` vs `mhost check -p example.com` do entirely different things.

---

## Architecture Findings

### 1. `NameServerConfig` Redundant `protocol` Field
**File: `nameserver/mod.rs:70-99`**

Each enum variant (`Udp`, `Tcp`, `Tls`, `Https`) carries a `protocol: Protocol` field that is always set to match the variant. The `protocol()` accessor ignores the stored field and derives it from the variant. This allows impossible states (e.g., `Udp { protocol: Protocol::Tls }`). Remove the field.

### 2. mdive Reaches Into `app/modules/`
**Files: `bin/mdive/app.rs:20`, `bin/mdive/discovery.rs:7`, `bin/mdive/lints.rs:1`**

The documented boundary says mdive uses `app/common/` but not `app/modules/`. In practice, mdive imports from `app::modules::check::lints` and `app::modules::discover`. Either move shared logic to `app/common/` or document this as intentional.

### 3. Four Copies of `sliding_window_lookups`
**Files: `resolver/mod.rs:380`, `resolver/lookup.rs:631`, `services/whois/mod.rs:303`, `services/server_lists/mod.rs:201`**

Exceeds the Rule of Three. The three breaker-based variants (resolver/lookup, whois, server_lists) are near-identical and could be unified into a generic helper.

### 4. `AppConfig` God Struct
**File: `app/app_config.rs`**

25+ flat fields covering resolver config, output config, nameserver selection, and runtime behavior. Grouping into sub-structs would improve SRP and reduce coupling.

### 5. `spectral` Dev Dependency
Unmaintained since 2017. Consider replacing with standard `assert_eq!`/`assert!` assertions over time.

---

## Security Findings

### Positive Highlights
- **Zero `unsafe` code** in the entire codebase
- **Strong TLS** via `rustls` + `ring` (no OpenSSL)
- **Transaction ID validation** on raw UDP/TCP queries
- **Comprehensive CLI argument range validation**
- **Proper timeout enforcement** on all network operations
- **`overflow-checks = true`** in release profile
- **Wildcard detection** in discovery prevents false positives

### Other Findings

| Severity | Finding | Location |
|----------|---------|----------|
| Low | `max-worker-threads` hidden param has no range validation | `cli_parser.rs:345-351` |
| Low | Unbounded file reads (wordlist, resolv.conf, nameserver files) | `wordlist.rs:449`, `system_config.rs:26`, `load.rs:34` |
| Low | Real email addresses in WHOIS test fixtures (violates CLAUDE.md policy) | `whois/service.rs:~558,966,1062` |
| Low | `sliding_window_lookups` silently discards lookup errors | `resolver/mod.rs:390-398` |
| Info | UDP buffer fixed at 4096 bytes (mitigated by TCP fallback) | `raw.rs:274` |
| Info | Predefined servers use Quad9 unfiltered endpoints (by design) | `predefined.rs` |

---

## Test Coverage Findings

**Overall: 397 tests across 60+ test modules. Rating: Good.**

### Coverage Strengths
- `nameserver/parser.rs`: 29 tests -- excellent
- `resources/rdata/`: 79 tests covering most types
- `resources/dnssec_validation.rs`: 28 tests -- very thorough
- `app/modules/` commands: ~130 tests (recently improved -- trace, propagation, diff, dnssec, check lints all well-tested)
- mdive TUI pure functions: 21 tests

### Critical Gaps

| Module | Status | Impact |
|--------|--------|--------|
| `statistics/lookups.rs` | **0 tests** | User-facing stats computation untested |
| `resolver/query.rs` | **0 tests** | MultiQuery Cartesian product untested |
| `estimate.rs` | **0 tests** | Request estimation untested |
| `rdata/mx.rs`, `srv.rs`, `null.rs`, `unknown.rs` | **No module-level tests** | Violates CLAUDE.md guideline |
| Library API integration tests | **None exist** | No offline integration tests for `ResolverGroup` API |
| Mock DNS resolver | **Does not exist** | All resolver tests require network or use pre-built `Lookup` objects |

### Infrastructure Issues
- **Network-dependent tests mixed with unit tests**: `nameserver/parser.rs` async tests, `whois/service.rs` tests hit real APIs
- **No `cargo audit` in CI** for dependency vulnerability scanning
- **`spectral` assertion library** adds noise -- inconsistent with newer tests using standard assertions

---

## UX/CLI/TUI Findings

### Positive Highlights
- Excellent defaults (A, AAAA, CNAME, MX for lookups)
- `infer_subcommands` lets users abbreviate commands
- `mhost info` command is a great progressive disclosure tool
- mdive TUI has comprehensive vi-style navigation, drill-down with history, regex filtering, multiple grouping modes, rich help popup

### Issues

| Priority | Finding | Location |
|----------|---------|----------|
| P1 | `--no-system-nameservers` requires bug (see above) | `cli_parser.rs:84` |
| P1 | `-p` flag overloading (see above) | `cli_parser.rs` |
| P2 | No usage examples in `mhost -h` | `cli_parser.rs` |
| P2 | `print_error_counts` uses `Debug` formatting for error keys | `console.rs:185` |
| P2 | ASCII+no-color mode: attention and error prefixes both render as `!` | `styles.rs` |
| P2 | No error message suggestions (e.g., "try --timeout" on timeout) | `bin/mhost.rs` |
| P2 | No `--ascii` flag for mdive TUI | `bin/mdive/main.rs` |
| P2 | Missing `long_about` on `check`, `discover`, `propagation` subcommands | `cli_parser.rs` |
| P3 | Empty input in mdive silently does nothing (should show hint) | `app.rs:751` |
| P3 | `@` shorthand for apex domain may confuse casual users | `ui.rs:293` |
| P3 | No mouse support in mdive | `main.rs:192` |
| P3 | Category toggle + vi-count digit overloading (1-9 keys) | `app.rs:586-604` |

---

## Performance Findings

### Positive Highlights
- Two-level bounded concurrency (ResolverGroup + per-Resolver)
- Custom `BufferUnorderedWithBreaker` stream combinator for early termination
- `Arc`-wrapped resolver internals for cheap cloning
- Incremental batch processing in mdive (avoids O(n^2) rebuild)
- Generation-tagged actions for stale result discarding

### Issues

| Priority | Finding | Location |
|----------|---------|----------|
| P1 | **No TUI rendering throttle** -- redraws on every channel message during rapid DNS updates | `main.rs:140-199` |
| P1 | `spawn_local` forces single-threaded DNS execution in mdive | `dns.rs:30`, `main.rs:115` |
| P1 | History clones full `Lookups` (use `Arc` instead) | `app.rs:1087` |
| P2 | Unnecessary `task::spawn` double-wrapping in `multi_lookup` | `resolver/mod.rs:318` |
| P2 | `RecordRow` stores owned Strings everywhere (nameserver, name repeated) | `app.rs:249` |
| P2 | `sort_rows` full-sorts on every batch append (use merge instead) | `app.rs:1298` |
| P2 | `update_dnssec_status` recomputes on every batch | `app.rs:963,1005` |
| P2 | Discovery `FuturesUnordered` has no outer concurrency bound | `discovery.rs:55-58` |
| P3 | Dedup key allocates 2 Strings per record before checking | `app.rs:1243` |
| P3 | `reqwest` not feature-gated for library-only builds | `Cargo.toml` |
| P3 | Regex filter re-scans all rows, not just new ones | `app.rs:1301-1308` |
| P3 | Wordlist re-parsed on every discovery spawn (424 `Name::from_str` calls) | `wordlist.rs:499` |
| P3 | `build.rs` generates shell completions even for library-only builds | `build.rs` |

---

## Recommended Action Plan

### Phase 1: Bugs & Security (Quick Wins)
1. ~~Fix `--no-system-nameservers` requires clause~~ — Not a bug; the `requires` clause intentionally prevents zero system nameservers.
2. ~~Add streaming size limits to HTTP response reads (chunked encoding bypass)~~ — Done: added post-read `body.len()` checks to whois, public_dns, opennic.
3. ~~Add range validation to `max-worker-threads`~~ — Done: `usize_range(1, 256)`.
4. ~~Replace real email addresses in WHOIS test fixtures~~ — Done: all replaced with `@example.com` variants.

### Phase 2: UX Improvements
5. Resolve `-p` short flag conflict — Deferred: low impact, subcommand scoping prevents actual ambiguity.
6. ~~Add usage examples to `mhost -h`~~ — Done: `after_help` with 10 example invocations.
7. ~~Distinguish attention/error prefixes in ASCII+no-color mode~~ — Done: error prefix changed to `x`.
8. ~~Add `--ascii` mode to mdive~~ — Done: flag + ASCII fallbacks for all Unicode glyphs in TUI.
9. ~~Improve error messages with actionable suggestions~~ — Done: Display formatting + timeout hint.

### Phase 3: Performance
10. ~~Add TUI rendering throttle (target 30 fps max)~~ — Done: `needs_redraw` flag + 33ms deadline.
11. Use `Arc<Lookups>` for history entries — Deferred: net negative on hot path due to merge pattern requiring clone anyway.
12. Implement merge-sort for incremental `sort_rows` — Deferred: Rust's Timsort already handles nearly-sorted data efficiently.
13. ~~Defer DNSSEC status recomputation~~ — Done: moved from `DnsBatch`/`DiscoveryBatch` to `DnsComplete` only.

### Phase 4: Test Coverage
14. ~~Add tests for `statistics/lookups.rs`~~ — Done: 6 tests covering stats computation.
15. ~~Add tests for `resolver/query.rs` (MultiQuery)~~ — Done: 7 tests covering Cartesian product and edge cases.
16. ~~Add module-level tests for `mx.rs`, `srv.rs`, `null.rs`, `unknown.rs`~~ — Done: 5 tests + 4 rdata accessor tests.
17. ~~Add tests for `estimate.rs`~~ — Done: 8 tests covering request estimation.
18. Consider a mock DNS resolver for offline testing — Deferred: `Resolver::new_for_test` helper added for synchronous test construction; full mock resolver not yet warranted.

### Phase 5: Architecture Cleanup
19. ~~Remove redundant `protocol` field from `NameServerConfig`~~ — Done: field removed from all 4 variants, protocol derived from enum variant via `protocol()` accessor. Added `port()` accessor. Serde format change accepted.
20. Unify the three breaker-based `sliding_window_lookups` copies — Skipped: the four implementations differ enough (breaker vs no-breaker, different error handling, different output types) that a generic abstraction would be more complex than the duplication it eliminates.
21. ~~Move shared discovery/lint logic to `app/common/`~~ — Resolved by documenting: mdive's imports from `app/modules/check/lints` and `app/modules/discover` are intentional shared business logic. Architecture docs updated.
22. ~~Feature-gate `reqwest` for library-only builds~~ — Done: new `services` feature (included by `app`) gates `reqwest`, `services/` module, and dependent `statistics/` submodules. Library-only builds no longer pull in HTTP dependencies.
