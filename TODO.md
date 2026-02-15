# TODO — mhost improvement roadmap

Work through these tasks in order, top to bottom. Each task is self-contained with context, relevant files, and acceptance criteria. Run `cargo test --lib` after each task to verify nothing breaks, and `cargo clippy` to check for warnings.

---

## 0. Global: IPv4-only / IPv6-only filtering

**Context**: mhost queries nameservers over both IPv4 and IPv6 by default. When a machine lacks IPv6 connectivity (common in many environments), queries to IPv6 addresses timeout, significantly slowing all commands — especially `trace`, `propagation`, and `discover` where many servers are queried in parallel. Glue records from DNS referrals include both A and AAAA addresses, and resolving NS names also returns both address families. Users need a way to restrict queries to a single address family.

**Files**:
- `src/app/cli_parser.rs` — add `--ipv4-only` (`-4`) and `--ipv6-only` (`-6`) global flags
- `src/app/app_config.rs` — add `AddressFamily` enum or `ipv4_only`/`ipv6_only` fields to `AppConfig`
- `src/resolver/mod.rs` — filter nameserver addresses by family when creating resolvers
- `src/resolver/raw.rs` — filter server addresses in `parallel_raw_queries()`
- `src/app/modules/trace/trace.rs` — filter glue IPs and resolved NS IPs by family
- `src/app/modules/propagation/` — filter predefined nameserver IPs by family
- `src/nameserver/predefined.rs` — may need to tag configs with address family

**Task**: Add global `--ipv4-only` (`-4`) and `--ipv6-only` (`-6`) flags that restrict DNS queries to a single address family. These flags should be mutually exclusive and affect all commands that make DNS queries.

**Acceptance criteria**:
- [x] `mhost -4 trace example.com` only queries IPv4 nameservers
- [x] `mhost -6 lookup example.com` only queries IPv6 nameservers
- [x] `-4` and `-6` are mutually exclusive (clap conflict)
- [x] Applies globally: trace, propagation, lookup, discover, check, domain-lookup, diff
- [x] Glue record filtering in trace respects the flag
- [x] Predefined nameserver filtering in propagation respects the flag
- [x] `cargo test --lib` passes
- [x] `cargo clippy` clean

---

## 1. Quick Wins

### 1.1 Expose shell completion installation command ✅

**Context**: `build.rs` already generates shell completions via `clap_complete` at compile time, but there is no CLI command or documented way for users to install them.

**Files**:
- `build.rs` — current completion generation
- `src/app/cli_parser.rs` — add a `completions` subcommand
- `src/app/modules/mod.rs` — register the new module

**Task**: Add a `completions` subcommand that prints shell completions to stdout for a given shell (bash, zsh, fish). Example usage: `mhost completions bash > /etc/bash_completion.d/mhost`.

**Acceptance criteria**:
- [x] `mhost completions bash` prints bash completions to stdout
- [x] `mhost completions zsh` and `mhost completions fish` work likewise
- [x] Shell argument uses `clap::ValueEnum` for the shell type
- [x] `cargo test --lib` passes
- [x] `cargo clippy` clean

---

### 1.2 Add zone transfer security lint ✅

**Context**: The `discover` module already attempts AXFR in `src/app/modules/discover/mod.rs:46` (`.axfr_attempt()`). The `check` module should flag successful AXFR as a security vulnerability.

**Files**:
- `src/app/modules/check/lints/mod.rs` — register new lint (currently 10 lints, lines 82-91)
- `src/app/modules/check/lints/` — add new `axfr.rs` lint file
- `src/app/modules/check/config.rs` — add `axfr` bool flag to `CheckConfig`
- `src/app/cli_parser.rs` — add `--no-axfr` flag to disable this lint

**Task**: Add a lint that attempts AXFR against each authoritative nameserver for the domain. If AXFR succeeds, emit `CheckResult::Failed` warning that zone transfer is publicly accessible. If it fails (expected), emit `CheckResult::Ok`.

**Acceptance criteria**:
- [x] New `axfr.rs` lint file in `src/app/modules/check/lints/`
- [x] Lint registered in the check pipeline (follows existing chain pattern)
- [x] `CheckResult::Failed` when AXFR succeeds from a public IP
- [x] `CheckResult::Ok` when AXFR is properly restricted
- [x] Unit tests for both outcomes
- [x] `cargo test --lib` passes

---

### 1.3 Add DNS diff command using existing `src/diff.rs` ✅

**Context**: `src/diff.rs` defines `Differ` and `SetDiffer` traits with implementations for MX, SOA, SRV, TXT, SPF, and UNKNOWN record types. These traits are tested but never exposed via the CLI.

**Files**:
- `src/diff.rs` — existing diff infrastructure (traits + `differ!` macro)
- `src/app/modules/` — add new `diff/` module
- `src/app/cli_parser.rs` — add `diff` subcommand
- `src/app/modules/mod.rs` — register the new module

**Task**: Add a `diff` subcommand that queries a domain's records from two different nameserver sets and shows differences. Example: `mhost diff example.com --nameserver 8.8.8.8 --nameserver 1.1.1.1`. Use the existing `Differ`/`SetDiffer` traits to compute and display differences.

**Acceptance criteria**:
- [x] `mhost diff example.com --left 8.8.8.8 --right 1.1.1.1` (or similar UX) shows record differences
- [x] Uses existing `Differ`/`SetDiffer` traits from `src/diff.rs`
- [x] Supports at least SOA, MX, TXT, SRV comparisons
- [x] Summary and JSON output supported
- [x] `cargo test --lib` passes

---

## 2. Additional lints for `check`

**Context**: The `check` command currently has 13 lints (SOA, NS, CNAME, MX, SPF, DMARC, CAA, TTL, DNSSEC, HTTPS/SVCB, AXFR, open resolver, delegation) in `src/app/modules/check/lints/`. Each lint is a struct that receives state from the previous lint in a chain pattern (see `dnssec_lint.rs:25` — `DnssecCheck.dnssec()` returns `HttpsSvcb`). The `CheckResults` struct in `lints/mod.rs` aggregates all results.

**Files**:
- `src/app/modules/check/lints/mod.rs` — `CheckResults` struct, lint module list
- `src/app/modules/check/lints/*.rs` — individual lint files
- `src/app/modules/check/config.rs` — `CheckConfig` with per-lint enable flags

**Task**: Add these lints, one at a time, following the existing chain pattern:

### 2.1 Open resolver detection lint ✅
- [x] New file `src/app/modules/check/lints/open_resolver.rs`
- [x] Query each authoritative NS with recursion desired (RD) flag for an external domain (e.g., `example.com`)
- [x] `CheckResult::Failed` if the server answers recursively (open resolver = amplification risk)
- [x] `CheckResult::Ok` if recursion is refused
- [x] Unit tests

### 2.2 Delegation consistency lint ✅
- [x] New file `src/app/modules/check/lints/delegation.rs`
- [x] Query parent zone for NS records, query child zone for NS records
- [x] `CheckResult::Failed` if parent and child NS sets disagree
- [x] `CheckResult::Ok` if they match
- [x] Unit tests

### 2.3 CNAME chain depth lint ✅
- [x] Add to existing `src/app/modules/check/lints/cnames.rs`
- [x] Follow CNAME chains, warn if depth > 3 or if circular reference detected
- [x] `CheckResult::Warning` for deep chains, `CheckResult::Failed` for circular
- [x] Unit tests

**Acceptance criteria**:
- [x] Each new lint integrates into the existing chain in `check/lints/mod.rs`
- [x] Each has a config flag in `CheckConfig` and a CLI `--no-X` disable flag
- [x] All existing tests still pass (`cargo test --lib`)

---

## 3. DNS propagation checking

**Context**: mhost already queries multiple nameservers concurrently via `ResolverGroup` and the predefined nameserver list (`src/nameserver/predefined.rs`) spans 6 providers across different networks. The infrastructure for parallel multi-server queries exists; what's missing is a presentation mode that highlights **divergence** between servers.

**Files**:
- `src/resolver/mod.rs` — `ResolverGroup`, `Resolver`
- `src/resolver/lookup.rs` — `Lookups` result type with per-resolver results
- `src/nameserver/predefined.rs` — 84 predefined nameservers across 6 providers
- `src/app/modules/` — add new `propagation/` module
- `src/app/cli_parser.rs` — add `propagation` subcommand

**Task**: Add a `propagation` (alias: `prop`) subcommand that queries a domain's records across all predefined nameservers (or a specified set) and reports which servers return which answers, highlighting inconsistencies. Think: "has my DNS change propagated everywhere yet?"

**Acceptance criteria**:
- [x] `mhost propagation example.com A` queries predefined nameservers and shows per-server results
- [x] Clearly highlights servers that return different answers (divergence)
- [x] Groups servers by response to show propagation percentage
- [x] Summary output shows a table: server name | provider | response | matches majority?
- [x] JSON output includes full per-server breakdown
- [x] `cargo test --lib` passes

---

## 4. `mhost trace` command

**Context**: mhost currently sends queries directly to recursive resolvers. It has no iterative resolution mode that traces the delegation path from root servers → TLD → authoritative, similar to `dig +trace`. The `Resolver` in `src/resolver/mod.rs` wraps `hickory_resolver` which supports configuring as a non-recursive resolver.

**Files**:
- `src/resolver/mod.rs` — `Resolver`, `ResolverConfig`, `ResolverOpts`
- `src/resolver/lookup.rs` — `Lookup`, `Lookups`
- `src/app/modules/` — add new `trace/` module
- `src/app/cli_parser.rs` — add `trace` subcommand

**Task**: Add a `trace` (alias: `t`) subcommand that performs iterative resolution from root to authoritative and displays each hop. For each delegation step, show: hop number, server queried, response (NS referral or final answer), and response time.

**Acceptance criteria**:
- [ ] `mhost trace example.com A` shows delegation path from root to answer
- [ ] Each hop displays: nameserver queried, response type (referral/answer), latency
- [ ] Works for at least A, AAAA, MX, NS, CNAME record types
- [ ] Summary output shows a clear step-by-step delegation chain
- [ ] JSON output includes structured hop data
- [ ] Handles CNAME chains in the trace (follow the chain)
- [ ] `cargo test --lib` passes

---

## 5. Refactor `RecordType::DNSSEC` into individual types

**Context**: `src/resources/record_type.rs:45` has a TODO comment: `// TODO: DNSSEC(DNSSECRecordType)`. Currently all DNSSEC record types (DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM, KEY, SIG) collapse into a single `RecordType::DNSSEC` variant. The corresponding rdata type `DNSSEC` in `src/resources/rdata/mod.rs` stores the sub-type as a string.

**Files**:
- `src/resources/record_type.rs` — `RecordType` enum, `FromStr`, `Display`, `all()`, conversions
- `src/resources/rdata/mod.rs` — `RData` enum, accessor methods
- `src/resolver/lookup.rs` — `Lookups` accessor `.dnssec()` and any per-type accessors
- `src/app/modules/check/lints/dnssec_lint.rs` — uses `DNSSEC` rdata type, checks `sub_type()` strings
- `src/app/output/summary/` — display formatting for DNSSEC records

**Task**: Replace `RecordType::DNSSEC` with individual variants: `DNSKEY`, `DS`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`. Create corresponding rdata structs (or at minimum a typed enum `DNSSECRecordType`) so that each type can be queried and filtered independently.

**Acceptance criteria**:
- [ ] `RecordType` has individual variants: `DNSKEY`, `DS`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`
- [ ] `RecordType::from_str("DNSKEY")` etc. all work
- [ ] `RecordType::all()` includes the new variants
- [ ] `display_round_trip` test passes for all new variants
- [ ] `Lookups` has `.dnskey()`, `.ds()`, `.rrsig()` etc. accessors (or at minimum type-filtered access)
- [ ] Existing DNSSEC lint still works (updated to use typed variants instead of string matching)
- [ ] Old `RecordType::DNSSEC` is removed (no backward compat shim)
- [ ] `cargo test --lib` passes
- [ ] `cargo clippy` clean

---

## 6. DNSSEC chain validation

**Context**: After task 5, individual DNSSEC record types are available. The current DNSSEC lint (`src/app/modules/check/lints/dnssec_lint.rs`) only checks **presence** of DNSKEY and RRSIG records (lines 60-92). It does not validate the cryptographic chain: DS (from parent) → DNSKEY (in zone) → RRSIG (signatures on records).

**Files**:
- `src/app/modules/check/lints/dnssec_lint.rs` — expand this lint
- `src/resources/rdata/` — may need new rdata parsers for DNSKEY fields (algorithm, key tag, public key)
- `Cargo.toml` — may need a crypto dependency (e.g., `ring`) for signature verification

**Task**: Extend the DNSSEC lint to perform actual chain validation:
1. Query parent zone for DS record
2. Query zone for DNSKEY records
3. Verify DS record matches a DNSKEY (key tag + digest)
4. Verify RRSIG signatures are valid against the DNSKEY
5. Check signature expiration dates

**Acceptance criteria**:
- [ ] Lint validates DS → DNSKEY binding (key tag and digest match)
- [ ] Lint checks RRSIG expiration (warn if expiring within 7 days, fail if expired)
- [ ] Lint checks DNSKEY algorithm strength (warn on weak algorithms like RSAMD5)
- [ ] `CheckResult::Ok` when full chain validates
- [ ] `CheckResult::Failed` when chain is broken
- [ ] `CheckResult::Warning` for weak algorithms or near-expiry signatures
- [ ] Unit tests with known-good and known-bad DNSSEC data
- [ ] `cargo test --lib` passes

---

## 7. Library API polish

**Context**: `src/lib.rs` lines 10-19 acknowledge the library "totally lacks documentation" and the "API might change." The current API requires manual construction: create `NameServerConfig`, wrap in `ResolverConfig`, create `Resolver`, add to `ResolverGroup`. There is no builder pattern or convenience constructors for common cases.

**Files**:
- `src/lib.rs` — top-level docs and re-exports
- `src/resolver/mod.rs` — `ResolverGroup`, `Resolver`, `ResolverConfig`, `ResolverOpts`
- `src/nameserver/mod.rs` — `NameServerConfig`
- `src/nameserver/predefined.rs` — predefined nameserver configurations
- `src/resolver/predefined.rs` — predefined resolver group creation
- `src/error.rs` — `Error` type

**Task**: Improve the library API in these steps:

### 7.1 Builder pattern for `ResolverGroup`
- [ ] Add `ResolverGroupBuilder` with fluent API
- [ ] `.system()` — add OS resolvers
- [ ] `.predefined(name)` — add a predefined provider (e.g., `"google"`, `"cloudflare"`)
- [ ] `.nameserver(config)` — add a custom nameserver
- [ ] `.timeout(duration)` / `.retries(n)` — configure options
- [ ] `.build()` — async, returns `Result<ResolverGroup>`
- [ ] Update `lib.rs` doc example to use the builder

### 7.2 Richer error types
- [ ] Add error variants to distinguish: `Error::Timeout`, `Error::NxDomain`, `Error::Refused`, `Error::ServerFailure`
- [ ] Existing `src/resolver/error.rs` wraps hickory errors — map them to these categories
- [ ] Preserve existing error API (add new variants, don't break existing ones)

### 7.3 Documentation
- [ ] Add module-level `//!` docs for `resolver`, `nameserver`, `resources`
- [ ] Add doc comments on all public types and their key methods
- [ ] Update `lib.rs` crate-level docs to remove the "PoC" / "lacks documentation" disclaimers
- [ ] `cargo doc --no-deps` builds without warnings

**Acceptance criteria**:
- [ ] `ResolverGroupBuilder` works as described above
- [ ] Error types distinguish timeout/nxdomain/refused/servfail
- [ ] `cargo doc --no-deps` clean
- [ ] `cargo test --lib` passes
- [ ] `cargo clippy` clean
