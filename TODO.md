# TODO — mhost improvement roadmap

Work through these tasks in order, top to bottom. Each task is self-contained with context, relevant files, and acceptance criteria. Run `cargo test --lib` after each task to verify nothing breaks, and `cargo clippy` to check for warnings.

---

## Completed

<details>
<summary>0. Global: IPv4-only / IPv6-only filtering ✅ (v0.6.0)</summary>

Added global `--ipv4-only` (`-4`) and `--ipv6-only` (`-6`) flags. Mutually exclusive, affects all commands. Trace command defaults to dual-stack root servers (IPv4+IPv6) when neither flag is set.

- [x] `mhost -4 trace example.com` only queries IPv4 nameservers
- [x] `mhost -6 lookup example.com` only queries IPv6 nameservers
- [x] `-4` and `-6` are mutually exclusive (clap conflict)
- [x] Applies globally: trace, propagation, lookup, discover, check, domain-lookup, diff
- [x] Glue record filtering in trace respects the flag
- [x] Predefined nameserver filtering in propagation respects the flag
- [x] `cargo test --lib` passes
- [x] `cargo clippy` clean
</details>

<details>
<summary>1.1 Expose shell completion installation command ✅ (v0.6.0)</summary>

Added hidden `completions` subcommand that prints shell completions to stdout.

- [x] `mhost completions bash` prints bash completions to stdout
- [x] `mhost completions zsh` and `mhost completions fish` work likewise
- [x] Shell argument uses `clap::ValueEnum` for the shell type
- [x] `cargo test --lib` passes
- [x] `cargo clippy` clean
</details>

<details>
<summary>1.2 Add zone transfer security lint ✅ (v0.6.0)</summary>

Added AXFR lint to check command that flags publicly accessible zone transfers.

- [x] New `axfr.rs` lint file in `src/app/modules/check/lints/`
- [x] Lint registered in the check pipeline (follows existing chain pattern)
- [x] `CheckResult::Failed` when AXFR succeeds from a public IP
- [x] `CheckResult::Ok` when AXFR is properly restricted
- [x] Unit tests for both outcomes
- [x] `cargo test --lib` passes
</details>

<details>
<summary>1.3 Add DNS diff command ✅ (v0.6.0)</summary>

Added `diff` subcommand comparing DNS records between two nameserver sets.

- [x] `mhost diff example.com --left 8.8.8.8 --right 1.1.1.1` shows record differences
- [x] Uses existing `Differ`/`SetDiffer` traits from `src/diff.rs`
- [x] Supports at least SOA, MX, TXT, SRV comparisons
- [x] Summary and JSON output supported
- [x] `cargo test --lib` passes
</details>

<details>
<summary>2.1 Open resolver detection lint ✅ (v0.6.0)</summary>

- [x] New file `src/app/modules/check/lints/open_resolver.rs`
- [x] Query each authoritative NS with recursion desired (RD) flag for an external domain
- [x] `CheckResult::Failed` if the server answers recursively
- [x] `CheckResult::Ok` if recursion is refused
- [x] Unit tests
</details>

<details>
<summary>2.2 Delegation consistency lint ✅ (v0.6.0)</summary>

- [x] New file `src/app/modules/check/lints/delegation.rs`
- [x] Query parent zone for NS records, query child zone for NS records
- [x] `CheckResult::Failed` if parent and child NS sets disagree
- [x] `CheckResult::Ok` if they match
- [x] Unit tests
</details>

<details>
<summary>2.3 CNAME chain depth lint ✅ (v0.6.0)</summary>

- [x] Add to existing `src/app/modules/check/lints/cnames.rs`
- [x] Follow CNAME chains, warn if depth > 3 or if circular reference detected
- [x] `CheckResult::Warning` for deep chains, `CheckResult::Failed` for circular
- [x] Unit tests
</details>

<details>
<summary>3. DNS propagation checking ✅ (v0.6.0)</summary>

Added `propagation` (alias: `prop`) subcommand with SOA-serial-based detection.

- [x] `mhost propagation example.com A` queries predefined nameservers and shows per-server results
- [x] Clearly highlights servers that return different answers (divergence)
- [x] Groups servers by response to show propagation percentage
- [x] Summary output shows a table: server name | provider | response | matches majority?
- [x] JSON output includes full per-server breakdown
- [x] `cargo test --lib` passes
</details>

<details>
<summary>4. mhost trace command ✅ (v0.6.0)</summary>

Added `trace` (alias: `t`) subcommand with parallel iterative resolution. Queries all nameservers at each delegation level, detects referral divergence, reports per-server latency. Defaults to dual-stack root servers.

- [x] `mhost trace example.com A` shows delegation path from root to answer
- [x] Each hop displays: nameserver queried, response type (referral/answer), latency
- [x] Works for all record types via `-t` flag
- [x] Summary output shows a clear step-by-step delegation chain
- [x] JSON output includes structured hop data
- [x] `cargo test --lib` passes
</details>

<details>
<summary>7.1 Builder pattern for ResolverGroup ✅ (v0.6.0)</summary>

Added `ResolverGroupBuilder` with fluent API and `PredefinedProvider` enum.

- [x] `.system()` — add OS resolvers
- [x] `.predefined(provider)` — add a predefined provider (e.g., `PredefinedProvider::Google`)
- [x] `.nameserver(config)` / `.nameservers(configs)` — add custom nameservers
- [x] `.timeout(duration)` / `.retries(n)` — configure options
- [x] `.build()` — async, returns `Result<ResolverGroup>`
- [x] Updated `lib.rs` doc example to use the builder
</details>

---

## Remaining

### 5. Refactor `RecordType::DNSSEC` into individual types

**Context**: `src/resources/record_type.rs:49` has a TODO comment: `// TODO: DNSSEC(DNSSECRecordType)`. Currently all DNSSEC record types (DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM, KEY, SIG) collapse into a single `RecordType::DNSSEC` variant. The corresponding rdata type `DNSSEC` in `src/resources/rdata/mod.rs` stores the sub-type as a string.

**Files**:
- `src/resources/record_type.rs` — `RecordType` enum, `FromStr`, `Display`, `all()`, conversions
- `src/resources/rdata/mod.rs` — `RData` enum, accessor methods
- `src/resolver/lookup.rs` — `Lookups` accessor `.dnssec()` and any per-type accessors
- `src/app/modules/check/lints/dnssec_lint.rs` — uses `DNSSEC` rdata type, checks `sub_type()` strings
- `src/app/output/records.rs` — display formatting for DNSSEC records

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

### 6. DNSSEC chain validation

**Context**: After task 5, individual DNSSEC record types are available. The current DNSSEC lint (`src/app/modules/check/lints/dnssec_lint.rs`) only checks **presence** of DNSKEY and RRSIG records. It does not validate the cryptographic chain: DS (from parent) → DNSKEY (in zone) → RRSIG (signatures on records).

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

### 7.2 Richer error types ✅

Already implemented. `src/resolver/error.rs` has semantic variants: `Timeout`, `QueryRefused`, `ServerFailure`, `NoRecordsFound`, `CancelledError`, plus `From<ResolveError>` and `From<ProtoError>` conversions that map hickory errors to these categories.

---

### 7.3 Documentation ✅

All key modules (`lib.rs`, `resolver/mod.rs`, `nameserver/mod.rs`, `resources/mod.rs`, `resolver/error.rs`, `resolver/lookup.rs`, `resolver/query.rs`, `resolver/builder.rs`) have `//!` module-level docs. All major public types have doc comments. `lib.rs` has full crate-level docs with builder and manual construction examples, no "PoC" disclaimers. `cargo doc --no-deps` builds with zero warnings.
