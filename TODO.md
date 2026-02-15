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

### 7. DNSSEC trust chain visualization

**Context**: After tasks 5+6, mhost can validate the DNSSEC chain cryptographically. This task adds a visual representation of the trust chain in the terminal, making DNSSEC debugging accessible and intuitive. No existing CLI tool does this well.

**Task**: Add a `--visualize` flag to the DNSSEC check lint (or a standalone `mhost dnssec` subcommand) that renders the full trust chain:
1. Query root → TLD → zone for DS, DNSKEY, and RRSIG records at each level
2. Render a tree showing: root KSK → TLD DS → TLD DNSKEY → zone DS → zone DNSKEY → RRSIG
3. Color-code each link: green for valid, red for broken, yellow for warnings (weak algo, near-expiry)
4. Show key tags, algorithms, and expiration dates inline

**Acceptance criteria**:
- [ ] Renders a delegation-level trust chain from root to target zone
- [ ] Each node shows: record type, key tag, algorithm name, validity status
- [ ] Color-coded: green (valid), red (broken/expired), yellow (weak algo or expiring within 7 days)
- [ ] Works with `--ascii` flag (no Unicode box-drawing)
- [ ] JSON output includes structured chain data
- [ ] `cargo test --lib` passes
- [ ] `cargo clippy` clean

---

## Next Phase

### 8. DNS snapshot and timeline diff

**Context**: The existing `diff` command compares records between two nameserver sets at a single point in time. This task adds the ability to snapshot a domain's full DNS profile to disk and later diff against it, enabling before/after validation for DNS migrations, provider switches, or change tracking.

**Task**: Add snapshot and timeline diff capabilities:
1. `mhost snapshot example.com` — save a full DNS profile (all record types, all nameservers) to a JSON file with timestamp
2. `mhost snapshot example.com --output before.json` — save to a specific file
3. `mhost diff --snapshot before.json example.com` — compare saved snapshot against current live DNS state
4. `mhost diff --snapshot before.json --snapshot after.json` — compare two snapshots offline

**Files**:
- New `src/app/modules/snapshot/` module for snapshot creation and serialization
- Extend `src/app/modules/diff/` to accept snapshot files as input
- Reuse existing `Differ`/`SetDiffer` traits from `src/diff.rs`

**Acceptance criteria**:
- [ ] `mhost snapshot example.com` writes a timestamped JSON file with all record types and per-server results
- [ ] Snapshot file includes metadata: domain, timestamp, nameservers used, mhost version
- [ ] `mhost diff --snapshot <file>` compares snapshot against live DNS and shows added/removed/changed records
- [ ] `mhost diff --snapshot <file1> --snapshot <file2>` compares two snapshots offline
- [ ] Summary output highlights changes with clear before/after values
- [ ] JSON output includes structured diff data
- [ ] `cargo test --lib` passes
- [ ] `cargo clippy` clean


### 9. DNS monitoring / watch mode

**Context**: During DNS migrations, TTL changes, or incident response, operators need to continuously monitor DNS state and be alerted to changes. Currently this requires scripting around `mhost lookup` in a loop. A built-in watch mode would be far more ergonomic and powerful.

**Task**: Add a `watch` subcommand (or `--watch` flag on `lookup`/`propagation`) that continuously polls DNS and reports changes:
1. `mhost watch example.com A --interval 30s` — poll every 30 seconds, print only when records change
2. `mhost watch example.com --all --interval 1m` — watch all record types
3. Show timestamp and delta for each change (record added/removed/modified, TTL change, SOA serial bump)
4. Optional `--exit-on-change` for scripting (exit 0 on first detected change)

**Acceptance criteria**:
- [ ] `mhost watch example.com A` polls at a configurable interval (default: 60s)
- [ ] Only prints output when records change (suppresses identical results)
- [ ] Shows timestamp and clear change description (added, removed, modified)
- [ ] Detects SOA serial changes
- [ ] `--exit-on-change` exits with code 0 on first change (useful for scripting)
- [ ] `--interval` accepts humantime durations (e.g., `30s`, `5m`)
- [ ] JSON output includes change events with timestamps
- [ ] Ctrl+C exits cleanly
- [ ] `cargo test --lib` passes
- [ ] `cargo clippy` clean

---

### 10. Resolver response time benchmarking

**Context**: Choosing a DNS resolver often comes down to latency. While mhost already reports per-server latency in `trace` and `propagation`, there is no dedicated benchmarking mode that provides statistical analysis over many rounds. This fills a gap — existing tools like `dnsperf` are complex and server-focused.

**Task**: Add a `bench` subcommand for resolver performance benchmarking:
1. `mhost bench example.com --rounds 100` — query a domain N times across configured resolvers
2. Report per-resolver statistics: min, max, mean, median, p95, p99, stddev
3. `mhost bench example.com --resolvers 8.8.8.8,1.1.1.1 --rounds 50` — compare specific resolvers head-to-head
4. Summary output as a sorted table (fastest to slowest)

**Acceptance criteria**:
- [ ] `mhost bench example.com` runs configurable rounds (default: 50, range: 1-1000)
- [ ] Reports per-resolver: min, max, mean, median, p95, p99, stddev
- [ ] Summary output shows a sorted table (fastest resolver first)
- [ ] Supports `--record-type` flag (default: A)
- [ ] Supports all resolver specification methods (IP, predefined, system)
- [ ] JSON output includes full per-round timing data
- [ ] `cargo test --lib` passes
- [ ] `cargo clippy` clean

---

### 11. Export DNS records to infrastructure formats

**Context**: After discovering or looking up DNS records, operators often need to recreate them in a different provider or infrastructure-as-code tool. Manually transcribing records is tedious and error-prone. mhost already has all the data — it just needs output formatters.

**Task**: Add export capabilities to `lookup` and `domain-lookup`:
1. `mhost lookup example.com --export zone` — export as RFC 1035 zone file format
2. `mhost lookup example.com --export terraform` — export as Terraform `aws_route53_record` resources (or generic `dns_*_record_set`)
3. `mhost lookup example.com --export cloudflare` — export as Cloudflare API JSON payloads

**Files**:
- New `src/app/output/export/` module with per-format exporters
- Extend `OutputConfig` to support export formats alongside summary/JSON

**Acceptance criteria**:
- [ ] `--export zone` produces valid RFC 1035 zone file syntax
- [ ] `--export terraform` produces valid HCL for `dns_*_record_set` resources
- [ ] Handles all major record types: A, AAAA, CNAME, MX, TXT, SRV, CAA, NS, SOA
- [ ] Export works with both `lookup` and `domain-lookup` commands
- [ ] `cargo test --lib` passes
- [ ] `cargo clippy` clean

---

## Future Work

Ideas for longer-term consideration. These are not prioritized and may require significant design work.

### Interactive TUI mode

A terminal UI (using `ratatui` or similar) for exploring DNS interactively: type a domain, see records update live, drill into subdomains, navigate the delegation tree visually. Would set mhost apart from every other DNS CLI tool. Large scope — may warrant its own crate/binary built on the mhost library.

---

### DNS-over-QUIC (DoQ) support

DNS-over-QUIC (RFC 9250) is the next evolution of encrypted DNS transport. Hickory-dns has preliminary DoQ support. Adding DoQ as a transport option alongside UDP/TCP/DoT/DoH would future-proof mhost. Requires evaluating hickory-dns DoQ maturity and adding a new `NameServerConfig::Quic` variant.

---

### Zone file import and pre-deployment validation

Parse BIND-style zone files and validate them with the existing 13 check lints *before* deploying. Shift-left DNS validation: `mhost check --zone-file db.example.com` catches misconfigurations before they go live. Requires a zone file parser (potentially via hickory-dns zone file parsing) and adapting the lint pipeline to work against static data instead of live queries.

---

### Configuration profiles

Add `~/.config/mhost/profiles.toml` with named resolver sets, default options, and per-domain overrides. Power users managing dozens of domains have different resolver needs per context (internal vs external, staging vs production). Example: `mhost --profile internal lookup service.corp.example.com` uses corporate resolvers while `mhost --profile external` uses public ones.

---

### Geolocation-aware propagation

Enhance the `propagation` command to show results grouped by geographic region (Americas, Europe, Asia-Pacific). The predefined providers already span multiple regions. Adding region metadata to provider configs would enable output like "Propagated: 100% Americas, 83% Europe, 67% Asia-Pacific". Could integrate with IP geolocation databases or simply use static provider metadata.

---

### DNS response explainer

`mhost explain` — paste or pipe a raw DNS wire-format response, dig output, or packet capture and get a plain-English explanation. "Here's what this response means, here's what's unusual about it, here's what to check next." Useful for learning and debugging. Could also explain common DNS error scenarios (SERVFAIL, NXDOMAIN, truncation, etc.) with contextual guidance.

---

### Progress indicators for long operations

The `discover` command with CT logs + wordlist + recursive depth can take a while. Add richer progress reporting: current strategy name, discovered count so far, elapsed time, and estimated completion. Could use `indicatif` for progress bars. The `--partial` flag already exists for incremental output, but a proper progress bar would be more informative for interactive use.

---

### 7.2 Richer error types ✅

Already implemented. `src/resolver/error.rs` has semantic variants: `Timeout`, `QueryRefused`, `ServerFailure`, `NoRecordsFound`, `CancelledError`, plus `From<ResolveError>` and `From<ProtoError>` conversions that map hickory errors to these categories.

---

### 7.3 Documentation ✅

All key modules (`lib.rs`, `resolver/mod.rs`, `nameserver/mod.rs`, `resources/mod.rs`, `resolver/error.rs`, `resolver/lookup.rs`, `resolver/query.rs`, `resolver/builder.rs`) have `//!` module-level docs. All major public types have doc comments. `lib.rs` has full crate-level docs with builder and manual construction examples, no "PoC" disclaimers. `cargo doc --no-deps` builds with zero warnings.
