# Software Design Document: `verify` Command

**Feature**: DNS Zone File Verification — compare a source-of-truth zone file against live DNS
**Status**: Proposal
**Date**: 2026-02-16

---

## 1. Motivation

There is no good tool that answers the question: *"Does live DNS match what my zone file says it should be?"*

Tools like `dig` verify one record at a time manually. IaC tools like Terraform only check state they manage. Nobody stitches the two worlds together well. mhost is uniquely positioned to fill this gap — it already does concurrent multi-server lookups, record comparison, and structured output. Adding zone file verification turns mhost into a **DNS drift detection** tool, useful for:

- **Post-deployment validation**: After pushing zone changes, verify they propagated correctly.
- **Migration audits**: Before or after migrating DNS providers, confirm nothing was lost.
- **CI/CD integration**: Automated checks that DNS reality matches the checked-in zone file.
- **Ongoing monitoring**: Periodic verification that no unauthorized changes have been made.

## 2. Core Concept

Read a BIND zone file, extract expected records, perform live DNS lookups for each unique (name, type) pair, and report mismatches between expected and actual.

```
Zone file (source of truth)
  --> Parse into structured records
  --> For each unique (name, type): query live DNS
  --> Compare expected vs. actual
  --> Report: matches, mismatches, missing, extra
```

## 3. Placement: Part of `mhost`, Not a Separate Binary

The `verify` command belongs in the `mhost` binary as a new subcommand. Rationale:

- **Same interaction model.** `mhost` is a CLI that takes a command, does DNS work, and prints results. `verify` fits that pattern — it is a run-and-done operation, unlike `mdive` which requires a persistent TUI with raw terminal mode.
- **Natural neighbor to existing commands.** It completes a logical progression:

  | Command    | Question it answers                |
  |------------|------------------------------------|
  | `lookup`   | "What records exist?"              |
  | `check`    | "Are the records configured well?" |
  | `diff`     | "Do two sources agree?"            |
  | **`verify`** | **"Does reality match my intent?"** |

- **Precedent.** `diff` already supports `--left-from-file` / `--right-from-file` for JSON snapshots. `verify` extends that idea to zone files as the "expected" side.
- **Round-trip workflow.** Keeping everything in one binary enables natural workflows:

  ```sh
  mhost domain-lookup example.com --format zone > expected.zone
  # time passes, things change
  mhost verify expected.zone
  ```

## 4. Zone File Parsing

### 4.1 Approach: Use `hickory-proto` with `text-parsing` Feature

The `hickory-proto` crate (already in the dependency tree via `hickory-resolver` 0.25.2) includes a full RFC 1035 zone file parser behind the `text-parsing` feature flag.

**API:**

```rust
use hickory_proto::serialize::txt::Parser;

let content = std::fs::read_to_string(zone_path)?;
let (origin, records) = Parser::new(content, Some(zone_path), Some(origin)).parse()?;
// origin: Name
// records: BTreeMap<RrKey, RecordSet>
```

**Supported zone file features:**
- `$ORIGIN`, `$TTL`, `$INCLUDE` directives (nesting up to 256 levels)
- `@` shorthand for current origin
- Parenthesized multi-line records
- Comments (`;`)
- Escape sequences (octal `\DDD` and character `\X`)
- RFC 2308 TTL strings (`1w2d3h4m5s`)

**Record type coverage:**
A, AAAA, ANAME, CAA, CNAME, HINFO, HTTPS, MX, NAPTR, NS, OPENPGPKEY, SOA, SRV, SSHFP, SVCB, TLSA, TXT — every type mhost supports.

### 4.2 Why This Approach

| Option | Verdict |
|--------|---------|
| **hickory-proto `text-parsing`** | **Use this.** Zero new deps, types already convert, battle-tested (used by hickory-server). |
| `zoneparser` crate | Returns raw strings for rdata, not structured. Would require re-parsing everything. |
| NLnetLabs `domain` crate | Introduces a second DNS type system requiring new conversion code for every record type. |
| Write a custom parser | 17+ rdata parsers to write, RFC 1035 edge cases to handle. All already solved in hickory. |

### 4.3 Dependency Change

In `Cargo.toml`, add `hickory-proto` as a direct dependency with the `text-parsing` feature:

```toml
hickory-proto = { version = "0.25", features = ["text-parsing"] }
```

This adds **zero new crate downloads**. `hickory-proto` 0.25.2 is already in `Cargo.lock`. The `text-parsing` feature only requires `std` (already enabled), so it compiles additional modules within the existing crate.

### 4.4 Type Conversion: Already Done

mhost already has complete `From` conversions between hickory-proto types and its own types:

- `From<&hickory_proto::rr::Record> for mhost::Record` (`src/resources/record.rs:109-118`)
- `From<hickory_proto::rr::RData> for mhost::RData` (`src/resources/rdata/mod.rs:323-484`) — handles every variant
- `From<hickory_proto::rr::RecordType> for mhost::RecordType` (`src/resources/record_type.rs:137-176`) — bidirectional

The integration path is:

```
Zone file (string)
  --> hickory_proto::serialize::txt::Parser::parse()
  --> BTreeMap<RrKey, RecordSet>       (hickory types)
  --> iterate RecordSets, call existing From impls
  --> Vec<mhost::Record>               (mhost types)
```

No new conversion code is needed.

## 5. Architecture

### 5.1 Module Layout

```
src/
  resources/
    zone.rs                          # NEW: Zone file parsing, returns Vec<mhost::Record>
                                     #   Library-level code, no app dependency

  app/modules/
    verify/
      mod.rs                         # NEW: Command orchestration
      comparison.rs                  # NEW: Expected vs. actual record comparison

  app/output/summary/
    verify.rs                        # NEW: SummaryFormatter for verification results
```

### 5.2 Library Layer: `src/resources/zone.rs`

The zone parser belongs in the library (not `app/`) because it is a general-purpose capability usable by any consumer of the mhost library.

Responsibilities:
- Read and parse a BIND zone file via `hickory_proto::serialize::txt::Parser`
- Convert hickory types to mhost types using existing `From` impls
- Return a `Zone` struct containing the origin name and a `Vec<Record>`
- Handle parse errors with clear diagnostics (file path, line info from hickory's `ParseError`)

### 5.3 App Layer: `src/app/modules/verify/`

The verification command module follows the same pattern as every other mhost command module.

**Orchestration (`mod.rs`):**
1. Read zone file from the path argument
2. Parse into `Vec<mhost::Record>` via the library zone parser
3. Extract unique (name, record_type) pairs from the expected records
4. Build queries and execute live DNS lookups (reusing `ResolverGroup`)
5. Pass expected and actual records to the comparison engine
6. Format and output results

**Comparison (`comparison.rs`):**
- For each (name, type) pair in the expected set:
  - **Match**: all expected records found in live DNS
  - **Missing**: expected record not present in live response
  - **Mismatch**: record exists but rdata differs (e.g., wrong IP for an A record)
  - **TTL drift**: rdata matches but TTL differs (only in strict mode)
- For records in live DNS not present in the expected set:
  - **Extra**: unexpected record found (informational, since zone files may be partial)

Result struct:

```rust
struct VerifyResults {
    zone_file: String,
    origin: String,
    matches: Vec<Record>,         // expected and found in live DNS
    missing: Vec<Record>,         // expected but not in live DNS
    extra: Vec<Record>,           // in live DNS but not in zone file (empty when --ignore-extra)
    ttl_drifts: Vec<TtlDrift>,   // only populated in --strict mode
    skipped_wildcards: Vec<Record>, // wildcard records skipped (not verifiable via simple lookup)
    soa_check: Option<SoaCheck>,  // SOA serial comparison (None when --ignore-soa)
}

struct SoaCheck {
    expected_serial: u32,
    actual_serial: Option<u32>,   // None if live SOA lookup failed/absent
    match_: bool,
}
```

### 5.4 Output

Follows the existing `OutputConfig` pattern:
- **Summary (human-readable)**: Table showing matches/mismatches with colored status indicators using existing `styles.rs` prefixes (`ok_prefix()`, `attention_prefix()`, `error_prefix()`)
- **JSON**: Full `Serialize` output of `VerifyResults` for machine consumption

## 6. CLI Interface

```
mhost verify <ZONE_FILE> [OPTIONS]
```

**Arguments:**
- `<ZONE_FILE>` — Path to BIND zone file (required)

**Options:**
- `--origin <NAME>` — Override zone origin (default: derived from SOA in zone file)
- `--strict` — Enable strict mode: TTL differences count as mismatches
- `--only-type <TYPE>` — Only verify records of this type (repeatable, comma-delimited; mutually exclusive with `--ignore-type`)
- `--ignore-type <TYPE>` — Skip records of this type (repeatable, comma-delimited; mutually exclusive with `--only-type`)
- `--ignore-extra` — Do not report records found in live DNS but missing from zone file
- `--ignore-soa` — Skip SOA serial comparison
- Standard mhost options: `--server`, `--predefined`, `--timeout`, `--json`, `--no-color`, etc.

**Alias:** `v` (following the pattern of `l`, `d`, `c` for other commands)

**Exit codes:**
- `0` — All expected records verified successfully
- `1` — One or more mismatches or missing records detected
- `2` — Zone file parse error
- `3+` — Other errors (network, resolver setup, etc.)

Non-zero exit on mismatch makes this directly usable in CI pipelines:

```sh
mhost verify zones/example.com.zone --server ns1.example.com || notify_team "DNS drift detected"
```

## 7. Design Decisions

### 7.1 Which Nameservers to Query

Two distinct use cases:

1. **Authoritative verification** — query the zone's own nameservers (extracted from NS records or specified via `--server`). Answers: "Did my zone file deploy correctly?"
2. **Propagation verification** — query public resolvers (`--predefined`). Answers: "Can the world see my changes?"

Default behavior: use system resolvers (same as other mhost commands). Users can override with `--server` for authoritative checks or `--predefined` for propagation checks.

### 7.2 TTL Handling

TTLs from zone files are authoritative values. TTLs observed via caching resolvers will be lower (counting down toward expiry). Therefore:

- **Default mode**: Ignore TTL differences. Compare only (name, type, rdata).
- **Strict mode** (`--strict`): Report TTL differences. Only meaningful when querying authoritative nameservers directly.

This aligns with mhost's existing `Record` equality semantics — `PartialEq` and `Hash` already ignore TTL (`src/resources/record.rs:29-42`).

### 7.3 Partial Zone Files

A zone file for `example.com` may contain the complete zone, but live DNS may also return records from delegated subzones, synthesized records, or records managed by other systems. Therefore:

- **Missing records** (expected but not in DNS): always reported as errors.
- **Extra records** (in DNS but not in zone file): reported as informational by default, suppressible with `--ignore-extra`.

### 7.4 Records to Skip

Certain record types from the zone file should be skipped during verification:

- **SOA**: Excluded from record-by-record comparison, but the SOA is captured during zone parsing for serial comparison. The live SOA serial is compared against the zone file serial; a mismatch is reported as an issue. Use `--ignore-soa` to skip this check.
- **DNSSEC records** (RRSIG, DNSKEY, DS, NSEC, NSEC3, NSEC3PARAM): These are generated by the signing process, not manually authored. Verifying them requires DNSSEC validation logic, not simple comparison.
- **NS at apex**: Often managed by the registrar, not the zone file.

These should be skipped by default, with the ability to include them via `--only-type`.

## 8. Reuse Opportunities

- **`diff` module** (`src/diff.rs`): Verification is conceptually a directed diff (expected vs. actual). The existing diff infrastructure may be reusable or worth aligning with.
- **`check` lints** (`src/app/modules/check/`): Could optionally run lints on the parsed zone file before verification ("your zone file has issues before we even check live DNS").
- **`ResolverGroup`**: Standard concurrent lookup machinery, used as-is.
- **`Lookups` result type**: The existing typed accessors (`.a()`, `.mx()`, etc.) and `.unique()` deduplication work directly.

## 9. Phased Delivery

### Phase 1 — Minimum Viable Feature

- Parse BIND zone files via `hickory-proto`
- `mhost verify zone.db` command: read zone file, query DNS, report mismatches
- Human-readable and JSON output
- `--strict` flag for TTL matching
- Non-zero exit code on mismatch

### Phase 2 — Polish (done)

- ~~`--only-type` / `--ignore-type` filtering~~ — implemented: mutually exclusive, repeatable, comma-delimited, validated against `SUPPORTED_RECORD_TYPES`. Filtering applied before DNS queries to avoid unnecessary lookups.
- `--server` override for authoritative nameserver targeting — already supported via standard mhost resolver options
- ~~`--ignore-extra` to suppress extra record reporting~~ — implemented
- ~~`--ignore-soa` to skip SOA serial comparison~~ — implemented
- Integration with existing `check` lints on the parsed zone — deferred
- ~~SOA serial comparison (separate from record-by-record verification)~~ — implemented: zone parser captures SOA record before default-skip filtering; live SOA serial compared against zone file serial; mismatch counts as an issue (non-zero exit)

### Phase 3 — Extended Formats (Optional / Future)

These are ideas for potential future extension, not committed scope. They should only be pursued if there is clear user demand.

- BIND zone export from `lookup` / `domain-lookup` results (`--format zone`)
- Terraform state JSON import (`terraform show -json | mhost verify --format terraform-state -`)
- Generic CSV/TSV record format (name, type, value)
- **Probe-based wildcard verification** — For each wildcard record in the zone file (e.g., `*.example.com. IN A 1.2.3.4`), generate a random probe subdomain (e.g., `_mhost-probe-{random}.example.com.`), query it, and verify the response rdata matches the wildcard's rdata. This would actively test that wildcard synthesis works, rather than just confirming the wildcard record exists. Challenges: handling NXDOMAIN for zones without the expected wildcard, multi-level wildcards (`*.sub.example.com.`), interaction with explicit records that shadow wildcards, and CNAME wildcards.

## 10. Risks and Open Questions

1. **Zone file parser edge cases.** hickory-proto's parser handles standard zone files well, but exotic or malformed files may fail. Mitigation: clear error messages pointing to the parse failure, and document supported zone file features.

2. **`$INCLUDE` directive.** Zone files with `$INCLUDE` reference external files. The parser supports this (with path resolution relative to the zone file), but it requires filesystem access. This is fine for local files but worth documenting.

3. **Large zones.** The parser loads the entire zone into memory as a `BTreeMap<RrKey, RecordSet>`. For typical zones this is fine. For very large zones (e.g., TLD zone files with millions of records), memory usage and query volume could be problematic. This is an unlikely use case for mhost but worth noting.

4. **CNAME interaction.** If the zone file has a CNAME for `foo.example.com`, a live lookup for A records at that name will follow the CNAME and return A records of the target. The comparison logic needs to account for CNAME following behavior.

5. **Wildcard records.** ~~Zone files may contain wildcard records (`*.example.com`). Verifying these requires synthesizing specific names to query, which is non-trivial. Consider deferring wildcard verification to a later phase.~~ — Resolved: wildcard records (names where the first label is `*`) are now separated during zone parsing and reported as "skipped" in verification output. They are excluded from DNS queries since querying the literal wildcard name doesn't verify synthesis behavior. See "Probe-based wildcard verification" in Phase 3 for a future approach that would actively test wildcard synthesis.

6. **Feature flag scoping.** ~~The `text-parsing` feature should likely be gated behind the `app` feature flag (or a new `verify` feature) so library-only builds don't pull in the zone parser unless needed.~~ — Resolved: `hickory-proto` is declared `optional = true` and only enabled by the `app` feature. The `zone` module is gated with `#[cfg(feature = "hickory-proto")]`. Library-only builds exclude zone parsing.
