
## c55d5f5..a2e5a1f

### Reader

COUNTS blockers=2 majors=0 minors=0
LENSES Engineering, Security, Testing
BLOCKER | src/app/mhost/modules/dnssec/chain.rs:194 | With `--no-tcp-fallback`, a truncated DNSKEY answer only gets a warning and then counts as "no DNSKEY", so `dnssec` calls a correctly signed zone broken | `mhost --no-tcp-fallback dnssec <zone>`, where the parent serves a DS for the zone and every server of the zone truncates its DNSKEY+RRSIG answer with DO set (for example an RSA rollover set of about 1.7 KB against servers that cap UDP at 1232 bytes) |
BLOCKER | src/app/mhost/modules/dnssec/chain.rs:317 | With `--no-tcp-fallback`, a truncated NS referral counts as "no nameservers", so the walk stops early and still reports `Chain status: secure` for zones it never queried | `mhost --no-tcp-fallback dnssec <child>.<parent>`, where the parent's servers answer the non-EDNS NS query for the child (512-byte limit) with TC=1 because its in-domain glue does not fit |

#### BLOCKER 1: a truncated DNSKEY answer becomes a "broken" verdict

```quote src/app/mhost/modules/dnssec/chain.rs:194
        warn_truncated(&dnskey_results, &hickory_zone, HickoryRecordType::DNSKEY);
```

Traced at level `i > 0` for zone Z, where every `dnskey_results` entry is `Err(RawError::Truncated { .. })`:

- `warn_truncated` logs one warning per server. The extraction loop that follows reads only `Ok` results, so `dnskeys` and `rrsigs` stay empty.
- `ds_from_parent` is not empty: the earlier DS query with DO went to the parent and was small enough not to truncate. So this binding check runs with an empty key set:

```quote src/app/mhost/modules/dnssec/chain.rs:240
            findings.extend(dnssec_validation::validate_ds_dnskey_binding(&ds_refs, &dnskey_refs));
```

- That check returns a `Failed` finding:

```quote src/resources/dnssec_validation.rs:187
            "DS records exist but no DNSKEY records found: DNSSEC chain of trust is broken",
```

- The "Zone Z has no DNSKEY records: not DNSSEC-signed" warning is added as well. The level's status becomes `Failed`, and the footer prints:

```quote src/app/mhost/modules/dnssec/mod.rs:398
        Severity::Failed => "broken".paint(output_styles::ERROR).to_string(),
```

**Result:** a signed, valid zone is reported as `Chain status: broken` and "not DNSSEC-signed". The only true statement in the output is the warning that the answer was truncated. The walk could not check the zone, but the output says the zone is broken.

**Why this change causes it:** before this change the flag did not reach `dnssec`, so the TCP fallback fetched the keys and the verdict was correct. Requirement 11 asks for the warning, but neither it nor any other requirement asks for a truncated answer to count as a missing record set.

The same code path has a second form at the root (`i == 0`): no finding is added there, and the root level counts as `Ok` without any key or signature having been seen.

#### BLOCKER 2: a truncated NS referral ends the walk, and the verdict says "secure"

```quote src/app/mhost/modules/dnssec/chain.rs:317
            warn_truncated(&ns_results, &hickory_child, HickoryRecordType::NS);
```

`parallel_raw_queries` builds its message with `build_query_message`, which sets no EDNS, so the server's answer is limited to 512 bytes. Traced for the case where every NS result for the child is `Err(Truncated)`:

- `extract_ns_servers` skips `Err` results and returns an empty map.
- That sets:

```quote src/app/mhost/modules/dnssec/chain.rs:345
                current_servers = Vec::new();
```

- The next iteration stops at:

```quote src/app/mhost/modules/dnssec/chain.rs:161
        if current_servers.is_empty() {
```

- `TrustChain.status` is the worst status of the levels walked so far. If those levels are clean, the footer prints:

```quote src/app/mhost/modules/dnssec/mod.rs:396
        Severity::Ok => "secure".paint(output_styles::OK).to_string(),
```

**Result:** the chain is called secure, even though the zone being looked up and every zone between it and the parent were never queried.

**Why this change causes it:** without the flag, the raw query would have completed the referral over TCP.

#### Traced and sound

- **Estimate:** traced `Resolver::estimate` against `single_lookup` and `build_resolvers`, covering UDP with `tcp_retry`, UDP without fallback, and `tcp:`. The doubled maximum and the unchanged minimum match requirements 1–4.
- **Raw queries:** `raw_query` and `raw_dnssec_query` return `Truncated` before any TCP connect when `tcp_fallback` is false, and return a complete answer unchanged.
- **Call sites:** all five call sites pass `AppConfig.tcp_fallback` (`trace.rs:171`, `chain.rs:191/302/314`, `dnssec_lint.rs:112`).
- **`trace` rendering:** both renderings contain `truncated`.
- **`check` lint:** it does not judge DNSKEY without RRSIG, so a truncation there skips the signature checks without producing a false verdict.
- **Tests and lit patterns:** the new tests fail when the code they name is removed. The lit patterns and test-change trailers agree with requirement 5.
### Spec reader

COUNTS blockers=0 majors=0 minors=0
REQUIREMENTS met=12 partial=0 missed=0 contradicted=0

I traced a `udp:` resolver with `tcp_fallback` on and retries 2 through `Resolver::estimate` (`src/estimate.rs`), where `tcp_retry.is_some()` doubles the maximum to 36 for 2 names x 3 types; a `tcp:` resolver and a `udp:` resolver built with `--no-tcp-fallback` keep 18; I traced a truncated UDP answer through `raw_query` and `raw_dnssec_query` with `tcp_fallback` false to `Err(RawError::Truncated { server })` before `send_tcp`; and I traced the flag from `AppConfig.tcp_fallback` to all five raw call sites (trace.rs:165, chain.rs:185/296/308, dnssec_lint.rs:107), to trace's `ServerOutcome::Error` rendering, and to the `warn!` lines in chain.rs and the lint, with the lint's name carried by the `dnskey_rrsigs` span that the default fmt layer prints. I found no divergence from requirements 1–12, no unrequested behaviour, and no Rule 1 finding: Phase 1 (spec lines 117–118) and Phase 2 (lines 137–138) each have a scenario whose THEN names printed output.

### Refutation

F1 | src/app/mhost/modules/dnssec/chain.rs:194 | CONFIRMED — warn_truncated only logs; extraction reads Ok results only, so dnskeys stays empty while ds_from_parent is non-empty; validate_ds_dnskey_binding then returns Failed "chain of trust is broken" and the i>0 "not DNSSEC-signed" warning is added; footer prints broken. Req 11 asks only for the warn, not a broken verdict — confidence 8 — fix right (record a truncation finding at warning/inconclusive severity for the level and skip the DS/DNSKEY binding and unsigned checks when all DNSKEY queries truncated) — class dnssec walk, all servers of a level answer a raw query with Truncated under --no-tcp-fallback; neighbours DS query truncated (ds_from_parent empty, signed child looks unlinked); root level i==0 DNSKEY truncated (level stays Ok with no keys); RRSIG-bearing answer truncated in the check lint (debug-logged only) — new
F2 | src/app/mhost/modules/dnssec/chain.rs:317 | CONFIRMED — truncated NS results make extract_ns_servers empty, so the else branch sets current_servers empty; next iteration warns and breaks; child and deeper levels are never pushed and the fold over existing levels yields Ok, so "secure" prints for a shortened chain. Before the change TCP fallback completed the answer — confidence 7 — fix right (when NS results all truncated, add a visible non-secure finding/status for the unreached levels instead of a silent stop) — class dnssec walk, referral NS query truncated under --no-tcp-fallback; neighbours DS query truncated at the same level; non-EDNS NS query truncated for in-domain glue in trace (shown as server error, fine per req 10); glue resolution after a partial NS answer — new

### Calibration

| finding | refuter answer | confidence | result | command |
|---|---|---|---|---|
| F1 | CONFIRMED | 8 | held | `sed -n 140,250p src/app/mhost/modules/dnssec/chain.rs`: `warn_truncated` only logs, `dnskeys` stays empty, `validate_ds_dnskey_binding` runs when `ds_from_parent` is non-empty |
| F2 | CONFIRMED | 7 | held | `sed -n 300,360p src/app/mhost/modules/dnssec/chain.rs`: empty `extract_ns_servers` sets `current_servers = Vec::new()`, the loop breaks at the next level, status folds from the levels recorded so far |

### Findings

F1 | BLOCKER | src/app/mhost/modules/dnssec/chain.rs:194 | dnssec walk, all servers of a level truncate a raw query under --no-tcp-fallback | fixed
F2 | BLOCKER | src/app/mhost/modules/dnssec/chain.rs:317 | dnssec walk, referral NS query truncated under --no-tcp-fallback | fixed

## a2e5a1f..e11f40d

### Reader

COUNTS blockers=1 majors=2 minors=0
LENSES Engineering, Testing
BLOCKER | src/app/mhost/modules/dnssec/mod.rs:353 | When every DNSKEY answer for a zone is truncated, the summary tree still shows the parent's DS as "has no matching DNSKEY: chain of trust is broken" in red, under a footer that says only "warnings". | `mhost --no-tcp-fallback dnssec <zone>`: the parent serves a DS for `<zone>`, and every `<zone>` server answers DNSKEY with DO set with TC=1 |
MAJOR | src/app/mhost/modules/dnssec/chain.rs:82 | `all_truncated` treats an error-rcode response (REFUSED/SERVFAIL) as a usable answer, so a truncated DNSKEY answer next to one lame server still gives the false "chain of trust is broken" / "not DNSSEC-signed" verdict this change exists to prevent. | `mhost --no-tcp-fallback dnssec <zone>`: the parent serves a DS. NS A of `<zone>` truncates DNSKEY (TC=1). NS B is lame and answers REFUSED. |
MAJOR | src/app/mhost/modules/dnssec/chain.rs:376 | At the `--max-hops` cut, the last walked level still queries the child's DS and NS. A truncated child answer there turns a secure walk into "warnings" and blames truncation for stopping the walk, although the hop limit stopped it. | `mhost --no-tcp-fallback dnssec --max-hops 2 <name>.<tld>`, where the `<tld>` servers answer the NS (or DS) query for `<name>.<tld>` with TC=1 |

#### BLOCKER: the summary tree still shows a broken chain when the DNSKEY answer is truncated

```quote src/app/mhost/modules/dnssec/mod.rs:353
                let binding = dnssec_validation::classify_ds_binding(ds, &child_dnskey_refs);
```

Traced for parent level P and child level C, where every C `dnskey_results` entry is `Err(Truncated)`:

- `chain.rs` now pushes only the truncation warning for C and skips `validate_ds_dnskey_binding`. In JSON, C carries a single `Warning` and the chain status is `Warning`. That part is correct.
- C still has `ds_records = ds_from_parent`, which is not empty, and `dnskeys = []`.
- `write_level(P, next_ds = Some(&C.ds_records), next_dnskeys = Some(&C.dnskeys))` is used by both renderings: the full one (`mod.rs:220`) and the streamed one (`mod.rs:106`, `:140`).
- That call runs `classify_ds_binding` against an empty key set for each DS. `classify_ds_binding` returns `Failed("DS key tag N has no matching DNSKEY: chain of trust is broken")`, and `format_finding_inline` paints it in red.
- `write_level` never prints `level.findings`, so the summary does not show the new truncation finding anywhere.

**Result:** the default summary output still says the chain is broken at the exact DS this change meant to stop judging, while the footer says `Chain status: warnings`. The verdict was moved only in the data model, not in the rendering that users read. Requirement 11's `warn!` line on stderr names the truncation, but it does not take back the red "broken" line on stdout.

#### MAJOR: `all_truncated` counts an error-rcode response as data

```quote src/app/mhost/modules/dnssec/chain.rs:82
    results.iter().all(|r| r.result.is_err())
```

- `raw_dnssec_query` returns `Ok(response)` for any response that is not truncated, whatever its rcode (`src/resolver/raw.rs`, `raw_dnssec_query`).
- With servers A (`Err(Truncated)`) and B (`Ok`, REFUSED, empty answer), `all_truncated` is false.
- So `dnskeys` stays empty, and `validate_ds_dnskey_binding` returns `Failed("DS records exist but no DNSKEY records found: DNSSEC chain of trust is broken")`. The guard at `chain.rs:285` also lets the "not DNSSEC-signed" warning through.
- The footer reads `broken`.

With TCP fallback on, A's keys arrive over TCP and the verdict is correct. The guard lets through a truncated answer it should catch, because a response with no data counts as usable. The NS query has the same gap: a truncated server plus a REFUSED server stops the walk with no finding, and a clean chain still reads `secure`.

#### MAJOR: the hop limit is reported as a truncated referral

```quote src/app/mhost/modules/dnssec/chain.rs:182
        let child_zone = zones.get(i + 1);
```

```quote src/app/mhost/modules/dnssec/chain.rs:376
                    &format!("the walk stopped because the referral for {} was truncated", child),
```

- `walk_len = zones.len().min(max_hops)`, and `child_zone` is taken from `zones`, not from `walk_len`. So at `i = walk_len - 1 < zones.len() - 1`, the child's DS and NS are still queried.
- If those answers are all truncated, the new findings go onto the last walked level and raise its status to `Warning`.
- Without this change, and with TCP fallback, the same two-level walk ends `secure`. Its levels are unchanged, and the child's data would never have been used.
- Now it ends `warnings`, with a finding that blames truncation for stopping the walk, although the hop limit did.

#### Answers to the caller's questions

1. Yes: the three findings above.
2. JSON is correct: one truncation `Warning` on the zone level and chain status `Warning`. The summary output is wrong, see the BLOCKER.
3. No wrong result traced. The `Warning` lands on the parent level, `ds_from_parent` is empty, so the child level runs no DS binding check and the summary prints no DS lines. That level was rendered after the finding was added, at the next `on_level` call. If the hop limit stopped the walk, see MAJOR 2.
4. No wrong result traced. At `i == 0` the root level gets the truncation `Warning` and skips the binding checks. The unsigned-zone check does not apply at `i == 0`, and the status is `Warning`.
5. No wrong result in the plain walk. The NS finding is added after `on_level` ran for that level, but the streamed callback renders a level only once the next level arrives. The post-walk loop (`mod.rs:134-142`) renders the last level and the footer from the final `TrustChain`, so the footer shows `warnings` in both renderings. As with the other findings, the finding text appears only in JSON and in the stderr `warn!` lines. Exception: the hop-limit case, MAJOR 2.
6. Some servers truncated, the others answering with data: correct. The checks run on the union of the complete answers. Some truncated, the others answering with an error rcode: wrong, MAJOR 1. Servers timing out without truncating: `all_truncated` is false (tested), so the code takes the earlier path and an empty DNSKEY set again gives `broken`. That behaviour existed before this change, does not depend on `--no-tcp-fallback`, and is not counted here.

#### Traced and sound

- The `all_truncated` unit test covers the refused input (truncated, plus truncated with timeout) and its neighbours (empty, timeout only, truncated with Ok). Deleting either conjunct makes it fail.
- `truncated_finding` is a `Warning`, so `Severity::worst` cannot hide an existing `Failed`.
- `validate_rrsig_expiration` and the algorithm check still run when the DNSKEY answers are truncated, but both see empty sets in that case, so they add nothing.
### Spec reader

skipped: re-review over fix commits spawns the correctness reader only
COUNTS blockers=0 majors=0 minors=0

### Refutation

F1 | src/app/mhost/modules/dnssec/mod.rs:353 | CONFIRMED — write_level (both streamed and full paths) runs classify_ds_binding on the child's empty dnskeys; resources/dnssec_validation.rs:155 returns Failed "no matching DNSKEY: chain of trust is broken", painted red, while chain.rs only adds the truncation Warning (finding is not printed by write_level) — confidence 9 — fix right (render an unknown/warning state for DS lines when the child level carries the DNSKEY truncation finding, or skip DS binding there) — class summary rendering of DS lines when child DNSKEY set is unknown; neighbours hop-cut level with child ds_records but no child level; child DNSKEY queries all timed out (pre-existing); streamed vs full render — new
F2 | src/app/mhost/modules/dnssec/chain.rs:82 | CONFIRMED — all_truncated requires every result Err; an Ok REFUSED/SERVFAIL response from a lame server makes it false, so the empty DNSKEY set takes the old "broken"/"not signed" path — confidence 8 — fix wrong: count only Ok responses that are NOERROR and carry data as usable (treat error-rcode Ok as unusable), not just Err — class mixed truncated + non-data responses for one raw query; neighbours truncated + timeout (already handled); truncated + REFUSED on NS query (silent walk stop); truncated + NODATA NOERROR; truncated + SERVFAIL on DS — new
F3 | src/app/mhost/modules/dnssec/chain.rs:376 | CONFIRMED — child_zone = zones.get(i+1) ignores walk_len, so at the max-hops cut the child DS/NS are still queried and truncated answers add a Warning blaming truncation for the walk stopping — confidence 9 — fix right (take child only when i+1 < walk_len, also saves two queries) — class queries issued past the --max-hops cut; neighbours non-truncated child answers at the cut (wasted queries); DS truncated at the cut; NS truncated at the cut; max_hops=1 — new

### Calibration

| finding | refuter answer | confidence | result | command |
|---|---|---|---|---|
| F1 | CONFIRMED | 9 | held | `sed -n 340,360p src/app/mhost/modules/dnssec/mod.rs`: `classify_ds_binding(ds, &child_dnskey_refs)` runs on the empty child key set |
| F2 | CONFIRMED | 8 | held | `sed -n 75,92p src/app/mhost/modules/dnssec/chain.rs`: `all_truncated` requires every result to be `Err`, so an `Ok` REFUSED response defeats it |
| F3 | CONFIRMED | 9 | held | `sed -n 178,184p src/app/mhost/modules/dnssec/chain.rs`: `child_zone = zones.get(i + 1)` ignores `walk_len` |

### Findings

F1 | BLOCKER | src/app/mhost/modules/dnssec/mod.rs:353 | summary rendering of DS lines when the child DNSKEY set is unknown | fixed
F2 | MAJOR | src/app/mhost/modules/dnssec/chain.rs:82 | truncated plus non-data responses on one raw query | fixed
F3 | MAJOR | src/app/mhost/modules/dnssec/chain.rs:376 | queries issued past the --max-hops cut | fixed

### Summary

Round 2 (re-review over fix commit e11f40d). Reader: 1 blocker, 2 majors, 0 minors before and after refutation (3 confirmed); spec reader skipped (re-review over fix commits). verified 3, held 3. No principles declared, no roll call. The fix of round 1 F1/F2 left the rendered DS line red (F1) and two neighbours open (F2 lame-server mix, F3 max-hops cut); halted with blocker.

## e11f40d..e08445f

### Reader

COUNTS blockers=0 majors=0 minors=0
LENSES Engineering, Testing

I traced e11f40d..e08445f through `walk_trust_chain`, `is_usable`/`all_truncated`, `walked_child_zone` and `write_level` (both the streamed and the full render) for questions 2 to 8, and found no wrong result introduced by this range.

#### Answers to the caller's questions

1. No wrong result traced (details below).
2. No. When every DNSKEY answer for the child is truncated, `all_truncated(.., DNSKEY)` is true, so the child level carries `dnskeys_unknown = true` (chain.rs:335). The streamed callback renders the parent only after the child level has been pushed (chain.rs:337-341, mod.rs:103-109). The full render passes `levels.get(i + 1)`. In both renders the parent's DS lines show the warning "child DNSKEY set unknown: answer truncated" instead of `classify_ds_binding` (mod.rs:347-351), `link_info` is empty, and the child's truncation finding is printed (mod.rs:387-393). Footer: `warnings`.
3. No wrong result from this change. At the hop cut, `walked_child_zone` returns `None` (chain.rs:123-125), so no DS is queried and `ds_from_parent` is cleared (chain.rs:427). The last level renders with `next = None`, so it has no DS lines. When the walk stops because the NS referral is empty, the child DS records that were fetched have no level to render them. That was already true before this range and does not affect the verdict.
4. Not changed by this range. A timeout is not `Truncated`, so `all_truncated` is false and `dnskeys_unknown` stays false. The old "DS records exist but no DNSKEY records found" / "not DNSSEC-signed" path still runs. The pre-change `all_truncated` gave the same result, and the new test `summary_output_missing_child_dnskeys_still_break_the_chain` pins it on purpose. It is not counted here.
5. No. A REFUSED response is not usable (chain.rs:88), so `all_truncated(ns, NS)` is true. `extract_ns_servers` finds no NS, so the NS truncation finding is added (chain.rs:405-411), `current_servers` is emptied and the walk stops with `warnings`.
6. No. A NOERROR answer without records of the queried type is not usable. With a truncated sibling it yields the truncation finding and not a false "broken" or "not signed" verdict. For DS/DNSKEY a truncated NODATA from a correctly configured server would need a denial proof larger than the EDNS buffer (4096, raw.rs:257), which is not a realistic input.
7. No. SERVFAIL is not usable, so the DS truncation finding lands on the parent level (chain.rs:398-417). `ds_from_parent` is empty, so the child runs no DS binding check, and the parent prints the finding with no DS lines.
8. No. `walk_len = zones.len().min(max_hops)` with `max_hops` in 1..=20 (cli_parser.rs `usize_range(1, 20)`). `zones[..walk_len].get(i + 1)` is `None` exactly at `i = walk_len - 1`, so no DS/NS query is issued past the cut, also for `max_hops = 1` (root only). A truncated or clean child answer below the cut is never fetched.

#### Traced and sound

- `is_usable` requires NOERROR and a record of the queried type in the answer or authority section. That is a referral for NS (chain.rs:85-97). Removing either conjunct fails `all_truncated_ignores_lame_responses_without_data`.
- `summary_output_truncated_dnskeys_do_not_break_the_chain` fails if the `child_keys_unknown` branch is removed: `classify_ds_binding` on an empty key set prints "no matching DNSKEY". Its neighbour test keeps the non-truncated empty set "broken".
- The DS and NS findings are added to the parent level before the next level's callback renders it, so the streamed output shows them.
### Spec reader

skipped: re-review over fix commits spawns the correctness reader only

COUNTS blockers=0 majors=0 minors=0

### Refutation

none: no BLOCKER or MAJOR finding to refute

### Calibration

none

### Findings

### Summary

Round 3 (re-review over fix commit e08445f for round-2 F1-F3). Reader: 0 blockers, 0 majors, 0 minors before and after refutation; spec reader skipped (re-review over fix commits). verified 0, held 0. No principles declared, no roll call. Reader notes a signed zone whose DNSKEY queries all time out still reads broken: pre-existing, pinned by a test, not counted.
