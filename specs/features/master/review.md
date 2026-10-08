
## v0.11.4..7f212bb

### Reader

COUNTS blockers=3 majors=1 minors=2
LENSES Engineering, Security, Testing
BLOCKER | src/resources/zone.rs:93 | `parse_str`'s `$INCLUDE` guard only matches the directive at line start, but hickory's parser also accepts it mid-line after a `$ORIGIN`/`$TTL` value, so the include is still followed | `parse_str("$ORIGIN example.com. $INCLUDE /etc/passwd\n…", None, None)` → guard returns false, parser opens the file (absolute paths work with `path=None`; `$TTL 1 $INCLUDE /dev/zero` exhausts memory). Verified with a scratch build against hickory-proto 0.26.3: guard did not refuse, and a `www` record from the included file appeared in the parsed rrsets; same-line form also passes for `$TTL 3600 $INCLUDE <file>`.
BLOCKER | src/app/mhost/modules/check/lints/dnssec_lint.rs:106 | `dnskey_rrsigs` returns on the first `Ok` response even when it carries no RRSIGs, so the remaining nameservers are never asked and the RRSIG checks are silently skipped | Zone NS {ns1 lame → REFUSED, ns2/ns3 signed with an expired DNSKEY RRSIG}; probe order comes from a HashSet (`unique_ips` → `Uniquify`), so ~1/3 of runs ns1 is first: `raw_dnssec_query` returns Ok(REFUSED, 0 answers), 0 RRSIGs merged, `check_rrsig_expiration` sees nothing and (since d7ad19b) no "no RRSIG" warning exists — `check` reports no DNSSEC issue for an expired signature, nondeterministically.
BLOCKER | src/nameserver/mod.rs:374 | `is_global` recognises only the well-known NAT64 prefix; addresses the doc promises are non-public are reported global, so `deny_non_global(true)` lets them through | `udp:[64:ff9b:1::a00:1]:53` (RFC 8215 local-use NAT64, IANA "not globally reachable", embedding 10.0.0.1): `segments[..6]` = `[0x64,0xff9b,1,0,0,0]` falls through to plain v6 checks → true; on a network with local-use NAT64 the query reaches 10.0.0.1. Also `[2001:2::1]` (IPv6 benchmarking) and `[3fff::1]` (IPv6 documentation, RFC 9637) → true although the doc says benchmarking/documentation are false.
MAJOR | src/app/mhost/modules/check/lints/axfr.rs:86 | When every NS address is non-public and filtered, the AXFR / open-resolver / delegation lints report "No IP addresses resolved for NS servers" — false: they resolved — and the skipped addresses appear nowhere in JSON output | `mhost check corp.example` with NS resolving only to 10.0.0.53 → JSON `check_results` contain `Warning("No IP addresses resolved for NS servers: cannot check AXFR")`; the correct reason (`probe_targets`' "Not probing non-public nameserver addresses") is only printed to the console under partial results.
MINOR | justfile:52 | `--skip services::whois` is a substring filter and also skips the two offline parser tests `parse_whois_ripe` / `parse_whois_arin`, not just the five network tests the comment names | `just adlc-verify` never runs those two tests, so a regression in whois JSON parsing (`src/services/whois/service.rs` changed in this range) passes the gate; the "nine" skipped are 7 whois + 2 parser, of which only 7 are network.
MINOR | src/services/http.rs:61 | The only over-limit test trips the Content-Length pre-check, so the chunk-loop cap the change exists for has no test that can fail | `reqwest::Response::from(http::Response::new(String))` has an exact size hint → `content_length()` is `Some(10)` → early return; deleting the `if len > max` inside the `res.chunk()` loop leaves both tests green.

```quote src/resources/zone.rs:93
        line.len() >= 8 && line.is_char_boundary(8) && line[..8].eq_ignore_ascii_case("$INCLUDE")
```

```quote src/app/mhost/modules/check/lints/dnssec_lint.rs:106
                    return Ok(Lookups::new(vec![Lookup::from_records(query, name_server, records)]));
```

```quote src/nameserver/mod.rs:374
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
```

```quote src/app/mhost/modules/check/lints/axfr.rs:86
                "No IP addresses resolved for NS servers: cannot check AXFR".to_string(),
```

```quote justfile:52
        --skip services::whois \
```

```quote src/services/http.rs:61
        let err = read_text_capped(response("0123456789"), 9).await.unwrap_err();
```

### Refutation

| Finding | Refuter | Confidence |
|---|---|---|
| BLOCKER zone.rs:93 `$INCLUDE` mid-line | CONFIRMED | 9 |
| BLOCKER dnssec_lint.rs:106 first `Ok` without RRSIGs | CONFIRMED (severity arguable: skipped check, not a wrong verdict) | 8 |
| BLOCKER nameserver/mod.rs:374 NAT64/v6 special ranges | CONFIRMED (severity arguable: unlikely NS addresses) | 9 |
| MAJOR axfr.rs:86 false "No IP addresses resolved" | CONFIRMED (same pattern in open_resolver, delegation) | 8 |

Nothing refuted; severities kept.

### Calibration

| Finding | Refuter answer | Confidence | Result | Command |
|---|---|---|---|---|
| zone.rs:93 | CONFIRMED | 9 | held | `cargo test --lib parse_str_rejects_include` with `$TTL 3600 $INCLUDE /etc/hosts` — parser read /etc/hosts (label error from its contents) |
| dnssec_lint.rs:106 | CONFIRMED | 8 | held | read loop: `Ok(response) => … return` on any Ok; `unique_ips` order from `Uniquify` hash set — `unique_ips_are_ordered` failed against it |
| nameserver/mod.rs:374 | CONFIRMED | 9 | held | `cargo test --lib nameserver::test` → `[64:ff9b:1::a00:1] must not be global` |
| axfr.rs:86 | CONFIRMED | 8 | held | read `probe_targets` → empty vec on all non-public, branch emits "No IP addresses resolved"; skipped list only via `console.info` |

### Fixes

| Finding | Commit |
|---|---|
| zone.rs:93 | 2eb5d61 fix(zone): refuse $INCLUDE anywhere in zone text |
| nameserver/mod.rs:374 | 5223fd9 fix(nameserver): judge local NAT64, 6to4 and the newer IPv6 special ranges |
| dnssec_lint.rs:106 | 3fade51 fix(check): ask the next nameserver when DNSKEY signatures are missing |
| axfr.rs:86 | ebd83c2 fix(check): name non-public nameservers as the reason a probe was skipped |
| justfile:52 (MINOR) | 387617e fix(just): stop the gate from skipping the offline whois parser tests |
| http.rs:61 (MINOR) | 49b5998 test(services): cover the per-chunk body cap |

### Summary

Before refutation 3/1/2, after refutation 3/1/2. verified 4, held 4. No principles declared: no roll call. All six findings fixed on master after 7f212bb.

## 7f212bb..49b5998

### Reader

COUNTS blockers=0 majors=2 minors=2
LENSES Engineering, Security, Testing
MAJOR | src/nameserver/mod.rs:391 | `is_global_ipv6` still reports the SRv6 SID block 5f00::/16 as public: a 2024 IPv6 special range (RFC 9602) that IANA lists as "Globally Reachable: False", while the function's doc promises false for anything not "a globally routable address" | `NameServerConfig::from_str("udp:[5f00::53]:53").unwrap().is_global()` → true; a zone whose NS AAAA is 5f00::53 gets AXFR/open-resolver/DNSKEY probes, and `deny_non_global(true)` accepts it as a nameserver.
MAJOR | src/app/mhost/modules/check/lints/dnssec_lint.rs:87 | The DNSKEY probe's `unwrap_or_default()` drops the "not public" reason without a `debug!` and without a result — the same defect ebd83c2 fixed for AXFR/open-resolver/delegation, against the CLAUDE.md rule "Don't silently swallow errors — log at `debug!` minimum" | `mhost check` without `-p` (or JSON) on a signed zone whose NS all resolve to 10.0.0.53: no probe is sent, the RRSIG expiry/binding checks are silently skipped; neither results, JSON nor a debug log says why.
MINOR | src/app/mhost/modules/check/lints/dnssec_lint.rs:143 | The test added with 3fade51 cannot fail for that fix; it only asserts a REFUSED message with no answers yields no RRSIGs | Delete the `if records.is_empty() { …; continue; }` block (or make `dnskey_signatures` return `Vec::new()`): `refusing_server_yields_no_signatures` still passes.
MINOR | src/services/http.rs:28 | `read_text_capped` still has no test that fails if the per-chunk cap is removed, though 49b5998 claims coverage | Replace the line with `body.extend_from_slice(&chunk);`: all three tests stay green — `body_over_limit_fails` hits the Content-Length pre-check (String body has an exact size hint), `chunks_past_the_limit_fail` calls `push_capped` directly.

```quote src/nameserver/mod.rs:391
        || segments[..4] == [0x100, 0, 0, 0]) // discard-only
```

```quote src/app/mhost/modules/check/lints/dnssec_lint.rs:87
        let targets = super::probe_targets(&ns_lookups, &self.env.console).unwrap_or_default();
```

```quote src/app/mhost/modules/check/lints/dnssec_lint.rs:143
        assert!(dnskey_signatures(&response).is_empty());
```

```quote src/services/http.rs:28
        push_capped(&mut body, &chunk, max)?;
```

### Refutation

| Finding | Refuter | Confidence |
|---|---|---|
| MAJOR nameserver/mod.rs:391 SRv6 SID 5f00::/16 global | CONFIRMED | 9 |
| MAJOR dnssec_lint.rs:87 reason dropped by `unwrap_or_default()` | CONFIRMED | 8 |

### Calibration

| Finding | Refuter answer | Confidence | Result | Command |
|---|---|---|---|---|
| nameserver/mod.rs:391 | CONFIRMED | 9 | held | `cargo test --lib nameserver::test::non_global` with `[5f00::53]` → "must not be global" |
| dnssec_lint.rs:87 | CONFIRMED | 8 | held | read: `probe_targets(..).unwrap_or_default()`, no `debug!`, no `CheckResult` |

### Fixes

| Finding | Commit |
|---|---|
| nameserver/mod.rs:391 | 392f1e6 fix(nameserver): follow the IANA IPv6 special-purpose registry completely |
| dnssec_lint.rs:87 | d125624 fix(check): report why DNSKEY signatures were not fetched |
| dnssec_lint.rs:143 (MINOR) | a6a433f test(check): prove a refusing nameserver is passed over (mutation-checked) |
| http.rs:28 (MINOR) | f742424 test(services): read a chunked body past the limit (mutation-checked) |

### Summary

Before refutation 0/2/2, after refutation 0/2/2. verified 2, held 2. No principles declared: no roll call. All four findings fixed after 49b5998.

## 2e1a6e4..2ad36c9

### Reader

COUNTS blockers=1 majors=0 minors=0
LENSES Engineering, Testing
BLOCKER | src/resolver/lookup.rs:720 | A referral (NOERROR, empty answer, NS in authority) becomes `NxDomain` with `response_code() == Some(NoError)`, which the new contract (lookup.rs:579, CHANGELOG) defines as NODATA — "the name exists", a definite answer; a consumer following the contract treats a referral as proof the name exists | Query a non-recursive server below a delegation, e.g. `mhost -s a.gtld-servers.net l nonexistent.example.com` (type A): NOERROR, no answers, `example.com. NS …` + glue. hickory 0.26 `DnsError::from_response` turns this into `NoRecordsFound(NoRecords{response_code: NoError, ns: Some(referral), soa: None})`; `select_records` keeps nothing (type A, glue names differ), so `into_lookup` returns `NxDomain{response_code: Some(NoError)}` — by the documented meaning "nonexistent.example.com exists, type A does not", which is false. `NoRecords.ns`/`.soa` would separate a referral from real NODATA but are not consulted.

```quote src/resolver/lookup.rs:720
                        response_code: Some(ResponseCode::from_proto(no_records.response_code)),
```

```quote src/resolver/lookup.rs:579
/// `NXDomain` (the name does not exist) and `NoError` (NODATA: the name exists, the type does
```

### Refutation

| Finding | Refuter | Confidence |
|---|---|---|
| BLOCKER lookup.rs:720 referral reported as NODATA | CONFIRMED (severity arguable: hits external library consumers, not the CLI) | 8 |

### Calibration

| Finding | Refuter answer | Confidence | Result | Command |
|---|---|---|---|---|
| lookup.rs:720 | CONFIRMED | 8 | held | `referral_is_not_a_definite_answer`: NoRecords{NoError, ns: Some, soa: None} → NxDomain{Some(NoError)}, no API to tell it from NODATA at 2ad36c9 |

### Fixes

| Finding | Commit |
|---|---|
| lookup.rs:720 | 979bee1 fix(resolver): do not take a referral for NODATA |

### Summary

Before refutation 1/0/0, after refutation 1/0/0. verified 1, held 1. No principles declared: no roll call. Fixed after 2ad36c9.
