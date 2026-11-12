# Report: tcp-fallback-followups

## Phase 1 — Estimate counts the TCP retry

### Criteria

| id | criterion | status | test file |
|---|---|---|---|
| C1 | Req 1: max = names*types*2*(1+retries) with tcp_retry; upper-bound comment; existing estimate.rs asserts move to new max | green | src/estimate.rs, src/resolver/tcp_fallback_tests/estimate_counts_tcp_retry.rs |
| C2 | Req 2: min stays names*types for every resolver | green | src/resolver/tcp_fallback_tests/estimate_min_unchanged.rs |
| C3 | Req 3: no tcp_retry (tcp/tls/https or tcp_fallback off) keeps max = names*types*(1+retries) | already_implemented | src/resolver/tcp_fallback_tests/estimate_without_tcp_retry.rs |
| C4 | Req 4: ResolverGroup Multi (sum, limit) / Uni (first) over per-resolver values | green | src/resolver/tcp_fallback_tests/estimate_group_counts_tcp_retry.rs |
| C5 | Req 5: lit estimate lines from udp nameservers use `Sending [[.+]] request[[s*]] to`; dot-doh keeps fixed count | already_implemented | tests/lit/*.output (10 files; network, outside the gate; pattern accepts both forms) |
| C6 | Scenario: `--no-system-lookups -s udp:<ns> lookup -t A example.com` formats "between 1 and 2 requests" | green | src/app/mhost/tcp_fallback_tests/cli_estimate_counts_tcp_retry.rs (asserts min/max; no pure formatting seam) |
| C7 | Scenario: same with `--no-tcp-fallback` formats "1 request" | already_implemented | src/app/mhost/tcp_fallback_tests/cli_estimate_without_fallback.rs (asserts min == max == 1) |

### Runs

| group | coder runs | green by | tokens | seconds |
|---|---|---|---|---|
| G1 | 1 | sonnet | 18711 | 13 |

### Behavioural verification

```
$ mhost --no-system-lookups -s udp:127.0.0.1:1 --timeout 1 l -t A example.com
▸ Sending between 1 and 2 requests to 1 nameserver for 1 record type of 1 name.
$ mhost --no-system-lookups --no-tcp-fallback -s udp:127.0.0.1:1 --timeout 1 l -t A example.com
▸ Sending 1 request to 1 nameserver for 1 record type of 1 name.
$ mhost --no-system-lookups -s tcp:127.0.0.1:1 --timeout 1 l -t A example.com
▸ Sending 1 request to 1 nameserver for 1 record type of 1 name.
```

### Reader

specs/features/tcp-fallback-followups/reader.p1.md: 1 AMENDMENT (Uni estimate reflects first resolver only), not repaired in phase; Req 4 edited, decision triage-1.

## Phase 2 — `--no-tcp-fallback` reaches the raw paths

### Criteria

| id | criterion | status | test file |
|---|---|---|---|
| C1 | Req 6: the four raw functions take `tcp_fallback: bool` last; `true` retries a truncated UDP answer over TCP (scenario: complete answer, one TCP connection) | green | src/resolver/tcp_fallback_tests/raw_truncated_falls_back_over_tcp.rs |
| C2 | Req 7: `false` + truncated → no TCP connection, `Err(RawError::Truncated { server })`, Display `response from {server} was truncated and TCP fallback is disabled` (scenarios: raw_query, raw_dnssec_query, parallel_raw_queries) | green | src/resolver/tcp_fallback_tests/{raw_query,raw_dnssec_query,parallel_raw_queries}_no_fallback_reports_truncation.rs |
| C3 | Req 8: complete UDP answer returned unchanged, no TCP connection, for `true` and `false` | green | src/resolver/tcp_fallback_tests/raw_complete_udp_answer_needs_no_tcp.rs |
| C4 | Req 9: trace, dnssec, check DNSSEC lint pass `AppConfig.tcp_fallback` (checked by review, no test by spec) | test-unwritable | none: no seam observes the value at the call sites; checked by review (Req 9) |
| C5 | Req 10: trace renders a Truncated server error with `truncated` by default (`! <ip> (<name>): …`) and with `--show-all-servers` (`Error: …`), single-server hop | green | src/app/mhost/modules/trace/trace.rs (tests::summary_output_truncated_error_names_truncation) |
| C6 | Req 11: dnssec chain and check DNSSEC lint log `RawError::Truncated` at `warn!` with server, name, type; other errors unchanged | green | src/app/mhost/modules/check/lints/dnssec_lint.rs (tests::truncated_response_is_logged_at_warn_with_server); chain.rs path untested (no seam) |
| C7 | Req 12: CHANGELOG `## Unreleased` notes estimate + flag coverage (prose, no test) | test-unwritable | none: CHANGELOG prose |

### Runs

| group | coder runs | green by | tokens | seconds |
|---|---|---|---|---|
| G1 | 1 | sonnet | 36246 | 52 |

### Reader

none: review reads this range

### Behavioural verification

```
$ mhost --no-tcp-fallback trace -t A example.com
...
❖ Trace complete: 3 hops, 5s total
❖ Finished.
```

The live trace runs with the flag, and per-server errors still show on the `⚠︎ <ip> (<name>): <msg>` path (here IPv6 `No route to host`). No real server set TC for this query, so the truncation path is covered by the fake-NS and trace render tests, not live.
