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
