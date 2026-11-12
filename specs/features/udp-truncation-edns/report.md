# Report: udp-truncation-edns

## Phase 1 — UDP nameservers fall back to TCP on truncation

### Criteria

| id | criterion | status | test file |
|---|---|---|---|
| C1 | R1: the loop command prints TXT records and `✓ No errors occurred.`, no `response was truncated` | green | `src/resolver/tcp_fallback_tests/large_answer_over_tcp.rs` |
| C2 | R2: by default a `udp:` config gets [UDP, TCP] on its port; TCP only after truncation | green | `src/nameserver/tcp_fallback_tests/udp_default_connections.rs` |
| C3 | R3: `tcp:`/`tls:`/`https:` configs keep exactly one connection of their own protocol | green | `src/nameserver/tcp_fallback_tests/stream_configs_unchanged.rs` |
| C4 | R4: `ResolverOpts.tcp_fallback`, `true` in `Default`; `false` gives UDP only | green | `src/resolver/tcp_fallback_tests/opts_tcp_fallback.rs` |
| C5 | R5: `--no-tcp-fallback` sets `tcp_fallback = false` for every resolver; help text says so; loop then shows `response was truncated` | green | `src/app/mhost/tcp_fallback_tests/cli_flag_help.rs` |
| C6 | udp config, fallback on → connections [Udp 5353, Tcp 5353] | green | `src/nameserver/tcp_fallback_tests/udp_fallback_on.rs` |
| C7 | udp config, fallback off → connections [Udp 5353] | green | `src/nameserver/tcp_fallback_tests/udp_fallback_off.rs` |
| C8 | tcp config, fallback on → connections [Tcp 5353] | green | `src/nameserver/tcp_fallback_tests/tcp_fallback_on.rs` |
| C9 | `ResolverOpts::default().tcp_fallback` is `true` | green | `src/resolver/tcp_fallback_tests/opts_default.rs` |
| C10 | `--no-tcp-fallback lookup example.com` → `tcp_fallback` false; without flag true | green | `src/app/mhost/tcp_fallback_tests/cli_flag.rs` |
| C11 | fake ns: UDP answers TC, TCP answers 3 TXT → lookup returns the 3 TXT records | green | `src/resolver/tcp_fallback_tests/truncated_udp_falls_back.rs` |
| C12 | fake ns: UDP answers without TC → TCP listener gets no connection | green | `src/resolver/tcp_fallback_tests/udp_answer_needs_no_tcp.rs` |
| C13 | fake ns: UDP TC, `tcp_fallback = false` → error containing `response was truncated`, no TCP connection | green | `src/resolver/tcp_fallback_tests/no_fallback_keeps_truncation.rs` |
| C14 | network: loop command prints TXT records and `✓ No errors occurred.` (behavioural check) | green | `src/app/mhost/tcp_fallback_tests/cli_lookup_falls_back.rs` |
| C15 | network: loop with `--no-tcp-fallback` shows `response was truncated` (behavioural check) | green | `src/app/mhost/tcp_fallback_tests/cli_no_fallback.rs` |

### Runs

| group | coder runs | green by | tokens | seconds |
|---|---|---|---|---|
| G1 (C1–C15) | 1 | sonnet | 35326 | 62 |

### Reader

none: review reads this range

### Behavioural verification

```
$ ./target/debug/mhost --no-color --show-errors -S -s udp:8.8.8.8 lookup -t TXT microsoft.com.
▸ Received 1 responses with 62 RR [62 TXT], 0 Nx, 0 Err in (min 27, max 27) ms from 1 server within 29 ms of total run time.
✓ No errors occurred.

$ ./target/debug/mhost --no-color --show-errors --no-tcp-fallback -S -s udp:8.8.8.8 lookup -t TXT microsoft.com.
▸ Received 0 responses with 0 RR [], 0 Nx, 1 Err [0 TO, 0 QR, 0 SF, 1 O] in (min -, max -) ms from 0 servers within 19 ms of total run time.
 ∙ resolver error: response was truncated; TCP already tried or no other transport available (1 times)

$ ./target/debug/mhost --no-color --show-errors lookup -t TXT microsoft.com.   (system resolvers, reporter's path)
▸ Received 2 responses with 124 RR [124 TXT], 0 Nx, 0 Err in (min 39, max 50) ms from 2 servers within 50 ms of total run time.
✓ No errors occurred.

$ ./target/debug/mhost --help | rg -A1 no-tcp-fallback
      --no-tcp-fallback
          Does not retry truncated UDP answers over TCP
```

Note: the coder's `cargo fmt` reformatted five committed test files; they were restored from HEAD
and their formatting lands in a separate test commit with `ADLC-Test-Change` trailers.

## Phase 2 — mhost retries truncated UDP answers over its own TCP resolver

### Criteria

| id | criterion | status | test file |
|---|---|---|---|
| C1 | R6: udp: config UDP-only in hickory; with tcp_fallback a TCP-only resolver for same IP/port retries a truncated lookup once; every query starts over UDP | green | `src/resolver/tcp_fallback_tests/retry_once_per_lookup.rs` |
| C2 | R7: failed TCP retry → `ResolveError` text starting `response was truncated; TCP retry failed: ` + TCP error; counts as other, not timeout | green | `src/resolver/tcp_fallback_tests/tcp_retry_failure_is_not_timeout.rs` |
| C3 | R8: tcp_fallback off, or tcp:/tls:/https: → no TCP-only resolver; truncated answer ends in today's error | green | `src/resolver/tcp_fallback_tests/no_retry_resolver_without_fallback.rs` |
| C4 | udp config converted, fallback on or off → connections [Udp 5353] only | green | `src/nameserver/tcp_fallback_tests/*.rs, src/resolver/tcp_fallback_tests/opts_tcp_fallback.rs` |
| C5 | Resolver for udp: with fallback on holds a TCP-only resolver; off or tcp: config → none | green | `src/resolver/tcp_fallback_tests/tcp_retry_resolver.rs` |
| C6 | fake ns: TXT truncated, A drop dropped, others answered over UDP; TCP answers all → TCP saw exactly one query (TXT), A after answered over UDP | green | `src/resolver/tcp_fallback_tests/udp_stays_after_timeout.rs` |
| C7 | fake ns: UDP truncates, TCP accepts never answers, timeout 1 s → ResolveError starting `response was truncated; TCP retry failed: request timed out`, not Timeout | green | `src/resolver/tcp_fallback_tests/tcp_retry_timeout.rs` |
| C8 | fake ns: UDP truncates, no TCP listener → error starting `response was truncated; TCP retry failed: ` | green | `src/resolver/tcp_fallback_tests/tcp_retry_refused.rs` |
| C9 | Phase 1 fake-ns scenarios still pass against Phase 2 | green | `Phase 1 fake-ns tests (truncated_udp_falls_back, large_answer_over_tcp, udp_answer_needs_no_tcp, no_fallback_keeps_truncation)` |
| C10 | network loop with/without `--no-tcp-fallback` (behavioural check) | green | `src/app/mhost/tcp_fallback_tests/cli_lookup_falls_back.rs, cli_no_fallback.rs` |

### Runs

| group | coder runs | green by | tokens | seconds |
|---|---|---|---|---|
| G1 (C1–C10) | 3 | stuck → green after a test fix | 65709 | 166 |

The coder ended red on one test (`tcp_retry_failure_is_not_timeout`) whose setup was wrong: it left
`abort_on_error` at its default `true`, so the breaker stopped on the (correct) non-timeout error,
and its fake ns had no TXT records for the second lookup. Both fixed in the test (`a43d6be`,
`ADLC-Test-Change`); production code unchanged after that, suite green twice.

Coder deviations from the plan, kept: the UDP resolver runs with hickory `attempts = 0` when a TCP
retry resolver exists and `single_lookup` does the UDP retries itself, skipping `Truncated`
(hickory's `RetryDnsHandle` would resend a truncated query over UDP); the TCP retry resolver has
`cache_size = 0`.

### Reader

none: review reads this range

### Behavioural verification

```
$ ./target/debug/mhost --no-color --show-errors -S -s udp:8.8.8.8 lookup -t TXT microsoft.com.
▸ Received 1 responses with 62 RR [62 TXT], 0 Nx, 0 Err in (min 38, max 38) ms from 1 server within 39 ms of total run time.
✓ No errors occurred.

$ ./target/debug/mhost --no-color --show-errors --no-tcp-fallback -S -s udp:8.8.8.8 lookup -t TXT microsoft.com.
▸ Received 0 responses with 0 RR [], 0 Nx, 1 Err [0 TO, 0 QR, 0 SF, 1 O] in (min -, max -) ms from 0 servers within 9 ms of total run time.
 ∙ resolver error: response was truncated; TCP already tried or no other transport available (1 times)

$ ./target/debug/mhost --no-color --show-errors lookup -t TXT microsoft.com.   (system resolvers)
▸ Received 2 responses with 124 RR [124 TXT], 0 Nx, 0 Err in (min 10, max 31) ms from 2 servers within 32 ms of total run time.
✓ No errors occurred.

$ ./target/debug/mhost --no-color --show-errors --timeout 2 -S -s udp:127.0.0.1:5399 lookup -t TXT example.com.   (no server: plain timeout, no truncation text)
▸ Received 0 responses with 0 RR [], 0 Nx, 1 Err [1 TO, 0 QR, 0 SF, 0 O] in (min -, max -) ms from 0 servers within 2003 ms of total run time.
 ∙ request timed out (1 times)
```

### Checks to build

- `cargo fmt --check` over the test files staged in a failing-tests commit (`ADLC-Baseline`), in the pre-commit hook or `adlc check`: writer output here needed a later format-only test commit (`01fa327`).
