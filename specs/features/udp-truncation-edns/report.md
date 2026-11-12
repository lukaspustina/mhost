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
