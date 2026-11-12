
## 130ec9d..5334bb7

### Reader

Range 130ec9dead930fb997602168d16ccccffdd6acfc..5334bb7cd852c80fdcdc03fdfe77b03ee61e0359.

COUNTS blockers=0 majors=2 minors=1
LENSES Engineering, Testing
MAJOR | src/nameserver/mod.rs:339 | Once a truncated answer has opened the standing TCP connection, one UDP timeout makes hickory drop the UDP connection and send every later query of that resolver over TCP, although none of them was truncated; this breaks Requirement 2 ("UDP stays the transport of every query; TCP is used only after a truncated response"). | One resolver for udp:127.0.0.1:<port> against a fake server (UDP: TXT -> TC, A drop.example.com. -> no reply, other A -> answered; TCP answers everything), with lookups in order TXT example.com., A before.example.com., A drop.example.com. (times out), A after1.example.com., A after2.example.com.: the TCP listener logs "A after1.example.com.", "A after2.example.com." and the UDP socket never sees them.
MAJOR | src/nameserver/mod.rs:341 | When the server's TCP port drops SYNs or never answers, a truncated UDP answer now ends as Error::Timeout after the full --timeout, not as the immediate "response was truncated" error that Non-goal 3 promises ("the lookup still ends in the truncation error, as today"). | Fake server whose UDP answers TC and whose TCP listener accepts but never replies, timeout 2 s: with to_proto(false) the TXT lookup fails after 2.5 ms with "response was truncated; TCP already tried or no other transport available"; with to_proto(true), the new default, it fails after 2.006 s with "request timed out", and mhost counts it as TO.
MINOR | src/app/mhost/cli_parser.rs:229 | The global --no-tcp-fallback says truncated UDP answers are not retried over TCP, but trace, dnssec and the check DNSSEC lint send raw queries that still retry over TCP on TC whatever the flag. | `mhost --no-tcp-fallback trace -t TXT <name whose TXT RRset exceeds 512 bytes>`: raw queries carry no EDNS, the final hop's answer comes back TC, and raw_query resends it over TCP (src/resolver/raw.rs:156). The spec's Non-goal 2 and "Out of scope" exclude raw.rs, so this is MINOR.

#### Evidence

**Finding 1, TCP reuse after a UDP timeout.** For a `udp:` config the change hands hickory a TCP
connection config next to the UDP one:

```quote src/nameserver/mod.rs:339
            NameServerConfig::Udp { .. } if tcp_fallback => vec![
                ConnectionConfig::new(ProtocolConfig::Udp),
                ConnectionConfig::new(ProtocolConfig::Tcp),
            ],
```

How hickory-resolver 0.26.3 (`name_server.rs`) behaves:

- `send_inner` marks a connection `Status::Failed` on a transport error, and a UDP timeout is one.
- `connected_mut_client` first keeps only connections in the `Init` or `Established` state. It then
  reuses the best surviving connection that the policy allows. It creates a new connection, which
  would prefer UDP, only when none survives.

After a truncation the TCP connection is `Established`. A later UDP timeout removes the UDP
connection, so every following query, including hickory's own retry of the query that timed out,
reuses TCP until the server closes it. The spec requires the opposite:

```quote specs/features/udp-truncation-edns/spec.md:53
   UDP first, TCP second. UDP stays the transport of every query; TCP is used only after a
```

I checked this with a scratch crate outside the repository, built on the locked hickory-resolver
0.26.3. It copies `NameServerConfig::to_proto(true)` and `ResolverOpts::to_proto` (attempts 0,
5 concurrent requests, hosts file off) and runs against a loopback fake server. Output:

```
lookup TXT example.com.: ok 1 records
lookup A before.example.com.: ok 1 records
lookup A drop.example.com.: err request timed out
lookup A after1.example.com.: ok 1 records
lookup A after2.example.com.: ok 1 records
udp saw: ["TXT example.com.", "A before.example.com.", "A drop.example.com.", "A drop.example.com.", "A drop.example.com."]
tcp saw: ["TXT example.com.", "A after1.example.com.", "A after2.example.com."]
```

Where it shows in mhost: a `Resolver` is reused across lookups by `check`, `discover`, the other
modules that run several lookups, and library callers, and so is any multi-record lookup under
`--continue-on-timeout`. Such a resolver switches to TCP after a single lost UDP packet that
follows a truncation. The fix's tests cannot catch this: `udp_answer_needs_no_tcp.rs` covers only
a clean UDP answer with no earlier truncation.

**Finding 2, blocked TCP turns the truncation into a timeout.** The added TCP connection is what
hickory tries after TC:

```quote src/nameserver/mod.rs:341
                ConnectionConfig::new(ProtocolConfig::Tcp),
```

The path through hickory 0.26.3:

1. A SYN-dropping firewall makes hickory-net's `connect_tcp` give up after `options.timeout` with
   `io::ErrorKind::TimedOut`, which `From<io::Error> for NetError` maps to `NetError::Timeout`.
   A TCP peer that accepts and then stays silent ends in `NetError::Timeout` from the multiplexer.
2. In `name_server_pool.rs` the pool treats `Timeout` as a reason to try another server, and
   `most_specific(Truncated, Timeout)` returns `Timeout`.
3. With no server left, the pool returns `Timeout`. Before this change, the second pass found no
   server allowed under `disable_udp` and returned `Truncated` at once.

The spec says:

```quote specs/features/udp-truncation-edns/spec.md:22
3. No new behaviour when TCP to the server is blocked: the lookup still ends in the truncation
```

Scratch-crate probe, same setup as above, with UDP always answering TC and the TCP listener
accepting without replying, timeout 2 s:

```
== experiment 3: TCP accepted but never answered, tcp_fallback=false
lookup TXT example.com. after 2.475709ms: err response was truncated; TCP already tried or no other transport available
== experiment 3: TCP accepted but never answered, tcp_fallback=true
lookup TXT example.com. after 2.005893958s: err request timed out
```

`Error::from_net` maps this to `Error::Timeout`, so the summary line reports `1 Err [1 TO, ...]`
instead of the truncation error, after `--timeout` seconds per attempt. The breaker then applies
`abort_on_timeout`, not `abort_on_error`. No test covers a TC answer whose TCP retry cannot
complete.

**Finding 3, the global flag does not reach raw queries.** The help text is shown for every
subcommand:

```quote src/app/mhost/cli_parser.rs:229
                .help("Does not retry truncated UDP answers over TCP"),
```

The raw query path that `trace` (`raw::parallel_raw_queries`), `dnssec` and the `check` DNSSEC lint
use retries over TCP unconditionally and never reads `tcp_fallback`:

```quote src/resolver/raw.rs:156
    if response.is_truncated() {
```

`build_query_message` sets no EDNS on non-DNSSEC raw queries, so any final-hop answer over 512 bytes
is truncated, and with `--no-tcp-fallback` it is still fetched over TCP. The spec declares raw.rs
out of scope (Non-goal 2, "Out of scope"), hence MINOR.

#### Traced and found sound

- `load_resolver_opts` passes `tcp_fallback` through both branches, including
  `--use-system-resolv-opt` via `..app_config_opts`.
- `Resolver::new` and `new_for_test` forward `opts.tcp_fallback`. No other caller of
  `to_proto(..)` exists.
- TCP, TLS and HTTPS configs keep one connection on their own port.
- hickory prefers UDP over TCP for new connections whatever the config order.
- With `tcp_fallback = false` the pool returns `Truncated` without touching TCP.
- All 18 new tests are collected by `cargo test --lib --all-features -- --list`.
### Spec reader

COUNTS blockers=0 majors=0 minors=0
REQUIREMENTS met=5 partial=0 missed=0 contradicted=0

I traced a `udp:` config with `tcp_fallback = true`. `NameServerConfig::to_proto` (src/nameserver/mod.rs:335) gives it `[Udp, Tcp]` on its own port, and hickory 0.26.3 retries a TC response with UDP disabled while preferring an existing UDP connection afterwards (`name_server_pool.rs:388-391`, `name_server.rs:913-915`), so R1 and R2 hold. `tcp:`/`tls:`/`https:` keep exactly one connection of their own protocol (R3). `ResolverOpts::tcp_fallback` is public and `true` in `Default`; `Resolver::new` passes it to `to_proto` (R4). `--no-tcp-fallback` is `.global(true)` with help "Does not retry truncated UDP answers over TCP", becomes `AppConfig::tcp_fallback` and then `load_resolver_opts`, including the `--use-system-resolv-opt` merge. Every CLI resolver, system ones included, is built from that output via `AppResolver::create_resolvers`/`from_configs` (R5). I found no unrequested behaviour. Rules 1 and 2 report nothing because the spec directory holds `bug.md` (Rule 3). The network loop command could not run here: the sandbox gave `no connections available`. R1 therefore rests on the code trace, the offline CLI-level fake-server test `src/app/mhost/tcp_fallback_tests/cli_lookup_falls_back.rs`, and the output recorded in report.md.

### Refutation

F1 | src/nameserver/mod.rs:339 | CONFIRMED — hickory name_server.rs send_inner sets Status::Failed on a UDP timeout; connected_mut_client then retains only Init/Established connections, so the UDP state is dropped. select_connection picks from what is left (only the TCP state) and reuses it. UDP is not reconnected while a TCP connection exists, so later queries go over TCP and Requirement 2 breaks — confidence 8 — fix right (a hickory-side change is not available: have mhost handle NetError::Truncated itself, or accept and document the drift) — class UDP failure on a dual-connection udp: resolver after TCP was opened; neighbours UDP io error (Status::Failed) with TCP already open; QueryCaseMismatch sets disable_udp for that request only (not persistent) — new
F2 | src/nameserver/mod.rs:341 | CONFIRMED — hickory name_server_pool.rs: truncated response sets disable_udp and err=Truncated, then retries the same server; the TCP attempt that times out returns Timeout, which replaces Truncated. With a TCP port that drops SYNs or never replies, the lookup ends after the full timeout as Timeout, not as the truncation error Non-goal 3 promises — confidence 8 — fix right (map a TCP failure after truncation back to the truncation error, or amend Non-goal 3 and the text of the --no-tcp-fallback help) — class TCP failure after truncated UDP answer; neighbours TCP connection refused (Io error, still replaces Truncated); TCP answer also truncated (stays Truncated); TCP reset mid-query — new

### Calibration

| finding | refuter answer | confidence | result | command |
|---|---|---|---|---|
| F1 | CONFIRMED | 8 | held | `sed -n 150,210p` and `sed -n 258,300p` of hickory-resolver-0.26.3/src/name_server.rs: any send error (timeout included) sets `Status::Failed`; `connected_mut_client` drops it and `select_connection` reuses the open TCP connection |
| F2 | CONFIRMED | 8 | held | `sed -n 405,462p` of hickory-resolver-0.26.3/src/name_server_pool.rs: `most_specific(Truncated, Timeout)` returns `Timeout`; `Io` likewise replaces `Truncated` |

### Findings

F1 | MAJOR | src/nameserver/mod.rs:339 | UDP failure on a dual-connection udp: resolver after TCP was opened | open
F2 | MAJOR | src/nameserver/mod.rs:341 | TCP failure after truncated UDP answer | open

### Summary

- Reader (opus, xhigh): before refutation 0/2/1 (blockers/majors/minors), after 0/2/1. LENSES Engineering, Testing.
- Spec reader: 0/0/0; REQUIREMENTS met=5 partial=0 missed=0 contradicted=0.
- verified 2, held 2. MAJORs F1, F2 stay open (round 1: majors are not fixed by review). MINOR deferred.
- Roll call: no principles declared.

## 130ec9d..d3967d3

### Reader

```
COUNTS blockers=0 majors=1 minors=0
LENSES Engineering, Testing
MAJOR | src/estimate.rs:45 | The request estimate printed before a lookup does not count the new TCP retry, so its exact count understates what is sent whenever a UDP answer is truncated | `mhost -s udp:8.8.8.8 lookup -p -t TXT microsoft.com.` with the default `--retries 0` prints "Sending 1 request to 1 nameserver for 1 record type of 1 name." (min == max == 1), then `single_lookup` sends the UDP query and, on `NetError::Truncated`, a second query over the TCP retry resolver (src/resolver/lookup.rs:683); with `--retries N` the TCP resolver has `attempts = N` as well, so up to 1 + (N+1) requests can go out against a printed maximum of N+1
```

```quote src/estimate.rs:45
        let max_lookups = query.names.len() * query.record_types.len() * (1 + self.opts.retries);
```

```quote src/resolver/lookup.rs:683
        (Err(NetError::Truncated), Some(tcp)) => {
```

What I traced and found sound:

- The truncation path with hickory 0.26.3: with a UDP-only nameserver, `NameServerPool::try_send` sets `disable_udp` on a TC response, the server then fails `allows_server`, and the pool returns `Err(NetError::Truncated)`, which matches the `(Err(NetError::Truncated), Some(tcp))` arm.
- Moving the UDP retries into mhost: hickory's `RetryDnsHandle` retries every error except `NoConnections`, `NoRecordsFound` and `DnssecBogus`, and it retries `Truncated` too. `build_resolvers` sets `attempts = 0` only when a TCP retry resolver exists, and the loop in `single_lookup` sends 1 + `retries` requests. It excludes the same three errors plus `Truncated`. This matches hickory's count except for `Busy`, which hickory does not count as an attempt and mhost does. That only bounds a loop that hickory leaves unbounded.
- When the TCP retry fails, the `LookupResult::Error` becomes `ResolveError` with the required prefix, so the breaker and the statistics count it as an other error, not a timeout. An NxDomain or a response from TCP passes through unchanged.
- Every app module builds its resolvers through `AppResolver` and `load_resolver_opts`, so `--no-tcp-fallback` reaches every one of them, including the `--use-system-resolv-opt` branch (`..app_config_opts`). No code outside `single_lookup` calls `Resolver.inner` directly.
- The tests in `src/resolver/tcp_fallback_tests/`, `src/nameserver/tcp_fallback_tests/` and `src/app/mhost/tcp_fallback_tests/` all run offline against the loopback fake nameserver or temp files. Each assertion checks an outcome (records, error text, per-transport query log), not a mock call.
### Spec reader

COUNTS blockers=0 majors=0 minors=0
REQUIREMENTS met=8 partial=0 missed=0 contradicted=0

I traced a `udp:` nameserver through `NameServerConfig::to_proto` (UDP connection only, in every case), `tcp_retry_resolver` and `build_resolvers` in `src/resolver/mod.rs` (a TCP-only resolver on the same IP and port, built only for `Udp` with `tcp_fallback`, so none for `tcp:`/`tls:`/`https:` or `--no-tcp-fallback`), and `single_lookup` in `src/resolver/lookup.rs` (one TCP retry after `NetError::Truncated`; a failed retry becomes `ResolveError { reason: "response was truncated; TCP retry failed: <TCP error>" }`, which `create_breaker` treats as an other error rather than a timeout). I also traced `--no-tcp-fallback` from `AppConfig` through `load_resolver_opts` into every `AppResolver` path, system resolvers included. I found no divergence from requirements 1-8: requirement 2 is superseded by requirement 6 and counts as met. Rule 3 applies because the spec directory holds `bug.md`, so the phase shape is not judged.

### Refutation

F1 | src/estimate.rs:45 | CONFIRMED — Resolver::estimate ignores `tcp_retry`; single_lookup (lookup.rs:682-700) sends a second query via the TCP resolver (attempts = retries, so up to retries+1 more) after Truncated, and console.rs:95-108 prints min==max as an exact count; max stays 1+retries — confidence 7 — fix right (raise max_requests by names*types*(1+retries) when `self.tcp_retry.is_some()`, keep min) — class estimate/accounting of requests not updated for a new request path; neighbours the retries-loop for UDP (retries now driven in single_lookup, count unchanged); Mode::Uni/Multi group sums reuse the per-resolver estimate; print_whois_estimates is separate and unaffected — new

### Calibration

| finding | refuter answer | confidence | result | command |
|---|---|---|---|---|
| F1 | CONFIRMED | 7 | held | `sed -n 30,52p src/estimate.rs` (max = names*types*(1+retries), no TCP term) and `sed -n 678,700p src/resolver/lookup.rs` (a second query over `tcp_retry` after `Truncated`) |

### Findings

F1 | MAJOR | src/estimate.rs:45 | estimate/accounting not updated for a new request path | open

### Summary

- Reader (opus, high): before refutation 0/1/0, after 0/1/0. Spec reader: 0/0/0; REQUIREMENTS met=8 partial=0 missed=0 contradicted=0.
- verified 1, held 1. F1 (request estimate ignores the TCP retry) stays open: round 2, majors are not fixed by review.
- Round 1's F1 and F2 are addressed by Phase 2 (requirements 6 and 7); this reading found neither again.
- Roll call: no principles declared.
