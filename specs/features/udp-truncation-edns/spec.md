# Spec: TCP fallback for truncated UDP answers

Status: Done
Created: 2026-11-12
Finished: 2026-11-12

## Goal

A lookup through a `udp:` nameserver, including the system resolvers read from resolv.conf, whose
answer comes back truncated is retried over TCP to the same server and returns the records: the
loop in `bug.md` (`mhost ... -s udp:8.8.8.8 lookup -t TXT microsoft.com.`) prints the TXT records
and no `response was truncated` error. This is the RFC-conforming default (RFC 2181 §9: a client
that receives TC re-queries over a transport that allows larger replies; RFC 7766 §5 / RFC 9210:
DNS implementations support TCP). For diagnosis, the global flag `--no-tcp-fallback` keeps every
`udp:` nameserver on UDP alone, so a truncated answer stays visible as such. Source: GitHub issue #797.

## Non-goals

1. No configurable EDNS payload size and no new CLI flag: hickory 0.26 already sends EDNS with
   1232 bytes, and the reported answer (4782 bytes) needs TCP at any payload size.
2. No change to `src/resolver/raw.rs`: its non-recursive and DNSSEC queries already fall back to
   TCP on TC.
3. No retry over another server or another transport than TCP to the same IP and port. (Until
   2026-11-12 this line read "no new behaviour when TCP is blocked"; review F2 showed the Phase 1
   design broke it, and requirement 7 now states what a failed TCP retry reports.)
4. No EDNS switches (payload size, EDNS off) and no display of EDNS values: a later feature
   (operator, 2026-11-12).
5. No per-nameserver fallback parameter (e.g. `udp:...,tcp_fallback=false`): the global flag
   covers the diagnosis case, including system and predefined nameservers (operator, 2026-11-12).

## Context and constraints

- Rust, hickory-resolver/-proto 0.26.3; no new dependency. Hickory types stay crate-private
  (`to_proto` is `pub(crate)`).
- The test contract is `just adlc-verify` (fmt-check, clippy, offline lib and doc tests). New tests
  must be offline and deterministic: no query to a public resolver, no real domain other than
  `example.com` in test data.
- hickory's `NameServerPool` retries a truncated UDP response on the same server with UDP
  disabled (`name_server_pool.rs:388-392`); it needs a non-UDP `ConnectionConfig` on that server
  to have somewhere to go. hickory's own `NameServerConfig::udp_and_tcp` builds that pair.
- TCP for every query is not acceptable: public nameservers rate-limit TCP (issue #797).
- Review F1/F2 (`review.md`, range `130ec9d..5334bb7`): with UDP and TCP on one hickory nameserver,
  a UDP timeout marks the UDP connection failed and hickory then reuses the open TCP connection for
  every later query (`name_server.rs` `connected_mut_client`); and a TCP failure after a truncated
  answer replaces the truncation error (`name_server_pool.rs` `most_specific`). Phase 2 therefore
  keeps the UDP nameserver UDP-only and does the TCP retry in mhost through a separate TCP-only
  hickory resolver.
- The CLI builds `ResolverOpts` in `load_resolver_opts` (`src/app/mhost/resolver.rs`); global
  resolver flags live in `src/app/mhost/cli_parser.rs` next to `--retries` and `--timeout`.
  `ResolverOpts` is a public struct with public fields, so a new field is a library API change
  (pre-1.0, called out in the changelog).
- The fallback setting must reach `NameServerConfig::to_proto`, which today sees only the
  nameserver config; `Resolver::new` holds both and is where they meet.

## Requirements

1. `cargo build && ./target/debug/mhost --no-color --show-errors -S -s udp:8.8.8.8 lookup -t TXT microsoft.com.`,
   run from the repository root with network access, prints a `Received 1 responses with <n> RR [<n> TXT]`
   line with `<n>` > 0 and `✓ No errors occurred.`, and no line containing `response was truncated`.
2. Superseded by requirement 6 (review F1, operator, 2026-11-12). It read: by default a `udp:`
   nameserver config is handed to hickory with two connections on its port, UDP first, TCP
   second; UDP stays the transport of every query.
3. `tcp:`, `tls:` and `https:` nameserver configs keep exactly one connection of their own
   protocol: no UDP is added to them (agent default, confirmed by operator, 2026-11-12).
4. `ResolverOpts` carries a public `tcp_fallback: bool`, `true` in `Default`; with `false` a
   `udp:` nameserver is handed to hickory with its UDP connection only, as before this fix
   (operator, 2026-11-12).
5. The global flag `--no-tcp-fallback` sets `tcp_fallback = false` for every resolver of the run,
   system and predefined nameservers included; its `--help` text says that truncated UDP answers
   are then not retried over TCP. With the flag, the loop command of requirement 1 prints the
   error count line containing `response was truncated` and no TXT record (operator, 2026-11-12).
6. A `udp:` nameserver is handed to hickory with its UDP connection only, whatever `tcp_fallback`
   says. With `tcp_fallback` on, the `Resolver` also holds a TCP-only hickory resolver for the same
   IP and port, and a lookup whose UDP query ends in hickory's truncation error is repeated once
   over it. Every query starts over UDP, also after an earlier UDP timeout or an earlier truncated
   answer (review F1; operator, 2026-11-12).
7. When that TCP retry fails, the lookup's error is `Error::ResolveError` whose text starts with
   `response was truncated; TCP retry failed: ` followed by the TCP error's text (for example
   `request timed out`). It counts as an other error, not as a timeout, so abort-on-timeout does not
   fire on it (review F2; agent default, confirmed by operator, 2026-11-12).
8. With `tcp_fallback` off, or for `tcp:`, `tls:` and `https:` nameservers, no TCP-only resolver
   exists; a truncated UDP answer ends in today's truncation error (agent default, confirmed by
   operator, 2026-11-12).

## Phases

## Phase 1 — UDP nameservers fall back to TCP on truncation

**Depends on:** none
**Requirements:** 1, 2, 3, 4, 5

`NameServerConfig::to_proto` (`src/nameserver/mod.rs`) gives a `Udp` config a TCP connection on
the same port after its UDP connection when `ResolverOpts::tcp_fallback` is set (the default); the
other variants are unchanged. `--no-tcp-fallback` clears it in `load_resolver_opts`. Because the
system resolvers become `Udp` configs, the reporter's case takes the same path. Demonstrable locally with
the loop command; the tests reach the behaviour offline through two seams: `to_proto`'s connection
list, and a `Resolver` lookup against a local fake server on `127.0.0.1` whose UDP socket answers
with TC set and whose TCP listener on the same port returns the full answer.

### Test Scenarios

GIVEN `NameServerConfig::udp((127.0.0.1, 5353))` and fallback on WHEN it is converted for hickory THEN its `connections` are `[Udp port 5353, Tcp port 5353]` in that order.
GIVEN `NameServerConfig::udp((127.0.0.1, 5353))` and fallback off WHEN it is converted for hickory THEN its `connections` are `[Udp port 5353]` only.
GIVEN `NameServerConfig::tcp((127.0.0.1, 5353))` and fallback on WHEN it is converted for hickory THEN its `connections` are `[Tcp port 5353]` only.
GIVEN `ResolverOpts::default()` WHEN `tcp_fallback` is read THEN it is `true`.
GIVEN the CLI arguments `--no-tcp-fallback lookup example.com` WHEN `load_resolver_opts` builds the options THEN `tcp_fallback` is `false`; without the flag it is `true`.
GIVEN a local fake nameserver on `127.0.0.1:<port>` whose UDP socket answers a TXT query for `example.com.` with TC set and no answer, and whose TCP listener on the same port answers with three TXT records WHEN a `Resolver` for `udp:127.0.0.1:<port>` looks up `TXT example.com.` THEN the lookup is a response with those three TXT records, not an error.
GIVEN the same fake nameserver whose UDP socket answers without TC WHEN the same lookup runs THEN the TCP listener receives no connection.
GIVEN the fake nameserver answering with TC over UDP WHEN a `Resolver` with `tcp_fallback = false` runs the same lookup THEN the lookup is an error whose text contains `response was truncated` and the TCP listener receives no connection.
GIVEN network access WHEN the loop command of requirement 1 runs THEN it prints the TXT records and `✓ No errors occurred.` (behavioural check at the `mhost` binary).
GIVEN network access WHEN the loop command runs with `--no-tcp-fallback` added before `lookup` THEN the error count line contains `response was truncated` (behavioural check at the `mhost` binary).

## Phase 2 — mhost retries truncated UDP answers over its own TCP resolver

**Depends on:** Phase 1
**Requirements:** 6, 7, 8

`NameServerConfig::to_proto` gives a `Udp` config its UDP connection only again. `Resolver::new`
builds, for a `Udp` config with `tcp_fallback` on, a second hickory resolver from a TCP config of
the same IP and port; `single_lookup` (`src/resolver/lookup.rs`) repeats a lookup that ended in
`NetError::Truncated` once over it and maps a failure of that retry to requirement 7's error. The
Phase 1 tests that assert `[Udp, Tcp]` for a `udp:` config change to requirement 6 (with
`ADLC-Test-Change` trailers); the fake nameserver learns per-name UDP behaviour (answer, truncate,
drop), a TCP listener that accepts and never answers, and a log of the queries each transport saw.

### Test Scenarios

GIVEN `NameServerConfig::udp((127.0.0.1, 5353))` WHEN it is converted for hickory, with fallback on or off THEN its `connections` are `[Udp port 5353]` only.
GIVEN a `Resolver` for `udp:127.0.0.1:<port>` with `tcp_fallback` on WHEN it is built THEN it holds a TCP-only resolver for `127.0.0.1:<port>`; with `tcp_fallback` off, or for a `tcp:` config, it holds none.
GIVEN a fake nameserver whose UDP socket truncates `TXT example.com.`, drops `A drop.example.com.` and answers every other A query, and whose TCP listener answers everything WHEN one resolver looks up, in order, `TXT example.com.`, `A before.example.com.`, `A drop.example.com.` (times out) and `A after.example.com.` THEN the TXT records arrive, the TCP listener saw exactly one query (`TXT example.com.`), and `A after.example.com.` was answered over UDP.
GIVEN a fake nameserver whose UDP socket truncates and whose TCP listener accepts but never answers, timeout 1 s WHEN a lookup runs THEN its error is `Error::ResolveError` whose text starts with `response was truncated; TCP retry failed: request timed out`, and it is not `Error::Timeout`.
GIVEN a fake nameserver whose UDP socket truncates and whose port has no TCP listener WHEN a lookup runs THEN its error text starts with `response was truncated; TCP retry failed: `.
GIVEN the Phase 1 fake-nameserver scenarios (truncated answer completed over TCP, large answer, no TCP when UDP suffices, `tcp_fallback = false` keeps the truncation error) WHEN they run against Phase 2 THEN they still pass.
GIVEN network access WHEN the loop command of requirement 1 runs, with and without `--no-tcp-fallback` THEN it prints the TXT records and `✓ No errors occurred.`, respectively the error count line containing `response was truncated` (behavioural check at the `mhost` binary).

## Decision log

- TCP fallback over raising the EDNS payload size: hypothesis 2 refuted it (8.8.8.8 caps UDP at 512 bytes; the answer is 4782 bytes).
- Fix in mhost's config over a mapping change: hypothesis 3 refuted mhost's error mapping as the cause; the error is hickory's `NetError::Truncated`.
- No EDNS change: hypothesis 1 refuted missing EDNS; hickory 0.26 sends EDNS with 1232 bytes by default.
- UDP and TCP on the same server over a separate TCP resolver: hickory's pool retries the same server with UDP disabled, so the TCP connection must sit on that server's config (hypothesis 4, held).
- Offline fake-server test over a lit test against a public resolver: deterministic, no real domain in test data, runs under `just adlc-verify` (agent default, confirmed by operator, 2026-11-12).
- Non-goals 1-3 name no defect (agent default, confirmed by operator, 2026-11-12).
- RFC-conforming TCP fallback as default with a global opt-out over UDP+TCP always: the operator diagnoses UDP-only behaviour and must be able to force it (operator, 2026-11-12).
- Global flag `--no-tcp-fallback` over a per-nameserver parameter or both: covers system and predefined nameservers, matches the existing global resolver flags (operator, 2026-11-12).
- EDNS switches deferred to a later feature over adding them here: the fix does not need them, hickory already sends 1232 bytes (operator, 2026-11-12).
- TCP retry in mhost through a separate TCP-only hickory resolver over UDP+TCP on one hickory nameserver: review F1 (UDP abandoned after one UDP timeout) and F2 (truncation error replaced by the TCP error) are hickory pool behaviour that mhost cannot change (operator, 2026-11-12).
- A failed TCP retry as `ResolveError` with a fixed text prefix over a new `Error` variant: no public enum change, and the text keeps both causes visible (agent default, confirmed by operator, 2026-11-12).

## Open decisions

None.

## Out of scope

- Diagnosis, loop output and refuted hypotheses: `specs/features/udp-truncation-edns/bug.md`.
- Raw query TCP fallback: `src/resolver/raw.rs` (already present).
