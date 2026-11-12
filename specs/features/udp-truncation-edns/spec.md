# Spec: TCP fallback for truncated UDP answers

Status: Ready for Implementation
Created: 2026-11-12

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
3. No new behaviour when TCP to the server is blocked: the lookup still ends in the truncation
   error, as today.
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
2. By default a `udp:` nameserver config is handed to hickory with two connections on its port:
   UDP first, TCP second. UDP stays the transport of every query; TCP is used only after a
   truncated response (agent default, confirmed by operator, 2026-11-12).
3. `tcp:`, `tls:` and `https:` nameserver configs keep exactly one connection of their own
   protocol: no UDP is added to them (agent default, confirmed by operator, 2026-11-12).
4. `ResolverOpts` carries a public `tcp_fallback: bool`, `true` in `Default`; with `false` a
   `udp:` nameserver is handed to hickory with its UDP connection only, as before this fix
   (operator, 2026-11-12).
5. The global flag `--no-tcp-fallback` sets `tcp_fallback = false` for every resolver of the run,
   system and predefined nameservers included; its `--help` text says that truncated UDP answers
   are then not retried over TCP. With the flag, the loop command of requirement 1 prints the
   error count line containing `response was truncated` and no TXT record (operator, 2026-11-12).

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

## Open decisions

None.

## Out of scope

- Diagnosis, loop output and refuted hypotheses: `specs/features/udp-truncation-edns/bug.md`.
- Raw query TCP fallback: `src/resolver/raw.rs` (already present).
