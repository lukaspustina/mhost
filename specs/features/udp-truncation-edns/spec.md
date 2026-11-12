# Spec: TCP fallback for truncated UDP answers

Status: Draft
Created: 2026-11-12

## Goal

A lookup through a `udp:` nameserver, including the system resolvers read from resolv.conf, whose
answer comes back truncated is retried over TCP to the same server and returns the records: the
loop in `bug.md` (`mhost ... -s udp:8.8.8.8 lookup -t TXT microsoft.com.`) prints the TXT records
and no `response was truncated` error. Source: GitHub issue #797.

## Non-goals

1. No configurable EDNS payload size and no new CLI flag: hickory 0.26 already sends EDNS with
   1232 bytes, and the reported answer (4782 bytes) needs TCP at any payload size.
2. No change to `src/resolver/raw.rs`: its non-recursive and DNSSEC queries already fall back to
   TCP on TC.
3. No new behaviour when TCP to the server is blocked: the lookup still ends in the truncation
   error, as today.

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

## Requirements

1. `cargo build && ./target/debug/mhost --no-color --show-errors -S -s udp:8.8.8.8 lookup -t TXT microsoft.com.`,
   run from the repository root with network access, prints a `Received 1 responses with <n> RR [<n> TXT]`
   line with `<n>` > 0 and `✓ No errors occurred.`, and no line containing `response was truncated`.
2. A `udp:` nameserver config is handed to hickory with two connections on its port: UDP first,
   TCP second. UDP stays the transport of every query; TCP is used only after a truncated
   response (agent default, pending confirmation).
3. `tcp:`, `tls:` and `https:` nameserver configs keep exactly one connection of their own
   protocol: no UDP is added to them (agent default, pending confirmation).

## Phases

## Phase 1 — UDP nameservers fall back to TCP on truncation

**Depends on:** none
**Requirements:** 1, 2, 3

`NameServerConfig::to_proto` (`src/nameserver/mod.rs`) gives a `Udp` config a TCP connection on
the same port after its UDP connection; the other variants are unchanged. Because the system
resolvers become `Udp` configs, the reporter's case takes the same path. Demonstrable locally with
the loop command; the tests reach the behaviour offline through two seams: `to_proto`'s connection
list, and a `Resolver` lookup against a local fake server on `127.0.0.1` whose UDP socket answers
with TC set and whose TCP listener on the same port returns the full answer.

### Test Scenarios

GIVEN `NameServerConfig::udp((127.0.0.1, 5353))` WHEN `to_proto()` runs THEN its `connections` are `[Udp port 5353, Tcp port 5353]` in that order.
GIVEN `NameServerConfig::tcp((127.0.0.1, 5353))` WHEN `to_proto()` runs THEN its `connections` are `[Tcp port 5353]` only.
GIVEN a local fake nameserver on `127.0.0.1:<port>` whose UDP socket answers a TXT query for `example.com.` with TC set and no answer, and whose TCP listener on the same port answers with three TXT records WHEN a `Resolver` for `udp:127.0.0.1:<port>` looks up `TXT example.com.` THEN the lookup is a response with those three TXT records, not an error.
GIVEN the same fake nameserver whose UDP socket answers without TC WHEN the same lookup runs THEN the TCP listener receives no connection.
GIVEN network access WHEN the loop command of requirement 1 runs THEN it prints the TXT records and `✓ No errors occurred.` (behavioural check at the `mhost` binary).

## Decision log

- TCP fallback over raising the EDNS payload size: hypothesis 2 refuted it (8.8.8.8 caps UDP at 512 bytes; the answer is 4782 bytes).
- Fix in mhost's config over a mapping change: hypothesis 3 refuted mhost's error mapping as the cause; the error is hickory's `NetError::Truncated`.
- No EDNS change: hypothesis 1 refuted missing EDNS; hickory 0.26 sends EDNS with 1232 bytes by default.
- UDP and TCP on the same server over a separate TCP resolver: hickory's pool retries the same server with UDP disabled, so the TCP connection must sit on that server's config (hypothesis 4, held).
- Offline fake-server test over a lit test against a public resolver: deterministic, no real domain in test data, runs under `just adlc-verify` (agent default, pending confirmation).
- Non-goals 1-3 name no defect (agent default, pending confirmation).

## Open decisions

None.

## Out of scope

- Diagnosis, loop output and refuted hypotheses: `specs/features/udp-truncation-edns/bug.md`.
- Raw query TCP fallback: `src/resolver/raw.rs` (already present).
