# Intent: tcp-fallback-followups

Follow-ups of `udp-truncation-edns` (#797, PR #801), taken in from its review: deferred ids
`udp-truncation-edns/review-1` and `udp-truncation-edns/review-2`.

## Problem

1. **review-2 — the request estimate ignores the TCP retry.** `Resolver::estimate`
   (`src/estimate.rs`, `max = names * types * (1 + retries)`) predates the mhost-side TCP retry.
   `single_lookup` (`src/resolver/lookup.rs`) now sends a second query over `Resolver::tcp_retry`
   whenever a UDP answer is truncated, so `mhost -s udp:<ns> lookup -t TXT <large RRset>` prints
   "Sending 1 request …" (min == max == 1) and then sends two. With `--retries N` the TCP resolver
   retries too, so up to 1 + (N + 1) requests go out against a printed maximum of N + 1.
2. **review-1 — `--no-tcp-fallback` does not reach the raw query paths.** `trace`, `dnssec` and
   the `check` DNSSEC lint send raw queries (`src/resolver/raw.rs`, `raw_query` /
   `raw_dnssec_query`) that fall back to TCP on TC unconditionally. The flag's help says truncated
   UDP answers are not retried over TCP, which is false for those commands.

## Proposed outcome

- The printed estimate's maximum counts the possible TCP retry for every `udp:` resolver that has
  one (`tcp_fallback` on); the minimum stays the UDP-only count. `tcp:`/`tls:`/`https:` resolvers
  and `--no-tcp-fallback` runs keep today's estimate.
- With `--no-tcp-fallback`, the raw paths (`trace`, `dnssec`, the DNSSEC lint of `check`) report a
  truncated UDP answer as truncated instead of retrying over TCP; without the flag they behave as
  today. The flag's help text matches what it does across all commands.

## Affected users and systems

CLI users of `lookup`, `trace`, `dnssec`, `check` and `discover`; library callers of
`resolver::raw` (crate-private) and `Estimate`. Not affected: the default behaviour of every
command without `--no-tcp-fallback`.

## Constraints

- Offline, deterministic tests: reuse the fake nameserver in
  `src/resolver/tcp_fallback_tests/fake_ns.rs` (it binds loopback sockets; run cargo outside a
  sandbox that forbids local binding).
- No hickory type in the public API; `resolver::raw` stays `pub(crate)`.
- Only `example.com` names in test data.
