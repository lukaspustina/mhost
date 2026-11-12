# Spec: tcp-fallback-followups

Status: Done
Created: 2026-11-12
Finished: 2026-11-12

## Goal

The printed request estimate's maximum counts the TCP retry `single_lookup` may send for every
resolver that has a `tcp_retry` resolver, while the minimum and every other resolver's estimate stay
as today; and with `--no-tcp-fallback` the raw query paths (`trace`, `dnssec`, the DNSSEC lint of
`check`) open no TCP connection on a truncated UDP answer but turn it into a `truncated` error, while
without the flag they still complete the answer over TCP.

## Non-goals

- `dnssec` and the `check` DNSSEC lint do not start showing raw query errors other than truncation to the user.
- The TCP retry resolver keeps hickory's `attempts = retries`; this feature counts those attempts, it does not change them.
- `trace` and `dnssec` get no option to start at a nameserver other than the root servers.
- The README help block's wording ("Do not retry …") is not aligned with the clap help ("Does not retry …").
- WHOIS and download estimates (`print_whois_estimates`, `print_download_estimates`) stay unchanged.

## Context and constraints

- `Estimation { min_requests, max_requests }`; `impl Estimate for Resolver` computes
  `min = names * record_types`, `max = names * record_types * (1 + opts.retries)`
  (`src/estimate.rs:19-22`, `src/estimate.rs:42-52`). `ResolverGroup` sums resolvers in `Mode::Multi`
  (respecting `limit`) and takes the first in `Mode::Uni` (`src/estimate.rs:54-67`).
- `Console::print_lookup_estimates` prints "N request(s)" when min == max, else
  "between {min} and {max} requests" (`src/app/mhost/console.rs:89-131`).
- `single_lookup`: with `tcp_retry` present, UDP retries up to `opts.retries` times on errors other
  than `Truncated | NoConnections | NoRecordsFound | DnssecBogus`, and a truncated UDP answer triggers
  one `tcp.lookup` (`src/resolver/lookup.rs:665-692`). The TCP resolver is built with
  `opts.to_proto()`, so hickory makes up to `1 + retries` TCP attempts (`src/resolver/mod.rs:473`).
  Worst case per (name, type) without CNAME chasing: `1 + retries` UDP requests then `1 + retries`
  TCP requests. hickory follows a CNAME-only answer with further queries (depth limit 8), which no
  estimate counts today either.
- `tcp_retry_resolver` returns `Some` only for a `NameServerConfig::Udp` nameserver with
  `opts.tcp_fallback` (`src/resolver/mod.rs:192-204`).
- `raw_query` / `raw_dnssec_query` retry over TCP whenever `response.is_truncated()`, with no
  option (`src/resolver/raw.rs:148-162`, `:189-203`); `RawError` has no truncation variant
  (`src/resolver/raw.rs:63-72`). Parallel wrappers: `parallel_raw_queries` (`:166`),
  `parallel_raw_dnssec_queries` (`:207`).
- Raw callers: `trace` (`src/app/mhost/modules/trace/trace.rs:165`; an `Err` becomes
  `ServerOutcome::Error(e.to_string())`, `trace.rs:352-361`; printed as `Error: <msg>` with
  `--show-all-servers`, `trace.rs:711`, and as `! <ip> (<name>): <msg>` by default, `trace.rs:731`, `:741`),
  `dnssec` (`src/app/mhost/modules/dnssec/chain.rs:176`, `:285`, `:295`; errors ignored), the check
  lint (`src/app/mhost/modules/check/lints/dnssec_lint.rs:105`; errors logged at `debug!`, `:146`).
  All reach `AppConfig.tcp_fallback` (`src/app/mhost/app_config.rs:33`, set from
  `!no-tcp-fallback`, `:91`).
- Flag help: "Does not retry truncated UDP answers over TCP" (`src/app/mhost/cli_parser.rs:225-230`).
- Lit tests assert the estimate line: `tests/lit/lookup-mode_uni-example.com.output:5`
  (`Sending 4 request[[s*]]`, `-s 8.8.8.8`, UDP) and `[[\d+]] request[[s*]]` patterns in
  `lookup-example.com`, `lookup-dns_google`, `lookup-8_8_8_8`, `lookup-whois-example.com`,
  `diff-example.com`, `check-partial_results*`, `lookup_predefined.output-no-ci`,
  `domain-lookup-partial_results-example.com`. Lit tests are outside the gate (`just test`).
- `lookup` adds the system resolvers unless `--no-system-lookups` is given
  (`src/app/mhost/resolver.rs:135`).
- Fake nameserver: `src/resolver/tcp_fallback_tests/fake_ns.rs` (`UdpBehavior::Truncate`,
  `TcpMode`, `tcp_connections()`, `udp_queries()`, `tcp_queries()`); binds loopback sockets.
- Gate: `just adlc-verify`. Only `example.com` names in test data. No hickory type in the public
  API; `resolver::raw` stays `pub(crate)` (`CLAUDE.md`).

## Requirements

1. `impl Estimate for Resolver` returns `max_requests = names * record_types * 2 * (1 + retries)`
   when the resolver has a `tcp_retry` resolver (agent default, confirmed by operator, 2026-11-12). The value is
   an upper bound for answers without CNAME chasing, and the code says so in a comment. The existing tests in `src/estimate.rs` that
   build a `udp:` resolver with `tcp_fallback` on assert the new maximum (agent default, confirmed by operator, 2026-11-12).
2. `min_requests` stays `names * record_types` for every resolver.
3. A resolver without a `tcp_retry` resolver (a `tcp:`, `tls:` or `https:` nameserver, or any
   resolver built with `tcp_fallback` off) keeps `max_requests = names * record_types * (1 + retries)`.
4. `ResolverGroup` estimates keep their aggregation rules (`Mode::Multi` sum with `limit`,
   `Mode::Uni` first resolver) over the per-resolver values of 1–3. A `Mode::Uni` estimate reflects only the first resolver, so a mixed-protocol Uni group whose first resolver has no `tcp_retry` may undercount the TCP retry of a `udp:` resolver picked at random (amendment from the phase 1 reading).
5. Every lit test whose estimate line comes from a `udp:` nameserver matches the request count with
   `Sending [[.+]] request[[s*]] to`, which accepts both "N request(s)" and "between {min} and {max}
   requests"; `tests/lit/lookup-dot-doh-example.com.output` keeps its fixed count (agent default, confirmed by operator, 2026-11-12).
6. `raw_query`, `raw_dnssec_query`, `parallel_raw_queries` and `parallel_raw_dnssec_queries` take a
   `tcp_fallback: bool` as their last parameter; with `true` a truncated UDP answer is retried over
   TCP as today (agent default, confirmed by operator, 2026-11-12).
7. With `tcp_fallback` `false`, a truncated UDP answer opens no TCP connection and yields
   `Err(RawError::Truncated { server })`, whose `Display` reads
   `response from {server} was truncated and TCP fallback is disabled` (agent default, confirmed by operator, 2026-11-12).
8. A complete (non-truncated) UDP answer is returned unchanged and opens no TCP connection,
   whatever `tcp_fallback` is.
9. `trace`, `dnssec` and the `check` DNSSEC lint pass `AppConfig.tcp_fallback` to every raw query
   they send. No test seam observes the value at these call sites (trace and dnssec start at the
   root servers, the lint queries the zone's global NS addresses, and all call `raw::` directly); this requirement is checked by review of the diff, not by a test (agent default, confirmed by operator, 2026-11-12).
10. With `--no-tcp-fallback`, `trace` shows a truncated answer from a server as that server's
    error through its existing `ServerOutcome::Error` path, whose rendered line contains `truncated`
    both by default (`! <ip> (<name>): <msg>`) and with `--show-all-servers` (`Error: <msg>`), also
    when it is the only server of its hop (agent default, confirmed by operator, 2026-11-12).
11. With `--no-tcp-fallback`, `dnssec` (`chain.rs`) and the `check` DNSSEC lint log a
    `RawError::Truncated` at `warn!` with the server and the queried name and type; other raw query
    errors keep their current handling (agent default, confirmed by operator, 2026-11-12).
12. `CHANGELOG.md`, under its `## Unreleased` heading, notes that the estimate counts the TCP retry and that `--no-tcp-fallback` now
    also covers `trace`, `dnssec` and `check` (agent default, confirmed by operator, 2026-11-12).

## Phases

## Phase 1 — Estimate counts the TCP retry

**Depends on:** none
**Requirements:** 1, 2, 3, 4, 5

`Resolver::estimate` widens `max_requests` for a resolver with a `tcp_retry` resolver; the console
then prints "between {min} and {max} requests" for `mhost -s udp:<ns> lookup …` and keeps
"N request(s)" for `tcp:`/`tls:`/`https:` and `--no-tcp-fallback`. Lit patterns follow.

### Test Scenarios

GIVEN a `udp:` resolver with `tcp_fallback` on and `retries` 0 WHEN estimating 1 name × 1 type THEN min is 1 and max is 2.
GIVEN a `udp:` resolver with `tcp_fallback` on and `retries` 2 WHEN estimating 2 names × 3 types THEN min is 6 and max is 36.
GIVEN a `udp:` resolver with `tcp_fallback` off and `retries` 2 WHEN estimating 1 name × 1 type THEN min is 1 and max is 3.
GIVEN a `tcp:` resolver with `tcp_fallback` on and `retries` 1 WHEN estimating 1 name × 1 type THEN min is 1 and max is 2.
GIVEN a `Mode::Multi` group of one `udp:` and one `tcp:` resolver, both `retries` 0 WHEN estimating 1 name × 1 type THEN min is 2 and max is 3.
GIVEN a `Mode::Uni` group whose first resolver is `udp:` with `tcp_fallback` on and `retries` 0 WHEN estimating 1 name × 1 type THEN min is 1 and max is 2.
GIVEN `mhost --no-system-lookups -s udp:<ns> lookup -t A example.com` parsed into an `AppConfig` and resolvers WHEN the lookup estimate is formatted for the console THEN the line reads "between 1 and 2 requests".
GIVEN the same command with `--no-tcp-fallback` WHEN the estimate is formatted THEN the line reads "1 request".

## Phase 2 — `--no-tcp-fallback` reaches the raw paths

**Depends on:** none
**Requirements:** 6, 7, 8, 9, 10, 11, 12

The raw query functions gain a `tcp_fallback` switch and a `RawError::Truncated` variant; `trace`,
`dnssec` and the check DNSSEC lint pass `AppConfig.tcp_fallback`; `trace` prints the truncation as
the server's error, `dnssec` and the lint warn about it. `CHANGELOG.md` records both changes.

### Test Scenarios

GIVEN a fake nameserver truncating over UDP and answering over TCP WHEN `raw_query` runs with `tcp_fallback` `true` THEN the complete answer arrives and one TCP connection was opened.
GIVEN the same fake nameserver WHEN `raw_query` runs with `tcp_fallback` `false` THEN it returns `RawError::Truncated` naming the server and `tcp_connections()` is 0.
GIVEN the same fake nameserver WHEN `raw_dnssec_query` runs with `tcp_fallback` `false` THEN it returns `RawError::Truncated` and `tcp_connections()` is 0.
GIVEN a fake nameserver answering completely over UDP WHEN `raw_query` runs with `tcp_fallback` `false` THEN the answer is returned and `tcp_connections()` is 0.
GIVEN a fake nameserver answering completely over UDP WHEN `raw_query` runs with `tcp_fallback` `true` THEN the answer is returned and `tcp_connections()` is 0.
GIVEN a fake nameserver truncating over UDP WHEN `parallel_raw_queries` runs with `tcp_fallback` `false` THEN its result for that server is `RawError::Truncated` and `tcp_connections()` is 0.
GIVEN a hop whose only server result is `RawError::Truncated` WHEN `trace` renders its summary by default THEN that server's `! <ip> (<name>): …` line contains `truncated`.
GIVEN the same hop WHEN `trace` renders with `--show-all-servers` THEN that server's line reads `Error: …` and contains `truncated`.

## Decision log

- Max per (name, type) is `2 * (1 + retries)` over the intent's `1 + (1 + retries)`: `single_lookup` may spend all `1 + retries` UDP attempts on timeouts before a truncated answer, and the TCP resolver then makes up to `1 + retries` attempts (`lookup.rs:665-692`, `mod.rs:473`), so the intent's figure undercounts (agent default, confirmed by operator, 2026-11-12).
- The widening is keyed on `tcp_retry.is_some()` over re-deriving protocol and `tcp_fallback` from opts: one source of truth with `single_lookup` (agent default, confirmed by operator, 2026-11-12).
- Truncation without fallback is `Err(RawError::Truncated { server })` over returning the truncated `RawResponse` as `Ok`: callers already route errors (trace prints them), and no caller reads `is_truncated()`, so an `Ok` would pass a partial answer off as complete (agent default, confirmed by operator, 2026-11-12).
- `tcp_fallback: bool` parameter on the four raw functions over a new options struct: one switch, four crate-private functions (agent default, confirmed by operator, 2026-11-12).
- Lit estimate patterns are loosened to accept both forms over pinning ranges: counts change with record types and retries, and lit tests already use regex counts (agent default, confirmed by operator, 2026-11-12).
- CHANGELOG entry for both behaviour changes over none: both change visible CLI output (agent default, confirmed by operator, 2026-11-12).
- Dry-run points taken: doubled max stated as an upper bound; existing `src/estimate.rs` asserts move to the new max; lit pattern `Sending [[.+]] request[[s*]] to`; `tcp_fallback` as last parameter; fixed `Truncated` Display text; requirement 9 checked by review because no seam observes it; trace's single-server hop asserted; CHANGELOG under `## Unreleased` (agent default, confirmed by operator, 2026-11-12).
- Reading fixes: dnssec and the lint warn on truncation instead of swallowing it (CLAUDE.md: never swallow an error silently; intent: report as truncated); the upper bound excludes CNAME chasing; trace's default `!` rendering is asserted beside `Error:`; `domain-lookup-partial_results` joins the lit list; console scenarios use `--no-system-lookups`; requirement 9's reason corrected for the lint (agent default, confirmed by operator, 2026-11-12).
- Phases are independent (`Depends on: none`) over chaining: they touch disjoint files except `CHANGELOG.md` (agent default, confirmed by operator, 2026-11-12).

## Open decisions

None.

## Out of scope

- The `lookup`-path TCP retry itself and `--no-tcp-fallback` for `lookup`: built in `udp-truncation-edns` (`specs/features/udp-truncation-edns/`).
- WHOIS request estimates: `src/app/mhost/console.rs:137-149`.
