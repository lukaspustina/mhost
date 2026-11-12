---
class: unverified-claim-treated-as-fact
repeat-of: specs/solutions/2026-10-20-github-pages-defaults-assumed.md
---
# A UDP+TCP pair on one hickory nameserver keeps UDP as the transport

**What failed.** Phase 1 of `specs/features/udp-truncation-edns/spec.md` fixed truncated UDP
answers (#797) by giving a `udp:` nameserver a second `ConnectionConfig` for TCP, and the spec
stated as fact that "UDP stays the transport of every query" and that a blocked TCP port "still
ends in the truncation error". Neither was checked against hickory 0.26.3. Review
(`review.md`, range `130ec9d..5334bb7`, F1/F2) showed both wrong: one UDP timeout marks the UDP
connection `Status::Failed`, `connected_mut_client` drops it and `select_connection` reuses the
open TCP connection for every later query (`name_server.rs`); and `most_specific` lets a TCP
`Timeout`/`Io` error replace `NetError::Truncated` (`name_server_pool.rs`).

**What worked.** Phase 2 kept the nameserver UDP-only and moved the retry into mhost:
`Resolver::tcp_retry` is a separate TCP-only hickory resolver (cache off), `single_lookup` repeats a
`Truncated` lookup once over it and reports a failed retry as
`response was truncated; TCP retry failed: <reason>` (`9cb9530`). Fake-nameserver tests in
`src/resolver/tcp_fallback_tests/` (per-name UDP drop/truncate, silent or absent TCP, query logs)
pin the transport each query used.

**How to notice next time.** A spec sentence about what a dependency's pool, retry or cache does
has no test that observes the transport or the error at a fake server.
