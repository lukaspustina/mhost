## Phase 1 — Estimate counts the TCP retry

## Groups
G1: C1, C2, C4, C6

## Plan
### G1
1. src/estimate.rs — change — in `impl Estimate for Resolver::estimate`, keep `min_lookups = names * record_types`; compute `max_lookups = names * record_types * (1 + self.opts.retries)` and multiply it by 2 when `self.tcp_retry.is_some()` (same source of truth as `single_lookup`, `src/resolver/lookup.rs:665`, `:682`); add a comment that the value is an upper bound without CNAME chasing: up to `1 + retries` UDP attempts then up to `1 + retries` TCP attempts of the retry resolver (`src/resolver/mod.rs:192-204`). `ResolverGroup::estimate` (`src/estimate.rs:54-67`) is untouched and aggregates the new per-resolver values (C4); C6 follows through `AppResolver::create_resolvers` building a `udp:` resolver with `tcp_retry`. The existing unit tests in this file already assert the new max (test commit 70e2fe5). — hangs on `Estimate for Resolver::estimate`, src/estimate.rs:42-52
