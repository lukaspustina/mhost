### Reader

COUNTS blockers=0 amendments=1 majors=0 deferred=0 minors=0 nits=0
LENSES Engineering, Testing

AMENDMENT | src/estimate.rs:70 | When the group is `Mode::Uni`, the estimate comes from the first resolver only, so a mixed-protocol group whose first resolver is `tcp:` prints a maximum that leaves out the TCP retry of the `udp:` resolvers that `uni_lookup` can pick at random. Requirement 4 asks for exactly this, so the spec needs the fix, not the code. | `mhost -m uni --no-system-lookups -s tcp:1.1.1.1 -s udp:8.8.8.8 lookup -t TXT example.com` (default `--retries 0`). The first resolver is `tcp:` and has no `tcp_retry`, so the estimate is min 1 / max 1 and the console prints "Sending 1 request". `uni_lookup` picks either resolver with equal chance. If it picks `udp:8.8.8.8` and the answer is truncated, `single_lookup` sends 1 UDP request and then 1 TCP request, 2 in total. Before this change every resolver in the group had the same opts and the same max, so the first resolver was a sound stand-in, as the comment at :68-69 says. The protocol now changes the max, so it no longer is. A sound upper bound for Uni keeps min from the first resolver and takes the maximum of `max_requests` over all resolvers. | affected_phase: 1 | repaired_in_phase: no

```quote src/estimate.rs:70
            Mode::Uni => self.resolvers.first().map(|x| x.estimate(query)).unwrap_or_default(),
```

```quote specs/features/tcp-fallback-followups/spec.md:72
4. `ResolverGroup` estimates keep their aggregation rules (`Mode::Multi` sum with `limit`,
```

```quote src/resolver/mod.rs:385
                let resolver = resolvers.choose(&mut rng).expect("resolvers is non-empty");
```

```quote src/resolver/mod.rs:254
    /// [`Uni`](Mode::Uni) picks one at random per query.
```

Traced and found sound:

- Per-resolver max is `2 * (1 + retries)` when `tcp_retry` is set. The UDP leg runs with hickory `attempts = 0` (`src/resolver/mod.rs` `build_resolvers`), and `single_lookup` makes up to `1 + retries` UDP lookups. After that comes exactly one TCP retry lookup, and hickory gives it `attempts = retries`, so at most `1 + retries` sends (`RetryDnsHandle`, hickory-net 0.26.3).
- Without `tcp_retry` there are `1 + retries` hickory attempts, and the max is unchanged.
- Min is unchanged.
- `Mode::Multi` sums the resolvers with the same `take(limit)` as `multi_lookup`.
- The default `ResolverOpts` has `tcp_fallback: true`, so the existing unit tests in `src/estimate.rs` (built with `udp:`) do get a `tcp_retry` and assert the doubled max correctly.
- The lit estimate patterns in the phase diff accept both "N request(s)" and "between N and M requests".
