## Phase 1 — UDP nameservers fall back to TCP on truncation

## Groups
G1: C1, C2, C3, C4, C5, C6, C7, C8, C9, C10, C11, C12, C13, C14, C15

All fifteen criteria form one group: the lib tests compile as one crate, so no test runs until
the whole interface below (`to_proto(tcp_fallback)`, `ResolverOpts.tcp_fallback`,
`AppConfig.tcp_fallback`, `--no-tcp-fallback`) compiles. The library part (steps 1-3) is
independent of the app part (steps 4-7) and can be built first.

## Plan
### G1
1. src/nameserver/mod.rs — change — `to_proto(&self)` becomes `to_proto(&self, tcp_fallback: bool)`; build the connection list as a `Vec`: `Udp` gets `ConnectionConfig::new(ProtocolConfig::Udp)` on `self.port()` and, when `tcp_fallback`, a second `ConnectionConfig::new(ProtocolConfig::Tcp)` on the same port (UDP first, TCP second); `Tcp`, `Tls` (`dot`), `Https` (`doh`) keep exactly one connection of their own protocol whatever the flag; doc comment states the fallback rule (C2, C3, C6, C7, C8) — hangs on `NameServerConfig::to_proto`, src/nameserver/mod.rs:330
2. src/resolver/mod.rs — change — add `pub tcp_fallback: bool` to `ResolverOpts` with a doc comment (truncated UDP answers retried over TCP on the same server), `tcp_fallback: true` in `Default` (C4, C9); `From<resolv_conf::Config>` already spreads `..Default::default()`, so system opts keep `true` — hangs on `struct ResolverOpts`, src/resolver/mod.rs:83 and `impl Default for ResolverOpts`, src/resolver/mod.rs:111
3. src/resolver/mod.rs — change — `ResolverConfig::to_proto(&self)` takes `tcp_fallback: bool` and forwards it to `NameServerConfig::to_proto`; `Resolver::new` (line 180) and `Resolver::new_for_test` (line 449) call `config.to_proto(opts.tcp_fallback)` (C1, C11, C12, C13) — hangs on `ResolverConfig::to_proto`, src/resolver/mod.rs:467, `Resolver::new`, src/resolver/mod.rs:177, `Resolver::new_for_test`, src/resolver/mod.rs:446. No other call site of either `to_proto` exists (`raw.rs`/`delegation.rs` build no hickory resolver config); the `ResolverOpts` literals in src/resolver/builder.rs:398, src/estimate.rs:79 and src/resolver/mod.rs:492 use `..Default::default()` and need no change.
4. src/app/mhost/cli_parser.rs — change — add `Arg::new("no-tcp-fallback").long("no-tcp-fallback").action(ArgAction::SetTrue).global(true)` after `timeout`, help text e.g. "Does not retry truncated UDP answers over TCP" (must contain `truncat` and `TCP`; `is_global_set()` is asserted, so `.global(true)` is required) (C5) — hangs on `create_parser`, src/app/mhost/cli_parser.rs:66 (next to `retries`/`timeout`, lines 209-222)
5. src/app/mhost/app_config.rs — change — add `pub tcp_fallback: bool` to `AppConfig`, set `tcp_fallback: !args.get_flag("no-tcp-fallback")` in `TryFrom<&ArgMatches>`, add `tcp_fallback: true` to the test helper `make_config` literal (C5, C10) — hangs on `struct AppConfig`, src/app/mhost/app_config.rs:23, `AppConfig::try_from`, src/app/mhost/app_config.rs:74, `make_config`, src/app/mhost/app_config.rs:156 (the only two `AppConfig` literals in the crate; mdive and `app/common` build none)
6. src/app/mhost/resolver.rs — change — `load_resolver_opts` sets `tcp_fallback: config.tcp_fallback` in `app_config_opts`; the `use_system_resolv_opt` branch already spreads `..app_config_opts`, so the flag holds there too (C5, C10, C14, C15) — hangs on `load_resolver_opts`, src/app/mhost/resolver.rs:219
7. README.md — change — add `--no-tcp-fallback` to the "Concurrency & resilience" option list after `--timeout` (doc parity for the new global flag; no test) — hangs on nothing existing in code; README.md:613
