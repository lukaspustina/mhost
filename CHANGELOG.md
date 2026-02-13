# Changelog

## v0.3.2

### Major upgrades

- **Migrate DNS resolver from trust-dns-resolver v0.20 to hickory-resolver v0.25** — the trust-dns
  project was renamed to hickory-dns. This brings TLS/HTTPS improvements, updated DNSSEC support,
  and continued upstream maintenance.
- **Migrate CLI parser from clap v2 to clap v4** — modernized argument parsing with improved help
  formatting, value parsers, and typed argument actions.
- **Migrate nom from v5 to v7** — parser combinators updated from macro-based to function-based API.

### Dependency upgrades

- reqwest 0.11 to 0.13 (with hickory-dns feature)
- thiserror 1 to 2
- indexmap 1 to 2
- ipnetwork 0.17 to 0.21
- hostname 0.3 to 0.4
- rand 0.8 to 0.9
- yansi 0.5 to 1.0
- tracing-log 0.1 to 0.2
- clap_complete 2 to 4

### DNS server updates

- Switch Quad9 from filtered (9.9.9.9) to unfiltered (9.9.9.10) endpoints
- Remove stale hardcoded OpenNIC volunteer server IPs
- Add Mullvad DNS (privacy-focused, Sweden)
- Add Wikimedia DNS
- Add DNS4EU unfiltered (EU-based)
- Fix Cloudflare IPv6 TLS display name bug
- Fix Quad9 duplicate/missing IPv6 TLS entry

### Build and infrastructure

- Rust edition 2018 to 2021
- Slim tokio features (dropped unused: sync, signal, process, io-std, parking_lot, test-util)
- Modernize GitHub Actions CI workflows (dtolnay/rust-toolchain, actions/checkout@v4)
- Modernize release workflow (softprops/action-gh-release@v2, fix deprecated set-output syntax)
- Upgrade Docker action versions (login-action@v3, build-push-action@v6)
- Replace third-party musl action with native musl cross-compilation
- Fix clippy warnings

## v0.3.1

- Maintenance release

## v0.3.0

- Initial public release with DNS over UDP, TCP, TLS, and HTTPS support
- Multi-server concurrent lookups
- Domain/subdomain discovery
- DNS configuration linting
- WHOIS integration
- JSON and summary output formats
