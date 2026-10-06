# The verb contract of mhost (pdt-adlc ADR 0008).
#
# Migrated from a Makefile on 2026-08-19, by reduction: three of 27 targets are
# gone — help (`just --list` builds the listing), all (check + lint + test,
# which the contract calls `check`), and the old `check`.
#
# That last one is the point. `check` was
# `cargo check --bins --tests --benches --examples --all-features` — a compile,
# no test run — and the ADLC contract resolver preferred a target of that name.
# So every attestation this repository produced proved that 78 test files
# COMPILE (pdt-adlc backlog I14). There is no fast-compile verb any more:
# clippy compiles the same targets and checks more.
#
# WHAT THE GATE SKIPS, AND WHY IT IS NAMED HERE. `test-lib` carried the comment
# "Unit tests only (no network)" and that was false: nine of its tests talk to
# the network, and on 2026-08-19 seven of them failed — five whois tests calling
# stat.ripe.net, and two parser tests resolving dns.google and
# tls.cloudflare-dns.com through whatever resolver the host has (here: the two
# Pi-holes at 192.168.2.8 and .19, which time out for external names). They are
# real tests, they are just not gate material: repo-contract requirement 5 rules
# out the network. test-offline names each skipped group; `just test-lib` still
# runs all of them, network and all.

cargo := "cargo"
all_features := "--all-features"

default: adlc-verify

# --- the contract ------------------------------------------------------------

# What the ADLC gate runs: fmt-check, clippy, the offline library and doc tests.
adlc-verify: lint test-offline test-doc

# Everything: lint plus the full suite, network tests included.
check: lint test

# All tests: library, doc, integration — the last two groups need the network.
test: test-lib test-doc test-integration

# clippy + fmt-check.
lint: clippy fmt-check

# --- tests -------------------------------------------------------------------

# The library tests that need no network — what the gate runs.
#
# Skipped: services::whois::* (five tests, HTTPS to stat.ripe.net) and the two
# parser tests that resolve dns.google / tls.cloudflare-dns.com through the
# host's resolver. 549 of 558 run; the nine are reachable via `just test-lib`.
test-offline:
    {{cargo}} test --lib {{all_features}} -- \
        --skip services::whois \
        --skip nameserver::parser::test::dns_google \
        --skip nameserver::parser::test::tls_cloudflare_dns_com_tls_auth_name

# Every library test, network ones included.
test-lib:
    {{cargo}} test --lib {{all_features}}

# Doc tests.
test-doc:
    {{cargo}} test --doc {{all_features}}

# Integration and ignored tests. Needs the network.
test-integration:
    {{cargo}} test --bins --tests {{all_features}}
    {{cargo}} test --bins --tests {{all_features}} -- --ignored

# --- lints -------------------------------------------------------------------

clippy:
    {{cargo}} clippy --bins --tests --benches --examples {{all_features}} -- -D warnings

fmt-check:
    {{cargo}} fmt -- --check

fmt:
    {{cargo}} fmt

# --- build -------------------------------------------------------------------

# Debug build, all targets.
build:
    {{cargo}} build --bins --tests --benches --examples {{all_features}}

# Optimized release build, all targets.
build-release:
    {{cargo}} build --bins --tests --benches --examples {{all_features}} --release

# Install mhost and mdive locally.
install:
    {{cargo}} install {{all_features}} --path .

clean:
    {{cargo}} clean

# Build artifacts and the lockfile.
clean-all: clean
    rm -f Cargo.lock

# --- dependency hygiene (network: advisory database, crates.io) --------------

# audit + outdated.
secure: audit outdated

audit:
    {{cargo}} audit

outdated:
    {{cargo}} outdated -R

# Advisories, licences and sources (cargo-deny).
deny:
    {{cargo}} deny check

# Semver violations in the public API.
semver-check:
    {{cargo}} semver-checks check-release

# --- project-specific --------------------------------------------------------

# Fuzz tests. FUZZ_TIME=seconds, default 600.
fuzz fuzz_time="600":
    make -C fuzz fuzz -e FUZZ_TIME={{fuzz_time}}

# Debian package.
deb:
    {{cargo}} deb

# Full release build.
release: lint test build-release deb

# Regenerate the README table of contents.
docs:
    doctoc README.md && git add README.md

# rustup if it is missing, the toolchain rust-toolchain.toml pins (rustfmt and clippy with it), and
# the cargo tools the recipes call beyond it, pinned, into ~/.cargo/bin: mutation testing, audit,
# outdated, deny, semver-checks and deb.

# Install the pinned toolchain and cargo tools the recipes need.
adlc-setup:
    @command -v rustup >/dev/null || curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain none
    rustup toolchain install
    {{cargo}} install --locked cargo-mutants@27.1.0 cargo-audit@0.22.2 cargo-outdated@0.19.0 cargo-deny@0.20.2 cargo-semver-checks@0.51.0 cargo-deb@3.8.0

# Project statistics.
stats:
    #!/usr/bin/env bash
    echo "── Lines of Code ──"
    if command -v tokei >/dev/null 2>&1; then
        tokei src/
    else
        echo "  Rust files: $(find src -name '*.rs' | wc -l | tr -d ' ')"
        echo "  Total lines: $(find src -name '*.rs' -exec cat {} + | wc -l | tr -d ' ')"
    fi
    echo ""
    echo "── Dependencies ──"
    echo "  Direct: $(grep -cE '^\w+ =' Cargo.toml | tr -d ' ')"
    echo "  Total (resolved): $(grep -c 'name =' Cargo.lock 2>/dev/null || echo 'N/A')"
    echo ""
    echo "── Binary Sizes ──"
    for b in target/debug/mhost target/debug/mdive target/release/mhost target/release/mdive; do
        if [ -f "$b" ]; then echo "  $b: $(du -h "$b" | cut -f1)"; else echo "  $b: not built"; fi
    done
