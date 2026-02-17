# mhost Makefile
# ──────────────────────────────────────────────────────────────────────

CARGO       ?= cargo
FUZZ_TIME   ?= 600

# Feature sets
ALL_FEATURES = --all-features
CLI_FEATURES = --features app-cli
TUI_FEATURES = --features app-tui

# ──────────────────────────────────────────────────────────────────────
# Core targets
# ──────────────────────────────────────────────────────────────────────

.PHONY: all check build build-release test test-lib test-doc test-integration \
        lint clippy fmt fmt-check \
        secure audit outdated deny semver-check \
        fuzz \
        stats \
        docs deb install release \
        clean clean-all \
        init \
        help

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' | sort

all: check lint test  ## Run check, lint, and test

# ──────────────────────────────────────────────────────────────────────
# Check & Build
# ──────────────────────────────────────────────────────────────────────

check:  ## Type-check all targets
	$(CARGO) check --bins --tests --benches --examples $(ALL_FEATURES)

build:  ## Build debug (all features)
	$(CARGO) build --bins --tests --benches --examples $(ALL_FEATURES)

build-release:  ## Build optimized release (all features)
	$(CARGO) build --bins --tests --benches --examples $(ALL_FEATURES) --release

# ──────────────────────────────────────────────────────────────────────
# Test
# ──────────────────────────────────────────────────────────────────────

test: test-lib test-doc test-integration  ## Run all tests

test-lib:  ## Unit tests only (no network)
	$(CARGO) test --lib $(ALL_FEATURES)

test-doc:  ## Doc tests only
	$(CARGO) test --doc $(ALL_FEATURES)

test-integration:  ## Integration + ignored tests (needs network)
	$(CARGO) test --bins --tests $(ALL_FEATURES)
	$(CARGO) test --bins --tests $(ALL_FEATURES) -- --ignored

# ──────────────────────────────────────────────────────────────────────
# Lint & Format
# ──────────────────────────────────────────────────────────────────────

lint: clippy fmt-check  ## Run all linters

clippy:  ## Run clippy on all targets
	$(CARGO) clippy --bins --tests --benches --examples $(ALL_FEATURES) -- -D warnings

fmt:  ## Format code
	$(CARGO) fmt

fmt-check:  ## Check formatting
	$(CARGO) fmt -- --check

# ──────────────────────────────────────────────────────────────────────
# Security & Dependency auditing
# ──────────────────────────────────────────────────────────────────────

secure: audit outdated  ## Run all security checks

audit:  ## Audit dependencies for known vulnerabilities
	$(CARGO) audit

outdated:  ## List outdated dependencies
	$(CARGO) outdated -R

deny:  ## Check advisories, licenses, and sources (cargo-deny)
	$(CARGO) deny check

semver-check:  ## Check for semver violations in public API
	$(CARGO) semver-checks check-release

# ──────────────────────────────────────────────────────────────────────
# Fuzz
# ──────────────────────────────────────────────────────────────────────

fuzz:  ## Run fuzz tests (FUZZ_TIME=seconds, default 600)
	$(MAKE) -C fuzz fuzz -e FUZZ_TIME=$(FUZZ_TIME)

# ──────────────────────────────────────────────────────────────────────
# Stats
# ──────────────────────────────────────────────────────────────────────

stats:  ## Show project statistics (lines of code, deps, binary size)
	@echo "── Lines of Code ──"
	@if command -v tokei >/dev/null 2>&1; then \
		tokei src/ ; \
	else \
		echo "  Rust files: $$(find src -name '*.rs' | wc -l | tr -d ' ')"; \
		echo "  Total lines: $$(find src -name '*.rs' -exec cat {} + | wc -l | tr -d ' ')"; \
		echo "  Code lines (non-blank, non-comment): $$(find src -name '*.rs' -exec cat {} + | grep -cvE '^\s*(//|$$)' | tr -d ' ')"; \
		echo "  Test lines: $$(find src -name '*.rs' -exec grep -l '#\[cfg(test)\]' {} + 2>/dev/null | xargs cat 2>/dev/null | wc -l | tr -d ' ')"; \
		echo "  (install tokei for detailed breakdown)"; \
	fi
	@echo ""
	@echo "── Dependencies ──"
	@echo "  Direct: $$(grep -cE '^\w+ =' Cargo.toml | tr -d ' ')"
	@echo "  Total (resolved): $$(grep -c 'name =' Cargo.lock 2>/dev/null || echo 'N/A')"
	@echo ""
	@echo "── Features ──"
	@echo "  app-cli (default): CLI binary (mhost)"
	@echo "  app-tui:           TUI binary (mdive)"
	@echo "  app-lib:           shared app layer"
	@echo "  services:          HTTP services (whois)"
	@echo ""
	@echo "── Binary Sizes ──"
	@if [ -f target/debug/mhost ]; then \
		echo "  mhost  (debug):   $$(du -h target/debug/mhost | cut -f1)"; \
	else \
		echo "  mhost  (debug):   not built"; \
	fi
	@if [ -f target/debug/mdive ]; then \
		echo "  mdive  (debug):   $$(du -h target/debug/mdive | cut -f1)"; \
	else \
		echo "  mdive  (debug):   not built"; \
	fi
	@if [ -f target/release/mhost ]; then \
		echo "  mhost  (release): $$(du -h target/release/mhost | cut -f1)"; \
	else \
		echo "  mhost  (release): not built"; \
	fi
	@if [ -f target/release/mdive ]; then \
		echo "  mdive  (release): $$(du -h target/release/mdive | cut -f1)"; \
	else \
		echo "  mdive  (release): not built"; \
	fi
	@echo ""
	@echo "── Test Count ──"
	@echo "  Unit tests: $$($(CARGO) test --lib $(ALL_FEATURES) -- --list 2>/dev/null | grep -c ': test$$' || echo 'N/A')"

# ──────────────────────────────────────────────────────────────────────
# Package & Release
# ──────────────────────────────────────────────────────────────────────

docs:  ## Regenerate README TOC
	doctoc README.md && git add README.md

deb:  ## Build Debian package
	$(CARGO) deb

release: lint test build-release deb  ## Full release build

install:  ## Install mhost and mdive locally
	$(CARGO) install $(ALL_FEATURES) --path .

# ──────────────────────────────────────────────────────────────────────
# Clean
# ──────────────────────────────────────────────────────────────────────

clean:  ## Remove build artifacts
	$(CARGO) clean

clean-all: clean  ## Remove build artifacts and lockfile
	rm -f Cargo.lock

# ──────────────────────────────────────────────────────────────────────
# Setup
# ──────────────────────────────────────────────────────────────────────

init:  ## Install dev tooling (pre-commit, cargo plugins)
	brew install pre-commit
	pre-commit install
	$(CARGO) install cargo-audit cargo-outdated cargo-deb
