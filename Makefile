FUZZ_TIME=600

all: check build test

check:
	cargo check --bins --examples --all-features
	cargo check --tests --all-features
	cargo check --benches --all-features

build:
	cargo build --bins --tests --benches --examples --all-features

test:
	cargo test --doc
	cargo test --bins --tests --all-features

fuzz: _cargo_fuzz
	for i in $$(cargo fuzz list); do \
		cargo +nightly fuzz run $$i -- -dict=./fuzz/dicts/$$i.txt -max_len=256 -max_total_time=${FUZZ_TIME} -print_funcs=10 -print_final_stats=1 -print_coverage=1 || exit -1; \
	done

_cargo_fuzz:
	cargo-fuzz --version

secure:
	cargo audit 
	cargo outdated

lint: clippy fmt-check

clippy:
	cargo clippy --bins --tests --benches --examples --all-features

fmt-check:
	cargo fmt -- --check

fmt:
	cargo fmt

install:
	cargo install --all-features --path .
