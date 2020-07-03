all: check build test

check:
	cargo check --bins --tests --benches --examples --all-features

build:
	cargo build --bins --tests --benches --examples --all-features

test:
	cargo test --bins --tests --benches --examples --all-features

secure:
	cargo audit 
	cargo outdated

lint:
	cargo clippy
	cargo fmt -- --check

