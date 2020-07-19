all: check build test

check:
	cargo check --bins --tests --benches --examples --all-features

build:
	cargo build --bins --tests --benches --examples --all-features

test:
	cargo test --doc
	cargo test --bins --tests --benches --examples --all-features

secure:
	cargo audit 
	cargo outdated

lint:
	cargo clippy --bins --tests --benches --examples --all-features
	cargo fmt -- --check

fmt:
	cargo fmt

