.PHONY: fuzz
FUZZ_TIME=600

all: check build test

check:
	cargo check --bins --examples --all-features
	cargo check --tests --all-features
	cargo check --benches --all-features

build:
	cargo build --bins --tests --benches --examples --all-features

build-release:
	cargo build --bins --tests --benches --examples --all-features --release

test:
	cargo test --all-features --doc
	cargo test --bins --tests --all-features
	cargo test --bins --tests --all-features -- --ignored

fuzz:
	$(MAKE) -C fuzz fuzz -e FUZZ_TIME=${FUZZ_TIME}

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


prepare-release: docs

docs:
	doctoc README.md && git add README.md


deb:
	cargo deb

release: test prepare-release build-release deb


install:
	cargo install --all-features --path .


init: 
	brew install pre-commit
	pre-commit install


_rustup:
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

_cargo_packages:
	cargo install cargo-deb
	cargo install cargo-rpm

_cargo_security:
	cargo install cargo-crev
	cargo crev trust --level high https://github.com/dpc/crev-proofs
	cargo crev repo fetch all

