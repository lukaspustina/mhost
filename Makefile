all: check test

build-lib:
	cargo build

build:
	cargo build --features bin

check:
	cargo check --features bin

test:
	cargo test

clippy:
	rustup run nightly cargo clippy --features bin

fmt:
	rustup run nightly cargo fmt

_update-clippy_n_fmt:
	rustup update
	rustup run nightly cargo install clippy --force
	rustup run nightly cargo install rustfmt --force

