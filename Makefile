all: check test build

build-lib:
	cargo build

build:
	cargo build --features bin

check:
	cargo check --features bin

test:
	cargo test --features bin

clippy:
	rustup run nightly cargo clippy --features bin

fmt:
	rustup run nightly cargo fmt

prepare_release: all
	$(MAKE) -C docs

duplicate_libs:
	cargo tree -d

_update-clippy_n_fmt:
	rustup update
	rustup run nightly cargo install clippy --force
	rustup run nightly cargo install rustfmt --force

