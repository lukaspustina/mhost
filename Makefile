all: check test build

build-lib:
	cargo build

build:
	cargo build --features bin

check:
	cargo check --features bin

test:
	cargo test --features bin

test_env_build:
	cd tests; docker build . -t mhost-dnsmasq

test_env_start: test_env_build
	docker run -d -p 127.0.0.1:53:53/tcp -p 127.0.0.1:53:53/udp -v "$$(pwd)/tests/dnsmasq.d/":/etc/dnsmasq.d:ro --cap-add=NET_ADMIN --name mhost-dnsmasq mhost-dnsmasq:latest 

test_env_stop:
	-docker kill $$(docker ps -q -f name=mhost-dnsmasq)
	-docker rm $$(docker ps -a -q -f name=mhost-dnsmasq)

test_env_restart: test_env_stop test_env_start

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

