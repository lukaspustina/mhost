all:

fuzz: _cargo_fuzz _cargo_afl fuzz_fuzz fuzz_afl

fuzz_fuzz:
	for i in $$(cargo fuzz list | grep -v afl); do \
		cargo +nightly fuzz run $$i -- -dict=./dicts/$$i.txt -max_len=256 -max_total_time=${FUZZ_TIME} -print_funcs=10 -print_final_stats=1 -print_coverage=1 || exit -1; \
	done

fuzz_afl:
	for i in $$(cargo fuzz list | grep afl); do \
		cargo afl fuzz -V ${FUZZ_TIME} -i ./afl-input/$$i -o ./$$i.out ./target/debug/$$i; \
	done

_cargo_fuzz:
	cargo fuzz --version

_cargo_afl:
	cargo afl --version
