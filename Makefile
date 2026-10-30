# Entry points for humans and CI. Each target is also runnable by hand (see README.md).
.PHONY: test test-core check-nostd test-kernel lint run gdb

test: test-core check-nostd test-kernel

# Core libraries on the host, including property tests.
test-core:
	cargo test --workspace

# The core libraries must build for the bare-metal userspace target.
check-nostd:
	cargo build --workspace --target aarch64-unknown-none

# In-kernel unit tests in QEMU (two configurations: EL1 entry, EL2 entry).
test-kernel:
	kernel/scripts/ktest.sh

lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	cd kernel && cargo fmt --check
	cd kernel && cargo clippy --release -- -D warnings
	cd kernel && cargo clippy --release --features ktest -- -D warnings

run:
	kernel/scripts/qemu.sh

gdb:
	kernel/scripts/qemu.sh --gdb
