#!/usr/bin/env bash
# Boots the kernel in QEMU; quit with Ctrl-A X.
#   --gdb   wait for a debugger on localhost:1234, e.g.
#           gdb-multiarch target/aarch64-unknown-none-softfloat/release/aos-kernel -ex 'target remote :1234'
# Extra arguments go to QEMU. AOS_MEM sets the RAM size (default 512M).
set -euo pipefail
cd "$(dirname "$0")/.."

gdb=()
if [[ "${1:-}" == "--gdb" ]]; then
  gdb=(-s -S)
  shift
fi
cargo build --release
exec qemu-system-aarch64 -machine virt -cpu cortex-a72 -m "${AOS_MEM:-512M}" \
  -display none -serial mon:stdio "${gdb[@]}" "$@" \
  -kernel target/aarch64-unknown-none-softfloat/release/aos-kernel
