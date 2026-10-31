#!/usr/bin/env bash
# Builds the kernel with its in-kernel unit tests and runs them in QEMU (SPEC §B10).
# A configuration passes only if QEMU exits with status 0 (the semihosting exit code) and
# the serial log contains "KTEST SUMMARY passed=N failed=0" with N > 0.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release --features ktest
elf=target/aarch64-unknown-none-softfloat/release/aos-kernel
logs=target/ktest
mkdir -p "$logs"

# name, -machine, RAM in MiB, expected entry EL (virtualization=on starts the CPU at EL2)
configs=(
  "el1-512m virt 512 1"
  "el2-4g virt,virtualization=on 4096 2"
)

failed=0
for config in "${configs[@]}"; do
  read -r name machine mem_mib entry_el <<<"$config"
  log="$logs/$name.log"
  echo "=== ktest $name: -machine $machine -m ${mem_mib}M"
  set +e
  timeout "${KTEST_TIMEOUT:-120}" qemu-system-aarch64 \
    -machine "$machine" -cpu cortex-a72 -m "${mem_mib}M" \
    -display none -monitor none -serial stdio -no-reboot \
    -semihosting-config enable=on,target=native \
    -append "aos.test.mem_mib=$mem_mib aos.test.entry_el=$entry_el" \
    -kernel "$elf" </dev/null | tee "$log"
  status=${PIPESTATUS[0]}
  set -e
  if [[ $status -eq 0 ]] && grep -Eq 'KTEST SUMMARY passed=[1-9][0-9]* failed=0[[:space:]]*$' "$log"; then
    echo "=== ktest $name: PASS"
  else
    echo "=== ktest $name: FAIL (QEMU exit status $status; log: kernel/$log)"
    failed=1
  fi
done
exit $failed
