#!/bin/sh
# scripts/gen-gg-offsets.sh emits sym+0 displacements and a build-id fingerprint.
set -eu
BIN=${1:?test binary}
SCRIPT=${2:?script}
if ! command -v nm >/dev/null 2>&1 && ! command -v llvm-nm >/dev/null 2>&1; then
  echo "SKIP gen-gg-offsets (no nm)"
  exit 0
fi
out=$("$SCRIPT" "$BIN" llamaspy_test_u64)
printf '%s\n' "$out" | grep -q 'LLMS1|sym=llamaspy_test_u64|off=0x0|'
printf '%s\n' "$out" | grep -q 'fp=buildid:'
printf '%s\n' "$out" | grep -q '0xdead' && {
  echo "generator emitted a fake 0xdead offset" >&2
  exit 1
}
echo "gen-gg-offsets ok"
