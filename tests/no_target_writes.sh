#!/bin/sh
# The mem backend, tracers, and serve path must not grow a write primitive.
set -eu
ROOT=${1:?source root}
files=$(find "$ROOT/src" "$ROOT/scripts" -type f \
  \( -name '*.cpp' -o -name '*.hpp' -o -name '*.bt' -o -name '*.d' \))
if grep -nE 'process_vm_writev[[:space:]]*\(|PIOD_WRITE|PT_WRITE_D|PT_WRITE_I|PTRACE_POKEDATA|PTRACE_POKETEXT|PTRACE_POKEUSER|pwrite[[:space:]]*\(' \
    $files; then
  echo "write primitive found" >&2
  exit 1
fi
echo "no target writes"
