#!/bin/sh
# The mem backend and the serve path must not grow a write primitive.
set -eu
ROOT=${1:?source root}
# Deny-list mentions of SYS_process_vm_writev are the sandbox, not a write.
if grep -nE 'process_vm_writev[[:space:]]*\(|PIOD_WRITE|PTRACE_POKEDATA|PTRACE_POKETEXT|PTRACE_POKEUSER' \
    "$ROOT/src/mem_read.cpp" "$ROOT/src/serve.cpp" "$ROOT/src/js_engine.cpp"; then
  echo "write primitive found" >&2
  exit 1
fi
echo "no target writes"
