#!/bin/sh
# HookScript smoke for a source tree (build/llamaspy) or a prebuilt bundle (bin/llamaspy).
# Run from anywhere; paths are relative to this script.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ -x "$ROOT/bin/llamaspy" ]; then
  BIN=$ROOT/bin/llamaspy
elif [ -x "$ROOT/build/llamaspy" ]; then
  BIN=$ROOT/build/llamaspy
else
  echo "missing executable: $ROOT/bin/llamaspy or $ROOT/build/llamaspy" >&2
  exit 1
fi
HOOK=$ROOT/examples/hook.sample.json
if [ ! -f "$HOOK" ]; then
  echo "missing HookScript: $HOOK" >&2
  exit 1
fi
echo "== list-tools =="
"$BIN" --hook-file "$HOOK" --list-tools
echo
echo "== call-tool echo =="
"$BIN" --hook-file "$HOOK" --call-tool echo '{"msg":"hi"}'
echo
echo "== call-tool add =="
"$BIN" --hook-file "$HOOK" --call-tool add '{"a":2,"b":3}'
echo
echo "smoke ok"
