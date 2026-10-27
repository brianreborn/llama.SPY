#!/usr/bin/env bash
# HookScript smoke for a prebuilt llama.SPY bundle.
# Run from anywhere; resolves paths relative to this script → bundle root.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/bin/llamaspy"
HOOK="$ROOT/examples/hook.sample.json"
if [[ ! -x "$BIN" ]]; then
  echo "missing executable: $BIN" >&2
  exit 1
fi
if [[ ! -f "$HOOK" ]]; then
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
