#!/bin/sh
# Emit LLMS1 bindings for a llama.cpp (or any ELF) binary.
#
#   scripts/gen-gg-offsets.sh /path/to/llama-server llama_decode llama_n_vocab
#
# off is a displacement added to the resolved symbol. off=0x0 reads the symbol
# itself. The module-relative virtual address from nm is only a comment.
# fp=buildid:<gnu-build-id>. llama.SPY refuses a read when this does not match
# the running module. Paste the printed lines into a HookScript or .gg file.
#
# Needs nm (or llvm-nm) and, for the fingerprint, readelf (or llvm-readelf).
set -eu

if [ $# -lt 1 ]; then
  echo "usage: gen-gg-offsets.sh BINARY [SYMBOL ...]" >&2
  echo "prints LLMS1 lines. off=0x0 means symbol + 0. See docs/GAME_GENIE.md." >&2
  exit 2
fi

BIN=$1
shift

NM=nm
command -v nm >/dev/null 2>&1 || NM=llvm-nm
if ! command -v "$NM" >/dev/null 2>&1; then
  echo "gen-gg-offsets: nm or llvm-nm is required" >&2
  exit 1
fi

READELF=""
for c in readelf llvm-readelf eu-readelf; do
  if command -v "$c" >/dev/null 2>&1; then
    READELF=$c
    break
  fi
done

BID=""
if [ -n "$READELF" ]; then
  BID=$("$READELF" -n "$BIN" 2>/dev/null | awk '/Build ID/ { print $3; exit }')
fi
if [ -z "$BID" ]; then
  echo "# warning: no GNU build-id; fingerprint is buildid:MISSING" >&2
  BID=MISSING
fi

if [ $# -eq 0 ]; then
  echo "# no symbols requested. Example:" >&2
  echo "#   $0 $BIN llama_decode" >&2
  exit 0
fi

found=0
for sym in "$@"; do
  line=$("$NM" -D "$BIN" 2>/dev/null | awk -v s="$sym" '$NF == s && $2 != "U" { print; exit }')
  if [ -z "$line" ]; then
    line=$("$NM" "$BIN" 2>/dev/null | awk -v s="$sym" '$NF == s && $2 != "U" { print; exit }')
  fi
  if [ -z "$line" ]; then
    echo "# symbol not found: $sym" >&2
    continue
  fi
  va=$(printf '%s\n' "$line" | awk '{ print $1 }')
  echo "# $sym va=0x$va (module-relative or preferred VA; resolver adds st_value itself)"
  echo "LLMS1|sym=$sym|off=0x0|width=8|type=u64|fp=buildid:$BID|note=symbol+0 displacement; fix width and type"
  found=$((found + 1))
done

if [ "$found" -eq 0 ]; then
  exit 1
fi
