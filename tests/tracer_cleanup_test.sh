#!/bin/sh
# SIGTERM and SIGKILL of --serve must not leave the tracer process behind.
set -eu
BIN=${1:?llamaspy}
ROOT=${2:?source root}
if [ "$(uname -s)" != "Linux" ]; then
  echo "SKIP tracer cleanup (Linux bpftrace provider)"
  exit 0
fi
TMP=$(mktemp -d)
SP=""
PID=""
cleanup() {
  if [ -n "$PID" ]; then kill -KILL "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  if [ -n "$SP" ]; then kill -KILL "$SP" 2>/dev/null || true; wait "$SP" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

sleep 120 &
SP=$!
mkdir -p "$TMP/bin"
cat > "$TMP/bin/bpftrace" << EOF
#!/bin/sh
echo \$\$ > "$TMP/tracer.pid"
echo "\$@" > "$TMP/tracer.args"
exec sleep 300
EOF
chmod 700 "$TMP/bin/bpftrace"

start_spy() {
  rm -f "$TMP/tracer.pid" "$TMP/out"
  LLAMASPY_BPFTRACE="$TMP/bin/bpftrace" "$BIN" --serve 127.0.0.1:0 --listen-api-key test-key \
    --backend bpftrace --pid "$SP" --dtrace-script "$ROOT/scripts/llama_decode.d" \
    --no-hud >"$TMP/out" 2>&1 &
  PID=$!
  i=0
  while [ "$i" -lt 50 ]; do
    if [ -s "$TMP/tracer.pid" ]; then return 0; fi
    if ! kill -0 "$PID" 2>/dev/null; then
      echo "llamaspy exited early" >&2
      cat "$TMP/out" >&2
      return 1
    fi
    i=$((i + 1))
    sleep 0.1
  done
  echo "tracer did not start" >&2
  cat "$TMP/out" >&2
  return 1
}

start_spy
TR=$(cat "$TMP/tracer.pid")
kill -TERM "$PID"
i=0
while kill -0 "$PID" 2>/dev/null && [ "$i" -lt 40 ]; do
  i=$((i + 1))
  sleep 0.1
done
if kill -0 "$PID" 2>/dev/null; then
  echo "parent survived SIGTERM" >&2
  exit 1
fi
if kill -0 "$TR" 2>/dev/null; then
  echo "tracer $TR survived SIGTERM of llamaspy" >&2
  exit 1
fi
BT=$(awk '{print $NF}' "$TMP/tracer.args")
DIR=$(dirname "$BT")
if [ -e "$BT" ] || [ -d "$DIR" ]; then
  echo "bpftrace program dir survived SIGTERM: $DIR" >&2
  exit 1
fi
PID=""

start_spy
TR=$(cat "$TMP/tracer.pid")
SERVE=$(sed -n 's/.*serve pid=\([0-9][0-9]*\).*/\1/p' "$TMP/out" | head -n 1)
kill -KILL "$PID"
sleep 0.4
if kill -0 "$TR" 2>/dev/null; then
  echo "tracer $TR survived SIGKILL of parent" >&2
  exit 1
fi
if [ -n "$SERVE" ] && kill -0 "$SERVE" 2>/dev/null; then
  echo "serve pid $SERVE survived SIGKILL of parent" >&2
  exit 1
fi
PID=""
echo "tracer cleanup ok"
