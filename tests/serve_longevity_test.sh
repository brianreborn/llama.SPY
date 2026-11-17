#!/bin/sh
# --serve must stay up well past the old 3 s self-kill, and still answer.
set -eu
BIN=${1:?need llamaspy path}
TMP=$(mktemp -d)
PID=""
cleanup() {
  if [ -n "$PID" ]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

printf '%s\n' 'eval time = 1.00 ms / 10 runs (12.50 tokens per second)' > "$TMP/t.log"
printf '%s\n' 'secret-key' > "$TMP/key"
chmod 600 "$TMP/key"

"$BIN" --serve 127.0.0.1:0 --listen-api-key-file "$TMP/key" --backend log \
  --log-file "$TMP/t.log" --no-hud >"$TMP/out" 2>&1 &
PID=$!

PORT=""
i=0
while [ "$i" -lt 50 ]; do
  PORT=$(sed -n 's/.*127\.0\.0\.1:\([0-9][0-9]*\).*/\1/p' "$TMP/out" | head -n 1)
  if [ -n "$PORT" ]; then break; fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "server exited during startup" >&2
    cat "$TMP/out" >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 0.1
done
if [ -z "$PORT" ]; then
  echo "no listen port" >&2
  cat "$TMP/out" >&2
  exit 1
fi

fetch_metrics() {
  PORT="$PORT" python3 - <<'PY'
import os, urllib.request
url = "http://127.0.0.1:%s/metrics" % os.environ["PORT"]
req = urllib.request.Request(url, headers={"Authorization": "Bearer secret-key", "Host": "127.0.0.1"})
body = urllib.request.urlopen(req, timeout=2).read().decode("ascii", "replace")
if "12.5" not in body:
    raise SystemExit("missing metric: " + body)
print("metrics ok")
PY
}

fetch_metrics
sleep 11
if ! kill -0 "$PID" 2>/dev/null; then
  echo "server died before 11 s" >&2
  cat "$TMP/out" >&2
  exit 1
fi
fetch_metrics
kill -TERM "$PID"
rc=0
wait "$PID" || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "SIGTERM exit $rc" >&2
  cat "$TMP/out" >&2
  PID=""
  exit 1
fi
PID=""
echo "serve longevity ok"
