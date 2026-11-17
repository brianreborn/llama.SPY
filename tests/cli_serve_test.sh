#!/bin/sh
# Integration: --serve binds loopback, requires an API key, and refuses 0.0.0.0.
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

"$BIN" --serve 127.0.0.1:0 --api-key-file "$TMP/key" --backend log \
  --log-file "$TMP/t.log" --no-hud >"$TMP/out" 2>&1 &
PID=$!

PORT=""
i=0
while [ "$i" -lt 50 ]; do
  if grep -q 'listening on 127.0.0.1:' "$TMP/out" 2>/dev/null; then
    PORT=$(sed -n 's/.*listening on 127.0.0.1:\([0-9][0-9]*\).*/\1/p' "$TMP/out" | head -n 1)
    break
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "server exited early" >&2
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
if ! grep -q 'no network listen' "$TMP/out"; then
  echo "collector did not report that it skips the network" >&2
  cat "$TMP/out" >&2
  exit 1
fi

PORT="$PORT" python3 - <<'PY'
import os, sys, time, urllib.request
port = os.environ["PORT"]
url = "http://127.0.0.1:%s/metrics" % port
try:
    urllib.request.urlopen(url, timeout=2)
    sys.exit("expected 401 without a key")
except Exception as e:
    if "401" not in str(e):
        sys.exit("expected 401, got %s" % e)
bad = urllib.request.Request(url, headers={"Authorization": "Bearer wrong"})
try:
    urllib.request.urlopen(bad, timeout=2)
    sys.exit("expected 401 for a bad key")
except Exception as e:
    if "401" not in str(e):
        sys.exit("expected 401 for a bad key, got %s" % e)
body = ""
for _ in range(40):
    req = urllib.request.Request(url, headers={"Authorization": "Bearer secret-key"})
    body = urllib.request.urlopen(req, timeout=2).read().decode("ascii", "replace")
    if "12.5" in body:
        break
    time.sleep(0.25)
else:
    sys.exit("authorized /metrics missing 12.5: " + body)
req = urllib.request.Request("http://127.0.0.1:%s/health" % port,
                              headers={"X-API-Key": "secret-key"})
health = urllib.request.urlopen(req, timeout=2).read().decode()
if health.strip() != "ok":
    sys.exit("health: " + health)
print("cli serve ok")
PY

# Policy rejects. These must fail before bind.
if "$BIN" --serve 0.0.0.0:9100 --api-key secret-key --backend log \
     --log-file "$TMP/t.log" --no-hud >"$TMP/rej" 2>&1; then
  echo "0.0.0.0 with a key should be refused" >&2
  exit 1
fi
if ! grep -q '0.0.0.0' "$TMP/rej"; then
  echo "missing 0.0.0.0 explanation" >&2
  cat "$TMP/rej" >&2
  exit 1
fi
if "$BIN" --serve 127.0.0.1:9100 --backend log --log-file "$TMP/t.log" --no-hud \
     >"$TMP/nokey" 2>&1; then
  echo "loopback without an API key should be refused" >&2
  exit 1
fi
if ! grep -q 'API key' "$TMP/nokey"; then
  echo "missing API key explanation" >&2
  cat "$TMP/nokey" >&2
  exit 1
fi

echo "cli_serve ok"
