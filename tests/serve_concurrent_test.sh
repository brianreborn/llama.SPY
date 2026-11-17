#!/bin/sh
# A slow client must not hold the accept loop. A second request still returns.
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

PORT="$PORT" python3 - <<'PY'
import os, socket, threading, time
port = int(os.environ["PORT"])

def slow():
    s = socket.create_connection(("127.0.0.1", port), timeout=2)
    s.settimeout(3)
    # Drip a request so a serial server would sit in recv.
    for b in b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\n":
        s.send(bytes([b]))
        time.sleep(0.05)
    time.sleep(1.5)
    s.close()

t = threading.Thread(target=slow)
t.start()
time.sleep(0.2)
s = socket.create_connection(("127.0.0.1", port), timeout=2)
s.settimeout(1.5)
req = (
    "GET /metrics HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Authorization: Bearer secret-key\r\n"
    "Connection: close\r\n\r\n"
)
s.sendall(req.encode("ascii"))
data = b""
while b"llamacpp:" not in data and len(data) < 8192:
    chunk = s.recv(1024)
    if not chunk:
        break
    data += chunk
s.close()
t.join(timeout=3)
text = data.decode("ascii", "replace")
if "12.5" not in text:
    raise SystemExit("fast client blocked or missing metric:\n" + text)
print("serve concurrent ok")
PY
