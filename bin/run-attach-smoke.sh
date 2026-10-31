#!/bin/sh
# llama.SPY shared smoke (Linux + FreeBSD): HookScript, HTTP metrics, live attach.
# Usage: bin/run-attach-smoke.sh [--pid PID] [--metrics-url URL] [--seconds N]
# Live attach needs root: FreeBSD dtrace(1); Linux bpftrace(8) (root or CAP_BPF+CAP_PERFMON).
cd "$(dirname "$0")/.." || exit 1
B=./bin/llamaspy; [ -x "$B" ] || B=./build/llamaspy
PID=""; URL=""; SECS=5
while [ $# -gt 0 ]; do case "$1" in
  --pid) PID=$2; shift 2;; --metrics-url) URL=$2; shift 2;; --seconds) SECS=$2; shift 2;;
  *) echo "unknown arg $1"; exit 2;; esac; done
[ -z "$PID" ] && PID=$(pgrep -n llama-server 2>/dev/null)
[ -z "$URL" ] && [ -n "$PID" ] && URL=http://127.0.0.1:8080/metrics
fail=0; os=$(uname -s)
echo "== llama.SPY smoke on $os ($(cat VERSION 2>/dev/null))"
r=$($B --hook-file examples/hook.sample.json --call-tool echo '{"msg":"hi"}' 2>/dev/null | tail -1)
echo "hook echo: $r"; [ "$r" = '{"ok":true,"echo":{"msg":"hi"}}' ] || fail=1
r=$($B --hook-file examples/hook.sample.json --call-tool add '{"a":2,"b":3}' 2>/dev/null | tail -1)
echo "hook add:  $r"; [ "$r" = '{"sum":5}' ] || fail=1
if [ -n "$URL" ]; then
  echo "-- http $URL"; timeout "$SECS" $B --backend http --metrics-url "$URL" --no-hud 2>&1 | tail -3
else echo "-- http: SKIP (no --metrics-url / llama-server)"; fi
if [ -n "$PID" ]; then
  SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo -n"
  echo "-- live attach (auto) pid=$PID ${SUDO:+via sudo}"
  timeout "$SECS" $SUDO $B --backend auto --pid "$PID" --no-hud 2>&1 | tail -5
  echo "   (frames appear only while llama_decode runs: send a prompt during the window)"
else echo "-- live attach: SKIP (no --pid / llama-server running)"; fi
[ $fail = 0 ] && echo "SMOKE: PASS" || echo "SMOKE: FAIL"; exit $fail
