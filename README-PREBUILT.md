# llama.SPY prebuilt test bundle

Version **0.1.0-test2**. Binary name: `llamaspy`. Product: **llama.SPY**.

## Layout

```
llamaspy-<os>-amd64/
  bin/llamaspy
  bin/run-hook-smoke.sh
  scripts/llama_decode.d
  examples/hook.sample.json
  examples/codes.sample.gg
  locales/en.json
  locales/ja.json
  README.md
  README-PREBUILT.md
  LICENSE
  VERSION
```

## Unpack (Linux amd64)

```sh
tar -xzf llamaspy-linux-amd64-0.1.0-test2.tar.gz
cd llamaspy-linux-amd64
```

## HookScript smoke (no llama-server required)

```sh
./bin/run-hook-smoke.sh
# expect echo → {"ok":true,"echo":{"msg":"hi"}}
# expect add  → {"sum":5}
```

Or manually:

```sh
./bin/llamaspy --hook-file examples/hook.sample.json --list-tools
./bin/llamaspy --hook-file examples/hook.sample.json --call-tool echo '{"msg":"hi"}'
./bin/llamaspy --hook-file examples/hook.sample.json --call-tool add '{"a":2,"b":3}'
```

You can invoke `bin/llamaspy` from any cwd; pass absolute or relative paths to
`--hook-file` / `--gg-file`. The DTrace script resolver looks beside the
executable (`../scripts/llama_decode.d` when the binary lives in `bin/`), so
`--backend dtrace` works without cd'ing first (FreeBSD only).

## HTTP metrics HUD (needs a running llama-server with --metrics)

```sh
./bin/llamaspy --backend http \
  --metrics-url http://127.0.0.1:8080/metrics
```

Optional: `--slots-url`, `--api-key`, `--no-hud`.

## FreeBSD DTrace (when FreeBSD binary is available)

```sh
# as root or with dtrace privileges; target already running
./bin/llamaspy --backend dtrace --pid "$(pgrep -n llama-server)"
# script auto-resolves to ../scripts/llama_decode.d from bin/
```

Linux live attach: `sudo ./bin/llamaspy --backend auto --pid PID` (needs bpftrace). FreeBSD: same command uses dtrace.

## Runtime deps (Linux)

Dynamically linked against glibc + libstdc++ (typical Ubuntu/Debian amd64).
No system Duktape package required (vendored at build time).

## Known stubs in this test build

- Mem backend for Game Genie bindings (metadata only)
- `--serve` privsep collector
- `--from-url` remote draft (no remote exec)

See `STATUS.txt` in the source repo and `docs/` for design notes.
