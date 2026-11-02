# llama.SPY

**FreeBSD-first** C++20 realtime observability for a running [llama.cpp](https://github.com/ggml-org/llama.cpp) process — zero restart, read-only MVP.

Also known in design discussions as *LlamaSpy* / *LlamaSnoop* (codename aliases).

Primary backend: **DTrace** userland `pid` provider on `llama_decode` (`scripts/llama_decode.d`).  
Portable fallback: poll `llama-server` **HTTP `/metrics`** (Prometheus text).

Hermes is an example stack only.

## Prebuilt test builds

Download a ready-to-run bundle from [Releases](https://github.com/brianreborn/llama.SPY/releases) (latest **v0.1.0-test2**: Linux + FreeBSD live attach).

- Linux amd64: unpack and run `./bin/run-hook-smoke.sh` — see [README-PREBUILT.md](README-PREBUILT.md)
- FreeBSD amd64: attached when CI / qodesh produces it

---

## Build

### FreeBSD (primary)

```sh
pkg install cmake llvm   # dtrace is usually in base; ensure C++20 toolchain
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

On FreeBSD, CMake defines `LLAMASPY_FREEBSD=1`, enabling the real DTrace provider (sources gate on `LLAMASPY_FREEBSD || __FreeBSD__`).

### DTrace script resolution

First match wins:
1. `--dtrace-script PATH`
2. env `LLAMASPY_DTRACE_SCRIPT`
3. `scripts/llama_decode.d` relative to cwd
4. beside the executable (`<exe>/llama_decode.d`, `<exe>/scripts/`, `<exe>/../scripts/`, `<exe>/../share/llamaspy/`)
5. compile-time install dir `${CMAKE_INSTALL_PREFIX}/share/llamaspy/llama_decode.d` (set prefix at configure: `cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..`)

### Linux (HTTP + bpftrace live attach)

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Live attach uses **bpftrace uprobes** on `llama_decode` (`--backend bpftrace` or `auto --pid PID`), mirroring `scripts/llama_decode.d` via `scripts/llama_decode.bt`. The target ELF is `libllama*.so` from `/proc/PID/maps`, else `/proc/PID/exe`. Needs `bpftrace` installed and root (or CAP_BPF+CAP_PERFMON; CAP_SYS_ADMIN on older kernels). Read-only, no ptrace, target untouched. Same `ts n avg_ns` lines → SnoopV1 frames as DTrace.

Shared smoke for both OSes: `bin/run-attach-smoke.sh [--pid PID] [--metrics-url URL]`.

Dependencies: C++20 STL + POSIX sockets + vendored Duktape C amalgamation (no Boost, no libcurl, no system JS package).  
Binary name: `llamaspy` (filesystem-safe); product name: **llama.SPY**.

## Run

### FreeBSD — DTrace (preferred)

```sh
# as root or with dtrace privileges; target already running
./build/llamaspy --backend dtrace --pid $(pgrep -n llama-server) \
  --dtrace-script scripts/llama_decode.d
```

Or `auto` with a pid:

```sh
./build/llamaspy --backend auto --pid $PID
```

### Anywhere — HTTP `/metrics`

Start llama-server with `--metrics`, then:

```sh
./build/llamaspy --backend http \
  --metrics-url http://127.0.0.1:8080/metrics
```

Optional HTTP enrichment (same host/port `/slots` by default; Bearer via `--api-key`):

```sh
./build/llamaspy --backend http \
  --metrics-url http://127.0.0.1:8080/metrics \
  --slots-url http://127.0.0.1:8080/slots \
  --api-key "$LLAMA_API_KEY"
```

Cooperative log timing stub (no FD hijack yet) — see [docs/METRICS_MAP.md](docs/METRICS_MAP.md):

```sh
./build/llamaspy --backend log --log-file /path/to/llama.log --no-hud
```

Default: a one-pane ANSI **HUD** refreshes each poll (gen/ingest tok/s, busy
slots, `n_decode` + decode rate, attach-mode badge `dtrace|http|log|auto`).
Pass `--no-hud` for classic one-line `[SnoopV1]` summaries instead.

### Game Genie — HookScripts that mint tool calls

Paste-in hooks (DTrace-shaped) that register **tool calls** into an in-memory
`ToolRegistry`. JSON HookScript is the primary path; LLMS1 offset codes are a
simple dialect. See [docs/GAME_GENIE.md](docs/GAME_GENIE.md).

```sh
# load HookScript, register tools (manifest + js_body), list, exit
./build/llamaspy --hook-file examples/hook.sample.json --list-tools

# invoke a JS-registered tool
./build/llamaspy --hook-file examples/hook.sample.json \
  --call-tool add '{"a":2,"b":3}'

# LLMS1 simple dialect still works
./build/llamaspy --gg-file examples/codes.sample.gg

# URL import is a stub (review-before-load later; no remote exec)
./build/llamaspy --from-url https://example.com/hooks/slot-watch.json
```

`js_body` runs in **vendored Duktape** (`third_party/duktape`, default
`-DLLAMASPY_JS=ON`). Host API: `registerTool`, `log`, `readBinding` (metadata
stub) — **no net, no fs**. Read-only default; own-process only. Delivery prior
art: [phantom-kv](https://github.com/lordx64/phantom-kv) (loadable reversible
grafts) — observability tooling only, not refusal-removal.

### i18n

CLI help + HUD labels via `T("key")`. Auto-pick: `LLAMASPY_LANG` → `LANG` /
`LC_MESSAGES` (prefix `en`, `ja`, …); fallback `en`. Ship `locales/en.json` +
`locales/ja.json`. **Add a language:** copy `locales/en.json` → `locales/xx.json`
(and extend the built-in table until a JSON loader lands). No gettext toolchain.

## Diagrams

Mermaid diagrams of `main` (`a0f4916`, v0.1.0-test2), rendered by GitHub. The text privsep diagram in [docs/PRIVSEP.md](docs/PRIVSEP.md) and the SnoopV1 / ring tables in [docs/DESIGN.md](docs/DESIGN.md) stay as they are. Dashed parts are designed, not implemented.

### Components and data path

```mermaid
flowchart LR
  target["running llama-server<br/>(not modified, no ptrace)"]
  subgraph backends["TelemetryProvider backends"]
    dtrace["dtrace-freebsd<br/>scripts/llama_decode.d<br/>pid provider on llama_decode"]
    bpf["bpftrace-linux<br/>scripts/llama_decode.bt<br/>uprobe on llama_decode"]
    http["http-metrics<br/>GET /metrics (Prometheus text)"]
    logp["log-timings<br/>--backend log --log-file"]
  end
  frame["SnoopV1 frame<br/>64 bytes, magic LLMS"]
  hud["HUD / summary output<br/>i18n en, ja"]
  gg["Game Genie<br/>HookScripts -> ToolRegistry<br/>Duktape js_body"]
  stdout["stdout"]
  serve["--serve (stub, exits 2;<br/>designed: dropped privileges, HTTP / TUI)"]

  target -->|FreeBSD, --pid| dtrace
  target -->|Linux, --pid| bpf
  target -->|--metrics-url| http
  target -->|--log-file| logp
  logp --> frame
  dtrace --> frame
  bpf --> frame
  http --> frame
  frame --> hud
  gg -->|--list-tools, --call-tool| stdout
  frame -.->|"designed: socketpair, later SHM ring"| serve
  classDef planned stroke-dasharray: 4 3
  class serve planned
```

`auto` picks DTrace on FreeBSD and bpftrace on Linux when `--pid` is given; otherwise it needs `--metrics-url` or `--log-file`. On other systems `auto --pid` errors (no live-attach backend). `uprobe` is an alias for `bpftrace`. `--serve` is drawn dashed because it is a stub that exits 2.

### Provider lifecycle

```mermaid
stateDiagram-v2
  [*] --> Select: --backend dtrace | bpftrace (uprobe) | http | log | auto
  Select --> Attach: pid, metrics URL or log file
  Select --> Error: auto without --pid, --metrics-url or --log-file, or auto --pid off FreeBSD / Linux (exit 2)
  Attach --> Streaming: tracer forked / URL set / log file set
  Attach --> Error: /proc unreadable, script missing, fork / pipe failed, wrong-OS stub NotSupported (exit 1)
  Streaming --> Streaming: ts n avg_ns lines -> SnoopV1 frames
  Streaming --> Streaming: http GET failed, retry after 1 s
  Streaming --> Detach: tracer exited (no privileges, CAP_BPF + CAP_PERFMON, or target gone), exit 0
  Streaming --> Detach: Ctrl-C / SIGTERM, or target exit (dtrace / bpftrace only)
  Detach --> [*]: SIGINT (bpftrace) or SIGTERM (dtrace), waitpid
  Error --> [*]
```

### IPC: SPSC ring (designed, not implemented)

```mermaid
sequenceDiagram
  participant C as Collector (producer)
  participant H as SharedRingHeader (head, tail, meta on own 64-byte lines)
  participant S as Serve or TUI (consumer)
  C->>H: load tail (acquire)
  alt head - tail == capacity
    C->>C: full (drop policy to be decided)
  else space
    C->>H: write frame into slot head % capacity (host byte order)
    C->>H: store head + 1 (release)
  end
  S->>H: load head (acquire)
  alt tail == head
    S->>S: empty, poll
  else frame ready
    S->>H: read slot tail % capacity
    S->>H: store tail + 1 (release)
  end
  Note over C,S: generation bump on collector restart poisons stale consumers.<br/>Designed MVP for --serve: socketpair, hton / ntoh only at that boundary.
```

### Privilege separation (designed for `--serve`)

```mermaid
flowchart TB
  parent["parent: socketpair(AF_UNIX, SOCK_SEQPACKET)<br/>then reaper"]
  coll["collector child<br/>DTrace / bpftrace / metrics<br/>never binds a port"]
  srv["serve child<br/>listen, accept, render<br/>never opens /dev/dtrace*"]
  parent -->|fork| coll
  parent -->|fork| srv
  coll -.->|"SnoopV1 frames over the FD<br/>(Capsicum: CAP_SEND)"| srv
```

### Data model

```mermaid
erDiagram
  SNOOP_V1_FRAME {
    u32 magic
    u16 version
    u16 flags
    u64 timestamp_ns
    u32 pid
    u32 decode_count
    f64 predicted_tok_s
    f64 prompt_tok_s
    u32 requests_processing
    u32 requests_deferred
    u64 decode_latency_ns_sum
    u32 decode_latency_n
    u32 reserved
  }
  HOOK_SCRIPT ||--o{ TOOL : "registers"
  TOOL_REGISTRY ||--o{ TOOL : "holds (in memory)"
  HOOK_SCRIPT {
    int llamaspy_hook
    string name
    bool readonly
    list tools
    list bindings
    string js_body
  }
  TOOL {
    string name
    string description
    json json_schema
    string handler
  }
```

### Where it runs

```mermaid
flowchart LR
  fbsd["FreeBSD node<br/>primary: DTrace attach"]
  linux["Linux nodes (GPU node, CI node, test node)<br/>bpftrace attach or /metrics"]
  other["Windows, Termux, macOS<br/>/metrics or --log-file only for now"]
  fbsd --- spy(("llama.SPY"))
  linux --- spy
  other -.- spy
```

## Layout

```
include/llamaspy/   snoop_v1, telemetry_provider, metrics_http, tui_stub, game_genie,
                   hook_script, tool_registry, js_engine, i18n
src/                main, metrics_http, provider_dtrace_freebsd, tui_stub, game_genie,
                   hook_script, tool_registry, js_engine, log_timings, i18n
third_party/        duktape/ (vendored amalgamation for js_body)
scripts/            llama_decode.d
examples/           hook.sample.json, codes.sample.gg
locales/            en.json, ja.json
docs/               DESIGN, PRIOR_ART, PRIVSEP, GAME_GENIE, METRICS_MAP
```

Repo directory: `/workspace/llama.SPY`.

## Docs

- [Design notes](docs/DESIGN.md) — SnoopV1, IPC `alignas(64)`, Capsicum privsep, Game Genie paste-in
- [Game Genie / HookScripts](docs/GAME_GENIE.md) — hooks that mint tools; `--hook-file` / `--list-tools`
- [Privilege separation](docs/PRIVSEP.md) — FreeBSD Capsicum + socketpair; Linux landlock/seccomp sketch
- [Prior art](docs/PRIOR_ART.md) — verified links; FreeBSD-first override noted at top

## Status

Scaffold: builds on Linux (HTTP + HUD + HookScript/ToolRegistry + Duktape `js_body` + i18n en/ja), FreeBSD DTrace behind `#if defined(LLAMASPY_FREEBSD) || defined(__FreeBSD__)`. No memory writes. `--serve` documented, not implemented. FreeBSD live testing deferred until first-test e2e. Fullscreen TUI later.

## Localization

UI strings (banner, help, HUD labels) come from flat JSON in `locales/<lang>.json`. Language is picked from `--lang xx`, else `LLAMASPY_LANG`, `LC_ALL`, `LANG` (`ja_JP.UTF-8` → `ja`), default `en`; missing keys fall back to English, then the key. Files are searched in `$LLAMASPY_LOCALEDIR`, `./locales`, beside the exe (and its parent), and `share/llamaspy/locales`.
**Add a language:** copy `locales/en.json` to `locales/xx.json` and translate the values. No gettext.
