# llama.SPY Design Notes (FreeBSD-first)

Official product name: **llama.SPY** (codename aliases: LlamaSpy / LlamaSnoop).

Locked from the AI Mode requirements audit + operator override: **FreeBSD is the primary v1 platform**. DTrace userland `pid` provider on `llama_decode` is the flagship backend. HTTP `/metrics` is a portable fallback (also what this Linux box can exercise). Linux/eBPF, Windows, Termux, and macOS are first-class *peers* that land after FreeBSD works — not the center of this document.

## Goals

- Zero-restart, non-invasive, read-only MVP for a running `llama.cpp` process.
- Hermes is an example stack only; llama-ui is admired, not the product.
- Beautiful TUI later; this scaffold prints SnoopV1 human summaries and ships a HUD string stub.
- Optional microservice only with privilege separation (collector never serves the net).

## Ingestion order (least invasive first)

1. **HTTP** `GET /metrics` (+ `/slots` later) if `llama-server` was started with `--metrics`.
2. **stderr / log hijack** (future; e.g. FD steal when timings already print).
3. **Platform tracing — FreeBSD DTrace first** (`scripts/llama_decode.d`, `pid$target::*llama_decode*:entry/return`).
4. **Opt-in Game Genie** — paste-in **HookScripts** that mint tool calls (JSON now; JS body next); LLMS1 offsets are a simple dialect.

## Why FreeBSD first

- DTrace is mature, safe for production attach, and maps cleanly to `llama_decode` latency without rewriting the target.
- Capsicum + `socketpair` give a crisp privsep story for an optional metrics microservice.
- Linux eBPF/Yama and Windows dbgeng are valuable but noisier; shipping FreeBSD proves SnoopV1 + IPC + TUI before port sprawl.

## TelemetryProvider

```
Attach(pid | metrics_url) → StreamMetrics(cb) → Detach()
```

Implementations:

| Backend | Role | Status in scaffold |
|---------|------|--------------------|
| `dtrace-freebsd` | Primary | Real spawn+parse on `__FreeBSD__`; stub elsewhere |
| `http-metrics` | Portable fallback | POSIX sockets + Prometheus text parser |
| (later) eBPF / Frida / Win32 / stderr | Peers | Not in this tree yet |

`auto` on FreeBSD prefers DTrace when `--pid` is set; elsewhere requires `--metrics-url`.

## SnoopV1 frame layout

Magic `0x4C4C4D53` (`LLMS`), version `1`, packed **64 bytes**.

| Offset | Type | Field |
|-------:|------|-------|
| 0 | u32 | magic |
| 4 | u16 | version |
| 6 | u16 | flags |
| 8 | u64 | timestamp_ns |
| 16 | u32 | pid |
| 20 | u32 | decode_count |
| 24 | f64 | predicted_tok_s |
| 32 | f64 | prompt_tok_s |
| 40 | u32 | requests_processing |
| 44 | u32 | requests_deferred |
| 48 | u64 | decode_latency_ns_sum |
| 56 | u32 | decode_latency_n |
| 60 | u32 | reserved |

Wire crossing uses `snoop_hton` / `snoop_ntoh` (byte-swap on little-endian hosts, including IEEE-754 doubles).

## IPC: SHM ring + mutex option

### Byte-order rule (locked)

- **SHM ring = host byte order** for `SnoopV1Frame` slots and header atomics.
- **`snoop_hton` / `snoop_ntoh` only at the network / `socketpair` privilege boundary** (collector → serve wire, or any off-host hop). Do not hton into SHM.

### SharedRingHeader layout (Race Review harden)

`SharedRingHeader` puts each of these on its **own** `alignas(64)` cache line:

| Line | Fields |
|------|--------|
| 0 | `atomic<uint64_t> head` (producer) |
| 64 | `atomic<uint64_t> tail` (consumer) |
| 128 | meta: `capacity_frames`, `frame_bytes`, `magic`, `version`, `generation` |

`static_assert`s freeze: `head%64==0`, `tail%64==0`, `meta%64==0`, `tail-head>=64`, `meta-tail>=64`, and `std::atomic<uint64_t>::is_always_lock_free`. Header is **POD atomics only** — no mutex in the SHM path.

`generation` is reserved for collector-restart poison / remap detection (consumer must drop frames or remount when generation changes). Capacity is in frames of `sizeof(SnoopV1Frame)`.

### SPSC ring protocol sketch (not implemented yet)

Single producer (collector), single consumer (serve or TUI). Slot array begins immediately after the header (or at a documented offset). Indices are free-running counters; slot index = `index % capacity_frames`.

**Publish (producer):**

1. Load `tail` with `memory_order_acquire` (or relaxed + later fence — TBD at impl).
2. If `head - tail == capacity` → **full**: drop-vs-block policy **TBD** (MVP likely drop-oldest or drop-new; document when coding).
3. Write full `SnoopV1Frame` payload into slot `[head % capacity]` (host order).
4. Store `head = head + 1` with **`memory_order_release`** so the consumer cannot see the new head until the payload write is visible.

**Consume (consumer):**

1. Load `head` with `memory_order_acquire`.
2. If `tail == head` → empty; wait or poll.
3. Read payload from slot `[tail % capacity]`.
4. Store `tail = tail + 1` with **`memory_order_release`**.

**Init / attach:** one writer zeros head/tail, sets capacity/magic/version, bumps `generation` on collector restart so stale consumers poison. Concurrent first-attach and crash mid-frame are TBD with the publish/consume impl.

**RO mapping conflict:** a true read-only map in serve **cannot** advance `tail`. See [PRIVSEP.md](PRIVSEP.md) — MVP uses **socketpair for `--serve`** until an SHM protocol (dual map, or seqlock/double-buffer for truly RO serve) lands.

Also support a mutex + condition-variable ring for hosts/workloads where lockless is the wrong trade. FreeBSD collector ↔ dropped-priv TUI/web should prefer `socketpair` (MVP) or SHM with Capsicum-limited FDs once the protocol above exists.

## Privilege separation (optional microservice)

```
[ high-priv collector ] --socketpair/SHM SnoopV1--> [ dropped-priv TUI/web ]
        |                                              |
   DTrace / mem read                              Capsicum / chroot /
   never binds :443                               setuid nobody; no raw FS
```

Collector must not listen on the network. Web/TUI never holds `dtrace` or ptrace credentials.

Concrete FreeBSD Capsicum + `socketpair` sequence (and Linux landlock/seccomp sketch):
see [PRIVSEP.md](PRIVSEP.md). `--serve` is intentionally unimplemented in MVP.

## FreeBSD DTrace script

`scripts/llama_decode.d`:

- `pid$target::*llama_decode*:entry` stores `timestamp`.
- `:return` aggregates avg/max/count; `profile:::tick-1s` prints `timestamp_ns decode_count avg_latency_ns` for the provider to parse.
- C++ mangling: wildcard `*llama_decode*` until we pin a demangled / `extern "C"` symbol list per build.

Provider may later embed **libdtrace** instead of spawning `/usr/sbin/dtrace`.

## Game Genie — HookScripts that mint tool calls

Primary story: paste-in **HookScripts** (DTrace-shaped) that `Register` one or
more tools into `ToolRegistry`. Full spec: [GAME_GENIE.md](GAME_GENIE.md).

```
load → validate → attach probes → Register tools → unload drops tools
```

- **`--hook-file`**: JSON HookScript (`llamaspy_hook`, `tools[]`, optional
  `bindings[]`, reserved `js_body`) **or** LLMS1 pipe file.
- **`ToolRegistry`**: in-memory `Register` / `Unregister` / `List`; `--list-tools`.
- **`--from-url`**: stub only — review-before-load; **no blind remote execute**.
- **LLMS1** (`--gg-file`): supported simple dialect for offset bindings.
- Delivery prior art: [phantom-kv](https://github.com/lordx64/phantom-kv)
  (loadable reversible grafts) — steal the *pipe*, not refusal-removal.
- Read-only default; write/graft opt-in explicit. Own-process only.
- JS/Lua body execution: **not embedded yet** (`js_body` stored, not run).
- `ApplyReadOnly(pid)` still stubbed until mem backends land.

No memory writes in MVP. Linux memory engine (later) **must** use `PTRACE_O_TRACEEXIT` to avoid zombies.

## Platform matrix

| Platform | Primary attach | Notes |
|----------|----------------|-------|
| **FreeBSD** | DTrace pid | **v1 home** |
| Linux | HTTP → eBPF / `process_vm_readv` | `PTRACE_O_TRACEEXIT` when using ptrace |
| Termux/Android | HTTP → Frida / limited ptrace | Peer after FreeBSD |
| macOS | DTrace (SIP caveats) / HTTP | Share `.d` script where allowed |
| Windows | HTTP → ReadProcessMemory / dbgeng | Peer |

## TUI

`include/llamaspy/tui_stub.hpp` + `src/tui_stub.cpp` — one-pane ANSI HUD (no ncurses yet):
ingest/gen tok/s, busy slots, `n_decode` + derived decode rate, attach-mode badge
(`dtrace|http|log|auto`). `main` refreshes each poll; `--no-hud` keeps the old
`[SnoopV1]` line stream. Fullscreen/sparklines TUI is a later milestone.

## Prior art

See [PRIOR_ART.md](PRIOR_ART.md) — higkoo dashboard, llama.cpp `--metrics`, VictoriaMetrics writeups, ProfInfer eBPF ladder, scanmem for paste-in search, phantom-kv for loadable reversible grafts (delivery only). Differentiator: **attach without restart**, FreeBSD DTrace first, HookScripts that mint tools.

## Contentious choices (flag for pushback)

1. **SnoopV1 fixed at 64 bytes** — doubles for tok/s; expand via version bump, not silent field inserts.
2. **Spawn `dtrace` vs libdtrace** — scaffold spawns for debuggability; embedding is TODO on FreeBSD.
3. **Wildcard `*llama_decode*`** — may over-match; tighten once we inventory symbols on real FreeBSD llama.cpp builds.
4. **HTTP metric names** — parse current Prometheus names (`llamacpp:predicted_tokens_seconds`, etc.); label variants ignored for MVP.
5. **Game Genie** — HookScripts mint tools; LLMS1 is the offset subset; JS engine + auto-POST deferred.
