# llama.SPY — Prior Art & Gaps

Codename aliases: LlamaSpy / LlamaSnoop.

Researched 2026-10-26..27 (America/Los_Angeles). Cite and reuse; do not reinvent.

**Operator override:** FreeBSD-first (DTrace primary). Ignore any “Linux first” slice wording below that came from the research draft; HTTP `/metrics` remains the portable fallback.

## Prior art

### Native llama.cpp (Tier-1)

- [llama-server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md) — `/metrics` (Prometheus), `/slots`; router needs `?model=`; `--api-key` gates.
- [PR #27041](https://github.com/ggml-org/llama.cpp/pull/27041) (merged) — live `/metrics`+`/slots` during `llama_decode`.
- [PR #25813](https://github.com/ggml-org/llama.cpp/pull/25813) (open) — proposed realtime per-slot `pp_*` / `tg_*`; not merged.
- [PR #21293](https://github.com/ggml-org/llama.cpp/pull/21293) (closed) — SSE `/monitor` ideas only.

Metric names to map: `llamacpp:predicted_tokens_seconds`, `prompt_tokens_seconds`, `n_decode_total`, speculative counters.

### HTTP dashboards (need `--metrics` — not zero-restart)

- [higkoo/llama.cpp-Monitor-Dashboard](https://github.com/higkoo/llama.cpp-Monitor-Dashboard)
- [jungrok5/zerollama-dashboard](https://github.com/jungrok5/zerollama-dashboard)
- [Grafana 25591](https://grafana.com/grafana/dashboards/25591-llama-cpp-monitoring/)
- [VictoriaMetrics writeup](https://rtfm.co.ua/en/llama-cpp-metrics-and-monitoring-with-victoriametrics/) — router scrape pitfalls

### Hermes-adjacent (example stack only)

- Hermes token-rate plugin PRs (log tail of `llama-server.log`)
- nevermore131315/llama-inference-monitor, Ayshinko/hermes-token-speed, TacoTakumi/hermes-provider-llamacpp

### Tracing / attach (Tier-3)

- **ProfInfer** (MLSys 2026 / [arXiv:2601.20755](https://arxiv.org/abs/2601.20755)) — eBPF uprobe ladder: `llama_decode` → `ggml_backend_graph_compute_async` → `ggml_compute_forward`. No public code found.
- [bpftime](https://eunomia-bpf.github.io/bpftime/) — userspace eBPF + Frida-gum.
- Keshri-Ankit/llm-tui-monitor — cooperative `cb_eval` only (not attach-to-running).
- FreeBSD DTrace pid provider — `pid$target::llama_decode:entry/return`; C++ mangling expected.
- `process_vm_readv(2)` — preferred Linux mem read; Yama/`PTRACE_MODE_ATTACH_REALCREDS`.
- [scanmem](https://github.com/scanmem/scanmem) — `sm_attach` / search for paste-in Game Genie bindings (read-only; ignore `sm_setaddr`).
- [phantom-kv](https://github.com/lordx64/phantom-kv) — loadable, reversible runtime grafts (KV-cache pills), mid-session hot-swap, no weight edit. **Cite for delivery only** (paste/load/unload); llama.SPY does **not** productize refusal-removal.

### X

- LIMCARS (@AgentSparko) — live dashboard layout reference, not process-attach.

## Gaps (track until closed)

1. HTTP version matrix (#27041 vs older; #25813 unmerged).
2. Router / multi-model discovery (`/v1/models`, `/props`).
3. Auth for dropped-priv web + OS sandbox matrix (capsicum / landlock / AppContainer / sandbox-exec).
4. llama-cli stderr timing corpus + FD hijack vs `tail -F`.
5. Symbol/ABI: C API + build hash; paste-in offsets; never hardcode VA.
6. Game Genie HookScripts + ToolRegistry; LLMS1 dialect; JS body engine; fingerprint/ASLR; read-only default; no auto-POST.
7. Termux: HTTP/log unless root or cooperative spawn.
8. Windows SeDebug / macOS SIP UX (never “disable SIP”).
9. Packaging: CMake presets; soft deps (Frida/libbpf/scanmem).
10. SnoopV1 ↔ Prometheus/slots mapping, SHM size, overruns, clock.
11. `PTRACE_O_TRACEEXIT` + `waitpid` + `ESRCH`.
12. Own-process-only ToS; no write-capable codes in MVP.

## Safety

| Risk | Note |
|------|------|
| ptrace / process_vm_* | Own processes only; document debugger-class attach |
| Game Genie / HookScript | Own-process; read-only default; no blind remote exec; review-before-load for URL |
| Frida / eBPF | Soft-feature; AV false positives |
| Microservice | Collector never binds public net; MVP metrics-only (no KV/text in SHM) |
| macOS SIP / Windows SeDebug | Clear prompts; no “disable SIP” path |

## v1 implementation slice (FreeBSD first)

1. FreeBSD DTrace collector on `llama_decode` → SnoopV1 (stdout JSON + `alignas(64)` SHM ring).
2. Portable HttpMetrics (`/metrics` + `/slots`, `--api-key`, `?model=`) — also builds on Linux for CI/dogfood.
3. Minimal TUI: ingest/gen tok/s, busy slots, n_decode rate, attach-mode badge.
4. Defer: eBPF/Frida/process_vm, JS HookScript engine, `--serve` privsep web, auto-calibration.
