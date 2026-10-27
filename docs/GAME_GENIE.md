# llama.SPY Game Genie — paste-in hooks that mint tool calls

**Game Genie** is how operators graft live tooling onto a process they already
control — same spirit as DTrace: load something, attach probes, get new
capabilities **without restarting** the target or rewriting its binary.

Headline: **paste-in HookScripts that register one or more tool calls**.
Offset codes (`LLMS1|…`) remain a supported **simple dialect** for “read this
symbol at this offset” — a subset, not the product story.

Companion: [DESIGN.md](DESIGN.md), [PRIVSEP.md](PRIVSEP.md),
`examples/hook.sample.json`, `examples/codes.sample.gg`.

## What we steal (and what we don’t)

Prior art for *delivery*: [phantom-kv](https://github.com/lordx64/phantom-kv) —
loadable, reversible runtime grafts (KV-cache pills) with no weight edit and
mid-session hot-swap. llama.SPY takes the **delivery idea** (paste/load a
reversible payload; unload restores baseline) for **observability + operator
tooling**. We do **not** productize refusal-removal, jailbreaks, or any
guardrail-bypass feature. Steal the *pipe*, not the payload.

## Mental model (DTrace-shaped)

| DTrace | Game Genie / HookScript |
|--------|-------------------------|
| `.d` script | HookScript (JSON manifest + `js_body` via Duktape) |
| `pid$target::…` probes | declared attach: DTrace / HTTP / mem-read / later grafts |
| aggregations / actions | handlers behind **tool calls** |
| unload script | unload hook → **Unregister** every tool it minted |

Lifecycle:

```
load → validate → attach probes → Register tools → (operator uses tools)
unload → Detach probes → Unregister tools
```

Each HookScript may establish **one or more** new tool calls. The
`ToolRegistry` (`include/llamaspy/tool_registry.hpp`) is the in-process
catalog exposed to the TUI, optional `--serve`, and the operator CLI
(`--list-tools`).

## Primary format: HookScript manifest (JSON)

A HookScript file is JSON with a tools array and/or a `js_body` that runs in
the embedded **Duktape** engine (`third_party/duktape`, `LLAMASPY_JS=ON` by
default). Manifest `tools[]` register immediately; `js_body` may call
`registerTool(...)` to mint more tools at load time.

```json
{
  "llamaspy_hook": 1,
  "name": "slot-watch",
  "note": "example — fake offsets",
  "readonly": true,
  "tools": [
    {
      "name": "gg_read_n_past",
      "description": "Read n_past via declared binding",
      "json_schema": "{\"type\":\"object\",\"properties\":{}}",
      "handler": "read_binding:n_past"
    }
  ],
  "bindings": [
    "LLMS1|sym=n_past|off=0xdead0000|width=8|type=u64|fp=llama.cpp@fake|note=kv cursor"
  ],
  "js_body": "registerTool({name:\"echo\", description:\"demo\", schema:{}, handler:function(a){return a;}});\n"
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `llamaspy_hook` | yes | Manifest version (`1`) |
| `name` | yes | Hook id (also prefixes diagnostics) |
| `tools` | yes\* | Array of tool descriptors to `Register` |
| `tools[].name` | yes | Tool call name (unique in registry) |
| `tools[].description` | no | Human blurb for TUI / `--list-tools` |
| `tools[].json_schema` | no | JSON Schema string (or object; stored as text) |
| `tools[].handler` | no | Opaque handler tag (`read_binding:…`, `http:…`, `dtrace:…`, later `js:…`) |
| `bindings` | no | Inline `LLMS1` lines (simple dialect) |
| `readonly` | no | Default **true**. Write/graft handlers require explicit `readonly: false` |
| `js_body` / `script` | no | Duktape source; may call `registerTool` / `log` / `readBinding` |
| `note` | no | Free text |

\* A manifest with only `bindings` (no `tools`) is valid: it loads the
codebook and registers nothing (same as a pure LLMS1 file).

### CLI

```sh
# load HookScript (JSON) or LLMS1 file; register tools; dump; exit
./build/llamaspy --hook-file examples/hook.sample.json
./build/llamaspy --hook-file examples/codes.sample.gg

# list tools currently in the in-memory registry
./build/llamaspy --hook-file examples/hook.sample.json --list-tools

# invoke a tool (manifest or js_body-registered); print JSON result
./build/llamaspy --hook-file examples/hook.sample.json \
  --call-tool echo '{"msg":"hi"}'
./build/llamaspy --hook-file examples/hook.sample.json \
  --call-tool add '{"a":2,"b":3}'

# LLMS1-only alias (unchanged)
./build/llamaspy --gg-file examples/codes.sample.gg

# URL import stub — never fetches/executes remotely in this scaffold
./build/llamaspy --from-url https://example.com/hooks/slot-watch.json
```

### `js_body` host API (MVP)

Injected globals — **no network, no filesystem, no `require`**:

| API | Behavior |
|-----|----------|
| `registerTool({name, description?, schema?, handler})` | `handler` must be a JS function; registers into `ToolRegistry` with tag `js:<name>` |
| `log(...)` | writes a single line to stderr |
| `readBinding(sym)` | returns binding **metadata** from the HookScript codebook, or `null`; `value` is always null until a mem backend exists |

Build flag: `-DLLAMASPY_JS=ON` (default when `third_party/duktape/` is present).
`-DLLAMASPY_JS=OFF` keeps the binary green without executing `js_body`.

`--hook-file -` reads stdin. Detection: leading `{` → JSON HookScript;
otherwise → LLMS1 pipe dialect.

`--from-url` prints a stub message (`not implemented: will draft HookScripts
from project README`) and exits non-zero. Future: fetch → **show for
review** → require explicit confirm before load. **No blind remote execute.**

## Simple dialect: LLMS1 pipe codes

Human-greppable, chat-pasteable offset codes. Still fully supported; treated
as a HookScript with implicit empty `tools[]` and the lines as `bindings`.

```
LLMS1|sym=<name>|off=<hex-or-dec>|width=<bytes>|type=<ty>|fp=<fingerprint>|note=<text>
```

| Field | Required | Meaning |
|-------|----------|---------|
| magic | yes | Literal `LLMS1` |
| `sym=` | yes | Logical name |
| `off=` | yes | Byte offset (`0x…` or decimal). Aliases: `offset=`, `addr=` |
| `type=` | yes\* | `u8` `u16` `u32` `u64` `i32` `i64` `f32` `f64` |
| `width=` | yes\* | Byte width; omit → derive from type. Cap 64 |
| `fp=` / `build=` | no | Build fingerprint |
| `note=` | no | Free text (avoid raw `\|`) |

\* At least one of `type=` or `width=`. Blank / `#` lines are comments.
Unknown `key=` ignored (forward-compatible).

Sample: `examples/codes.sample.gg`.

## Mapping to TelemetryProvider + ToolRegistry

```
TelemetryProvider          ToolRegistry
  Attach / Stream / Detach   Register / Unregister / List
         │                            ▲
         │         HookScript          │
         └──── probes + handlers ──────┘
                    │
              SnoopV1 frames (metrics)
              + tool calls (operator)
```

- Providers keep feeding **SnoopV1** (observability).
- HookScripts mint **tools** (operator actions / reads) into `ToolRegistry`.
- Unload must drop both: detach any probes the hook owned, then
  `Unregister` every tool name it registered.
- Optional `--serve` (see PRIVSEP) may expose `List` over IPC later — same
  registry, dropped-priv side never holds dtrace/mem credentials.

## Security (non-negotiable)

| Rule | Detail |
|------|--------|
| Own-process only | Attach / mem / hooks only against processes the operator already controls |
| No blind remote exec | `--from-url` is review-before-load; default is local paste/file |
| Read-only default | Manifests default `readonly: true`; write/graft opt-in must be explicit |
| No remote script fetch by default | Operators paste or point at a local path |
| Sandbox notes | Hook handlers run in the **collector** privilege domain; never in the dropped-priv serve child. Capsicum/FD scrub still apply ([PRIVSEP.md](PRIVSEP.md)) |
| JS sandbox | Duktape host API only — no net/fs builtins injected; still treat paste-in JS as trusted operator code |
| Review-before-load | Future URL/import path must dump the manifest and wait for confirm |

Product scope: observability + operator tooling. Not refusal-removal, not
unattended RCE, not shipping hostile grafts.

## Runtime status (this slice)

| Piece | Status |
|-------|--------|
| HookScript JSON load + tool Register | **Implemented** |
| `ToolRegistry` in-memory + `--list-tools` | **Implemented** |
| `--hook-file` (JSON or LLMS1) | **Implemented** |
| `--call-tool` / `--invoke` | **Implemented** (JS + read_binding stub) |
| `--gg-file` LLMS1 dump | **Implemented** (kept) |
| `--from-url` | **Stub** (message only) |
| `ApplyReadOnly(pid)` for bindings | **Stub** |
| `js_body` via Duktape | **Implemented** (vendored; `LLAMASPY_JS`) |
| Write / graft handlers | **Opt-in later**; off by default |
| FreeBSD live dogfood | Deferred until first-test e2e (operator) |

## Contentious / pushback

1. Duktape (ES5.1) chosen over QuickJS/V8 for a single amalgamation and zero
   system deps; fine for operator hooks, not a Node substitute.
2. `handler` tags: `js:<name>`, `read_binding:<sym>` dispatched; more backends
   later. JSON `tools[]` and `js_body` `registerTool` share one registry.
3. LLMS1 stays pipe-separated (chat-pasteable); JSON packs are HookScripts.
4. phantom-kv citation is **delivery only** — do not drift into refusal-removal
   as a feature.
5. JS is trusted-operator code in-process — not a multi-tenant sandbox.
