# Vendored Duktape 2.7.0

**Why Duktape:** single-file C amalgamation (`duktape.c` + `duktape.h` +
`duk_config.h`), MIT-licensed, no system packages, embeds cleanly in a C++20
binary. Smaller than QuickJS's multi-file tree for our MVP needs (ES5.1 + a
few extras is enough for HookScript `js_body`).

**Source:** https://duktape.org/duktape-2.7.0.tar.xz  
**License:** MIT (see upstream `LICENSE.txt` in the release tarball; summary:
do what you want, keep copyright notice).

**Security posture for llama.SPY:** the host API exposes only `registerTool`,
`log`, and `readBinding` (stub). No `require`, no network, no filesystem
builtins are injected. Operators still review HookScripts before load.

CMake compiles `duktape.c` into `llamaspy` when `LLAMASPY_JS=ON` (default).
