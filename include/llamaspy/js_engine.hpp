#pragma once
// Minimal Duktape-backed JS engine for HookScript js_body.
// Host API (no net, no fs): registerTool, log, readBinding (stub).
// See docs/GAME_GENIE.md and third_party/duktape/README.md.

#include "llamaspy/game_genie.hpp"
#include "llamaspy/hook_script.hpp"

#include <string>
#include <string_view>

namespace llamaspy {

// Process-local JS runtime (one duk heap). Thread-unsafe; CLI is single-threaded.
class JsEngine {
 public:
  static JsEngine& Instance();

  // Create heap + inject host API. Idempotent. Returns false if JS disabled at build.
  bool EnsureInit(std::string* err = nullptr);
  bool available() const;
  void Shutdown();

  // Bind codebook for readBinding(sym) lookups (metadata only; no mem read).
  void SetBindings(const GgCodebook* book);

  // Eval hook.js_body; registerTool() calls may mint tools into ToolRegistry.
  // Returns false on compile/runtime error (message in *err).
  bool EvalHook(const HookScript& hook, std::string* err);

  // Invoke a JS-registered tool handler. json_args is a JSON object string (default "{}").
  // On success writes JSON result into *result_json.
  bool CallJsTool(std::string_view tool_name, std::string_view json_args,
                  std::string* result_json, std::string* err);

 private:
  JsEngine() = default;
  void* ctx_ = nullptr;  // duk_context* (opaque to keep header C++-only)
  const GgCodebook* bindings_ = nullptr;
  bool init_attempted_ = false;
  bool init_ok_ = false;
};

// Dispatch ToolRegistry handler tags:
//   js:<name>            → JsEngine::CallJsTool
//   read_binding:<sym>   → stub JSON (no mem backend yet)
//   other                → error JSON
// Returns process exit-style: true if tool found and handler ran (even if stub).
bool CallTool(std::string_view name, std::string_view json_args,
              std::string* result_json, std::string* err);

}  // namespace llamaspy
