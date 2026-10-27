#pragma once
// HookScript loader — primary Game Genie path.
// JSON manifest registers tools; optional LLMS1 bindings; js_body executed via Duktape when LLAMASPY_JS=ON.
// See docs/GAME_GENIE.md. No JS engine in this scaffold.

#include "llamaspy/game_genie.hpp"
#include "llamaspy/tool_registry.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace llamaspy {

struct HookScript {
  int version = 0;
  std::string name;
  std::string note;
  bool readonly = true;
  std::string js_body;  // executed by JsEngine when non-empty
  std::vector<ToolDesc> tools;
  GgCodebook codebook;  // from bindings[] or LLMS1-only file
  std::vector<std::string> errors;
  bool ok = false;
  bool was_json = false;
};

// Load from text: leading '{' → JSON HookScript; else LLMS1 dialect.
HookScript LoadHookScriptText(std::string_view text, std::string_view source_name = "<input>");
HookScript LoadHookScriptFile(const std::string& path);

// Register all tools into ToolRegistry::Instance(); returns how many succeeded.
std::size_t ApplyHookTools(const HookScript& hook);

// Pretty dump for CLI.
std::string FormatHookScript(const HookScript& hook);

}  // namespace llamaspy
