#pragma once
// ToolRegistry — in-memory catalog of operator tool calls minted by HookScripts.
// Game Genie primary story: paste-in hooks that Register one or more tools.
// See docs/GAME_GENIE.md. No IPC / serve wiring yet.

#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace llamaspy {

struct ToolDesc {
  std::string name;
  std::string description;
  std::string json_schema;  // JSON Schema as text (may be "{}")
  std::string handler;      // opaque tag, e.g. read_binding:n_past / js:main
  std::string hook_name;    // HookScript that registered this tool (for unload)
};

// Process-local registry. Thread-safe for Register/Unregister/List.
class ToolRegistry {
 public:
  static ToolRegistry& Instance();

  // Returns false if name empty or already registered.
  bool Register(ToolDesc desc);
  // Returns number of tools removed (0 or 1 for by-name; N for by-hook).
  std::size_t Unregister(std::string_view name);
  std::size_t UnregisterByHook(std::string_view hook_name);
  void Clear();

  std::vector<ToolDesc> List() const;
  std::optional<ToolDesc> Find(std::string_view name) const;
  std::size_t size() const;

 private:
  ToolRegistry() = default;
  mutable std::mutex mu_;
  std::vector<ToolDesc> tools_;
};

// Pretty-print for --list-tools.
std::string FormatToolList(const std::vector<ToolDesc>& tools);

}  // namespace llamaspy
