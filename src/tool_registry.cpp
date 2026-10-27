#include "llamaspy/tool_registry.hpp"

#include <sstream>

namespace llamaspy {

ToolRegistry& ToolRegistry::Instance() {
  static ToolRegistry g;
  return g;
}

bool ToolRegistry::Register(ToolDesc desc) {
  if (desc.name.empty()) return false;
  std::lock_guard<std::mutex> lock(mu_);
  for (const auto& t : tools_) {
    if (t.name == desc.name) return false;
  }
  tools_.push_back(std::move(desc));
  return true;
}

std::size_t ToolRegistry::Unregister(std::string_view name) {
  std::lock_guard<std::mutex> lock(mu_);
  std::size_t n = 0;
  for (auto it = tools_.begin(); it != tools_.end();) {
    if (it->name == name) {
      it = tools_.erase(it);
      ++n;
    } else {
      ++it;
    }
  }
  return n;
}

std::size_t ToolRegistry::UnregisterByHook(std::string_view hook_name) {
  std::lock_guard<std::mutex> lock(mu_);
  std::size_t n = 0;
  for (auto it = tools_.begin(); it != tools_.end();) {
    if (it->hook_name == hook_name) {
      it = tools_.erase(it);
      ++n;
    } else {
      ++it;
    }
  }
  return n;
}

void ToolRegistry::Clear() {
  std::lock_guard<std::mutex> lock(mu_);
  tools_.clear();
}

std::vector<ToolDesc> ToolRegistry::List() const {
  std::lock_guard<std::mutex> lock(mu_);
  return tools_;
}

std::optional<ToolDesc> ToolRegistry::Find(std::string_view name) const {
  std::lock_guard<std::mutex> lock(mu_);
  for (const auto& t : tools_) {
    if (t.name == name) return t;
  }
  return std::nullopt;
}

std::size_t ToolRegistry::size() const {
  std::lock_guard<std::mutex> lock(mu_);
  return tools_.size();
}

std::string FormatToolList(const std::vector<ToolDesc>& tools) {
  std::ostringstream o;
  o << "ToolRegistry (" << tools.size() << " tool(s))\n";
  if (tools.empty()) {
    o << "  (empty — load a HookScript with --hook-file)\n";
    return o.str();
  }
  for (const auto& t : tools) {
    o << "  - " << t.name;
    if (!t.hook_name.empty()) o << "  [hook=" << t.hook_name << "]";
    o << "\n";
    if (!t.description.empty()) o << "      desc: " << t.description << "\n";
    if (!t.handler.empty()) o << "      handler: " << t.handler << "\n";
    if (!t.json_schema.empty()) o << "      schema: " << t.json_schema << "\n";
  }
  return o.str();
}

}  // namespace llamaspy
