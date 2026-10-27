#include "llamaspy/hook_script.hpp"

#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>

namespace llamaspy {
namespace {

std::string_view TrimView(std::string_view s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
  return s;
}

std::string Trim(std::string_view s) { return std::string(TrimView(s)); }

// Minimal JSON string/object helpers for the HookScript subset (no full parser).
bool SkipWs(std::string_view& s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
  return !s.empty();
}

bool Consume(std::string_view& s, char c) {
  if (!SkipWs(s) || s.front() != c) return false;
  s.remove_prefix(1);
  return true;
}

bool ParseJsonString(std::string_view& s, std::string* out) {
  if (!SkipWs(s) || s.front() != '"') return false;
  s.remove_prefix(1);
  std::string r;
  while (!s.empty()) {
    char c = s.front();
    s.remove_prefix(1);
    if (c == '"') {
      *out = r;
      return true;
    }
    if (c == '\\' && !s.empty()) {
      char e = s.front();
      s.remove_prefix(1);
      if (e == '"' || e == '\\' || e == '/') r.push_back(e);
      else if (e == 'n') r.push_back('\n');
      else if (e == 't') r.push_back('\t');
      else if (e == 'r') r.push_back('\r');
      else r.push_back(e);
    } else {
      r.push_back(c);
    }
  }
  return false;
}

// Extract "key": <string|number|bool|object-as-text|array-of-strings> at top level
// or inside a shallow object. Very small subset — good enough for HookScript v1.
bool FindKeyValue(std::string_view obj, std::string_view key, std::string* value_out,
                  bool* is_string_out) {
  // Search for "key"
  std::string needle = "\"";
  needle += key;
  needle += "\"";
  std::size_t pos = 0;
  while (pos < obj.size()) {
    auto found = obj.find(needle, pos);
    if (found == std::string_view::npos) return false;
    // Ensure it's a key (followed by optional ws and ':')
    std::string_view rest = obj.substr(found + needle.size());
    if (!SkipWs(rest) || rest.front() != ':') {
      pos = found + 1;
      continue;
    }
    rest.remove_prefix(1);
    if (!SkipWs(rest)) return false;
    if (rest.front() == '"') {
      std::string v;
      if (!ParseJsonString(rest, &v)) return false;
      *value_out = v;
      if (is_string_out) *is_string_out = true;
      return true;
    }
    if (rest.front() == '{' || rest.front() == '[') {
      // Capture balanced brace/bracket as raw text
      char open = rest.front();
      char close = (open == '{') ? '}' : ']';
      int depth = 0;
      std::size_t i = 0;
      bool in_str = false;
      bool esc = false;
      for (; i < rest.size(); ++i) {
        char c = rest[i];
        if (in_str) {
          if (esc) esc = false;
          else if (c == '\\') esc = true;
          else if (c == '"') in_str = false;
          continue;
        }
        if (c == '"') {
          in_str = true;
          continue;
        }
        if (c == open) ++depth;
        else if (c == close) {
          --depth;
          if (depth == 0) {
            *value_out = std::string(rest.substr(0, i + 1));
            if (is_string_out) *is_string_out = false;
            return true;
          }
        }
      }
      return false;
    }
    // number / bool / null — read until comma or }
    std::size_t i = 0;
    while (i < rest.size() && rest[i] != ',' && rest[i] != '}' && rest[i] != ']') ++i;
    *value_out = Trim(rest.substr(0, i));
    if (is_string_out) *is_string_out = false;
    return true;
  }
  return false;
}

std::vector<std::string> SplitTopArrayObjects(std::string_view arr) {
  std::vector<std::string> out;
  arr = TrimView(arr);
  if (arr.empty() || arr.front() != '[') return out;
  // Find matching ] from the front, respecting strings (tolerate trailing junk).
  int depth = 0;
  bool in_str = false;
  bool esc = false;
  std::size_t end = std::string_view::npos;
  for (std::size_t i = 0; i < arr.size(); ++i) {
    char c = arr[i];
    if (in_str) {
      if (esc) esc = false;
      else if (c == '\\') esc = true;
      else if (c == '"') in_str = false;
      continue;
    }
    if (c == '"') { in_str = true; continue; }
    if (c == '[') {
      if (++depth == 1) continue;  // outer open
    } else if (c == ']') {
      if (--depth == 0) { end = i; break; }
    }
  }
  if (end == std::string_view::npos || end < 1) return out;
  arr = arr.substr(1, end - 1);  // inner
  depth = 0;
  in_str = false;
  esc = false;
  std::size_t start = 0;
  for (std::size_t i = 0; i < arr.size(); ++i) {
    char c = arr[i];
    if (in_str) {
      if (esc) esc = false;
      else if (c == '\\') esc = true;
      else if (c == '"') in_str = false;
      continue;
    }
    if (c == '"') { in_str = true; continue; }
    if (c == '{' || c == '[') ++depth;
    else if (c == '}' || c == ']') {
      if (depth > 0) --depth;
    } else if (c == ',' && depth == 0) {
      auto piece = TrimView(arr.substr(start, i - start));
      if (!piece.empty()) out.push_back(std::string(piece));
      start = i + 1;
    }
  }
  auto last = TrimView(arr.substr(start));
  if (!last.empty()) out.push_back(std::string(last));
  return out;
}

std::vector<std::string> SplitTopArrayStrings(std::string_view arr) {
  std::vector<std::string> out;
  for (const auto& piece0 : SplitTopArrayObjects(arr)) {
    std::string_view piece = TrimView(piece0);
    if (!piece.empty() && piece.front() == '"') {
      std::string_view p = piece;
      std::string v;
      if (ParseJsonString(p, &v)) out.push_back(v);
    }
  }
  return out;
}

HookScript ParseJsonManifest(std::string_view text, std::string_view source) {
  HookScript h;
  h.was_json = true;
  std::string v;
  bool is_str = false;

  if (!FindKeyValue(text, "llamaspy_hook", &v, &is_str)) {
    h.errors.push_back(std::string(source) + ": missing llamaspy_hook");
    return h;
  }
  try {
    h.version = std::stoi(v);
  } catch (...) {
    h.errors.push_back("llamaspy_hook not an int");
    return h;
  }
  if (h.version != 1) {
    h.errors.push_back("unsupported llamaspy_hook version (want 1)");
    // continue best-effort
  }

  if (FindKeyValue(text, "name", &v, &is_str)) h.name = v;
  else {
    h.errors.push_back("missing name");
    h.name = "unnamed";
  }
  if (FindKeyValue(text, "note", &v, &is_str)) h.note = v;
  if (FindKeyValue(text, "readonly", &v, &is_str)) {
    h.readonly = !(v == "false" || v == "0");
  }
  if (FindKeyValue(text, "js_body", &v, &is_str)) h.js_body = v;
  else if (FindKeyValue(text, "script", &v, &is_str)) h.js_body = v;

  if (FindKeyValue(text, "tools", &v, &is_str)) {
    for (const auto& obj : SplitTopArrayObjects(v)) {
      ToolDesc t;
      t.hook_name = h.name;
      std::string tv;
      bool ts = false;
      if (FindKeyValue(obj, "name", &tv, &ts)) t.name = tv;
      if (FindKeyValue(obj, "description", &tv, &ts)) t.description = tv;
      if (FindKeyValue(obj, "handler", &tv, &ts)) t.handler = tv;
      if (FindKeyValue(obj, "json_schema", &tv, &ts)) {
        t.json_schema = tv;  // string or raw object text
      }
      if (t.name.empty()) {
        h.errors.push_back("tools[] entry missing name");
        continue;
      }
      if (t.json_schema.empty()) t.json_schema = "{}";
      h.tools.push_back(std::move(t));
    }
  }

  if (FindKeyValue(text, "bindings", &v, &is_str)) {
    auto lines = SplitTopArrayStrings(v);
    std::ostringstream joined;
    joined << "LLMS1\n";
    for (const auto& line : lines) joined << line << "\n";
    h.codebook = ParseGameGenie(joined.str(), std::string(source) + ":bindings");
    for (const auto& e : h.codebook.errors) {
      h.errors.push_back("binding: " + e.message);
    }
  } else {
    h.codebook.ok = true;
  }

  h.ok = h.errors.empty() || (!h.tools.empty() || !h.codebook.bindings.empty());
  if (!h.tools.empty() || !h.codebook.bindings.empty()) h.ok = true;
  return h;
}

}  // namespace

HookScript LoadHookScriptText(std::string_view text, std::string_view source_name) {
  auto trimmed = Trim(text);
  if (!trimmed.empty() && trimmed.front() == '{') {
    return ParseJsonManifest(trimmed, source_name);
  }
  // LLMS1 simple dialect
  HookScript h;
  h.was_json = false;
  h.name = std::string(source_name);
  h.version = 1;
  h.codebook = ParseGameGenie(text, source_name);
  h.ok = h.codebook.ok || !h.codebook.bindings.empty();
  for (const auto& e : h.codebook.errors) {
    h.errors.push_back(e.message);
  }
  return h;
}

HookScript LoadHookScriptFile(const std::string& path) {
  if (path == "-") {
    std::ostringstream ss;
    ss << std::cin.rdbuf();
    return LoadHookScriptText(ss.str(), "<stdin>");
  }
  std::ifstream in(path);
  if (!in) {
    HookScript h;
    h.errors.push_back("cannot open " + path);
    return h;
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return LoadHookScriptText(ss.str(), path);
}

std::size_t ApplyHookTools(const HookScript& hook) {
  std::size_t n = 0;
  auto& reg = ToolRegistry::Instance();
  for (const auto& t : hook.tools) {
    ToolDesc copy = t;
    if (copy.hook_name.empty()) copy.hook_name = hook.name;
    if (reg.Register(std::move(copy))) ++n;
  }
  return n;
}

std::string FormatHookScript(const HookScript& hook) {
  std::ostringstream o;
  o << "HookScript name=" << hook.name
    << " version=" << hook.version
    << " format=" << (hook.was_json ? "json" : "llms1")
    << " readonly=" << (hook.readonly ? "true" : "false")
    << " tools=" << hook.tools.size()
    << " bindings=" << hook.codebook.bindings.size()
    << " ok=" << (hook.ok ? "true" : "false") << "\n";
  if (!hook.note.empty()) o << "  note: " << hook.note << "\n";
  if (!hook.js_body.empty()) {
    o << "  js_body: " << hook.js_body.size()
      << " bytes (Duktape)\n";
  }
  for (const auto& e : hook.errors) o << "  ERR: " << e << "\n";
  for (const auto& t : hook.tools) {
    o << "  tool: " << t.name;
    if (!t.handler.empty()) o << " handler=" << t.handler;
    o << "\n";
    if (!t.description.empty()) o << "    " << t.description << "\n";
  }
  if (!hook.codebook.bindings.empty()) {
    o << FormatCodebook(hook.codebook);
  }
  return o.str();
}

}  // namespace llamaspy
