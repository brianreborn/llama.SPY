// LLMS1 pipe-code parser — simple dialect of Game Genie.
// Primary story is HookScripts (JSON/JS) that mint tool calls;
// see docs/GAME_GENIE.md and src/hook_script.cpp. This file stays
// the binding/offset subset used by HookScript bindings[] and --gg-file.

#include "llamaspy/game_genie.hpp"

#include <cctype>
#include <fstream>
#include <sstream>

namespace llamaspy {
namespace {

std::string Trim(std::string_view s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
    s.remove_prefix(1);
  }
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
    s.remove_suffix(1);
  }
  return std::string(s);
}

std::vector<std::string> SplitPipe(std::string_view line) {
  std::vector<std::string> parts;
  std::size_t start = 0;
  while (start <= line.size()) {
    auto bar = line.find('|', start);
    if (bar == std::string_view::npos) {
      parts.push_back(Trim(line.substr(start)));
      break;
    }
    parts.push_back(Trim(line.substr(start, bar - start)));
    start = bar + 1;
  }
  return parts;
}

bool ParseU64(std::string_view s, uint64_t* out) {
  if (s.empty() || !out) return false;
  try {
    std::size_t idx = 0;
    unsigned long long v = std::stoull(std::string(s), &idx, 0);
    if (idx != s.size()) return false;
    *out = static_cast<uint64_t>(v);
    return true;
  } catch (...) {
    return false;
  }
}

bool ParseU32(std::string_view s, uint32_t* out) {
  uint64_t v = 0;
  if (!ParseU64(s, &v) || v > 0xffffffffull) return false;
  *out = static_cast<uint32_t>(v);
  return true;
}

} // namespace

const char* GgValueTypeName(GgValueType t) {
  switch (t) {
  case GgValueType::U8: return "u8";
  case GgValueType::U16: return "u16";
  case GgValueType::U32: return "u32";
  case GgValueType::U64: return "u64";
  case GgValueType::I32: return "i32";
  case GgValueType::I64: return "i64";
  case GgValueType::F32: return "f32";
  case GgValueType::F64: return "f64";
  default: return "unknown";
  }
}

GgValueType GgValueTypeFromString(std::string_view s) {
  std::string lower;
  lower.reserve(s.size());
  for (char c : s) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  if (lower == "u8") return GgValueType::U8;
  if (lower == "u16") return GgValueType::U16;
  if (lower == "u32") return GgValueType::U32;
  if (lower == "u64") return GgValueType::U64;
  if (lower == "i32") return GgValueType::I32;
  if (lower == "i64") return GgValueType::I64;
  if (lower == "f32" || lower == "float") return GgValueType::F32;
  if (lower == "f64" || lower == "double") return GgValueType::F64;
  return GgValueType::Unknown;
}

uint32_t DefaultWidth(GgValueType t) {
  switch (t) {
  case GgValueType::U8: return 1;
  case GgValueType::U16: return 2;
  case GgValueType::U32:
  case GgValueType::I32:
  case GgValueType::F32: return 4;
  case GgValueType::U64:
  case GgValueType::I64:
  case GgValueType::F64: return 8;
  default: return 0;
  }
}

GgCodebook ParseGameGenie(std::string_view text, std::string_view source_name) {
  GgCodebook book;
  book.ok = true;
  int line_no = 0;
  std::size_t pos = 0;

  auto fail_line = [&](int ln, const std::string& msg) {
    book.errors.push_back(GgParseError{ln, msg});
    book.ok = false;
  };

  while (pos <= text.size()) {
    std::size_t eol = text.find('\n', pos);
    std::string_view raw =
        (eol == std::string_view::npos) ? text.substr(pos) : text.substr(pos, eol - pos);
    if (!raw.empty() && raw.back() == '\r') raw.remove_suffix(1);
    pos = (eol == std::string_view::npos) ? text.size() + 1 : eol + 1;
    ++line_no;

    std::string line = Trim(raw);
    if (line.empty() || line[0] == '#') continue;

    auto parts = SplitPipe(line);
    if (parts.empty()) continue;

    if (parts[0] != kGgMagicVersion && parts[0] != "LLMS1") {
      // Allow a bare header line "LLMS1" alone (version stamp).
      if (parts.size() == 1 && (parts[0] == "LLMS1" || parts[0] == kGgMagicVersion)) {
        book.format_version = kGgFormatVersion;
        continue;
      }
      fail_line(line_no,
                std::string(source_name) + ":" + std::to_string(line_no) +
                    ": expected magic LLMS1, got '" + parts[0] + "'");
      continue;
    }

    if (parts.size() == 1) {
      book.format_version = kGgFormatVersion;
      continue;
    }

    GgBinding b;
    b.raw_line = line;
    b.line_no = line_no;
    bool saw_sym = false;
    bool saw_off = false;
    bool line_bad = false;

    for (std::size_t i = 1; i < parts.size(); ++i) {
      if (parts[i].empty()) continue;
      auto eq = parts[i].find('=');
      if (eq == std::string::npos) {
        // Unknown bare token — ignore (forward-compat).
        continue;
      }
      std::string key = Trim(std::string_view(parts[i]).substr(0, eq));
      std::string val = Trim(std::string_view(parts[i]).substr(eq + 1));
      for (char& c : key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

      if (key == "sym" || key == "symbol" || key == "name") {
        b.symbol = val;
        saw_sym = !val.empty();
      } else if (key == "off" || key == "offset" || key == "addr") {
        uint64_t off = 0;
        if (!ParseU64(val, &off)) {
          fail_line(line_no, "invalid off='" + val + "'");
          line_bad = true;
          continue;
        }
        b.offset = off;
        b.has_offset = true;
        saw_off = true;
      } else if (key == "width" || key == "sz" || key == "size") {
        uint32_t w = 0;
        if (!ParseU32(val, &w) || w == 0 || w > 64) {
          fail_line(line_no, "invalid width='" + val + "'");
          line_bad = true;
          continue;
        }
        b.width = w;
      } else if (key == "type" || key == "ty") {
        b.type = GgValueTypeFromString(val);
        if (b.type == GgValueType::Unknown) {
          fail_line(line_no, "unknown type='" + val + "'");
          line_bad = true;
        }
      } else if (key == "note" || key == "comment") {
        b.note = val;
      } else if (key == "fp" || key == "build" || key == "fingerprint" || key == "build_fp") {
        b.build_fp = val;
        book.file_fingerprint = val;
      } else {
        // Unknown keys ignored intentionally.
      }
    }

    if (line_bad) continue;
    if (!saw_sym) {
      fail_line(line_no, "missing required sym=...");
      continue;
    }
    if (!saw_off) {
      fail_line(line_no, "missing required off=... (read-only bindings need an offset)");
      continue;
    }
    if (b.type == GgValueType::Unknown) {
      // type optional only if width set; otherwise require type
      if (b.width == 0) {
        fail_line(line_no, "need type=... or width=... for '" + b.symbol + "'");
        continue;
      }
    } else if (b.width == 0) {
      b.width = DefaultWidth(b.type);
    }

    book.bindings.push_back(std::move(b));
  }

  if (book.bindings.empty() && book.ok) {
    // Empty file with only comments is ok but flagged empty for ApplyReadOnly.
  }
  // ok stays true if we had zero hard errors; soft: still list bindings that parsed.
  // If any fail_line ran, ok=false but we keep successfully parsed bindings.
  return book;
}

GgCodebook LoadGameGenieFile(const std::string& path) {
  std::ifstream in(path);
  if (!in) {
    GgCodebook book;
    book.ok = false;
    book.errors.push_back(GgParseError{0, "cannot open '" + path + "'"});
    return book;
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ParseGameGenie(ss.str(), path);
}

std::string FormatCodebook(const GgCodebook& book) {
  std::ostringstream o;
  o << "llama.SPY Game Genie v" << book.format_version
    << " — " << book.bindings.size() << " binding(s)";
  if (!book.file_fingerprint.empty()) {
    o << " fp=" << book.file_fingerprint;
  }
  o << "\n";
  if (!book.ok) {
    o << "parse_ok=false (" << book.errors.size() << " error(s))\n";
  } else {
    o << "parse_ok=true\n";
  }
  for (const auto& e : book.errors) {
    o << "  ERR";
    if (e.line_no > 0) o << " line " << e.line_no;
    o << ": " << e.message << "\n";
  }
  for (const auto& b : book.bindings) {
    o << "  [" << b.line_no << "] sym=" << b.symbol
      << " off=0x" << std::hex << b.offset << std::dec
      << " width=" << b.width
      << " type=" << GgValueTypeName(b.type);
    if (!b.build_fp.empty()) o << " fp=" << b.build_fp;
    if (!b.note.empty()) o << " note=" << b.note;
    o << "\n";
  }
  return o.str();
}

GgApplyStatus ApplyReadOnly(uint32_t pid, const GgCodebook& book, std::string* detail_out) {
  if (book.bindings.empty()) {
    if (detail_out) *detail_out = "no bindings to apply";
    return GgApplyStatus::Empty;
  }
  if (pid == 0) {
    if (detail_out) *detail_out = "pid required for future mem read (got 0)";
    return GgApplyStatus::InvalidArg;
  }
  std::ostringstream o;
  o << "ApplyReadOnly not implemented yet (Linux process_vm_readv / FreeBSD later). "
    << "Would read " << book.bindings.size() << " binding(s) from pid=" << pid << ":\n";
  for (const auto& b : book.bindings) {
    o << "  - " << b.symbol << " @ 0x" << std::hex << b.offset << std::dec
      << " (" << GgValueTypeName(b.type) << ", " << b.width << " bytes)\n";
  }
  if (detail_out) *detail_out = o.str();
  return GgApplyStatus::NotImplemented;
}

} // namespace llamaspy
