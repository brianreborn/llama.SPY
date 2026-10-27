#pragma once
// Game Genie v1 — paste-in read-only offset codes for llama.SPY.
// Format: docs/GAME_GENIE.md. No memory writes; ApplyReadOnly is a stub.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace llamaspy {

inline constexpr const char* kGgMagicVersion = "LLMS1";
inline constexpr int kGgFormatVersion = 1;

enum class GgValueType : uint8_t {
  U8,
  U16,
  U32,
  U64,
  I32,
  I64,
  F32,
  F64,
  Unknown,
};

struct GgBinding {
  std::string symbol;          // human name, e.g. n_past
  uint64_t offset = 0;         // byte offset (required when off= present)
  bool has_offset = false;
  uint32_t width = 0;          // bytes; 0 = derive from type
  GgValueType type = GgValueType::Unknown;
  std::string note;
  std::string build_fp;        // optional fingerprint (fp= / build=)
  std::string raw_line;        // original line for diagnostics
  int line_no = 0;
};

struct GgParseError {
  int line_no = 0;
  std::string message;
};

struct GgCodebook {
  int format_version = kGgFormatVersion;
  std::string file_fingerprint; // last fp=/build= seen at file scope, if any
  std::vector<GgBinding> bindings;
  std::vector<GgParseError> errors; // non-fatal collected; fatal stops load
  bool ok = false;
};

enum class GgApplyStatus : int {
  Ok = 0,
  NotImplemented = 1,
  InvalidArg = 2,
  Empty = 3,
};

// Parse a full document (file body or stdin dump). Lines starting with '#'
// and blank lines are ignored. Unknown key=value pairs are ignored.
GgCodebook ParseGameGenie(std::string_view text, std::string_view source_name = "<input>");

// Load from filesystem path.
GgCodebook LoadGameGenieFile(const std::string& path);

// Pretty-print bindings (and errors) to a string.
std::string FormatCodebook(const GgCodebook& book);

const char* GgValueTypeName(GgValueType t);
GgValueType GgValueTypeFromString(std::string_view s);

// Stub: future Linux process_vm_readv / FreeBSD mem read. Lists bindings only.
GgApplyStatus ApplyReadOnly(uint32_t pid, const GgCodebook& book, std::string* detail_out);

} // namespace llamaspy
