#pragma once
// Log / stderr timing stub for llama.SPY.
// Parses common llama.cpp timing lines from a file (--log-file).
// No FD hijack yet — cooperative tail of an existing log only.

#include "llamaspy/snoop_v1.hpp"

#include <optional>
#include <string>

namespace llamaspy {

struct ParsedLogTimings {
  double predicted_tok_s = 0.0; // "eval time" / generation
  double prompt_tok_s = 0.0;    // "prompt eval time"
  bool any = false;
};

// Scan text for llama.cpp timing lines; keep the last match of each kind.
ParsedLogTimings ParseLlamaTimingText(const std::string& text);

// Read path and parse. Returns nullopt if the file cannot be opened.
std::optional<ParsedLogTimings> ParseLlamaTimingFile(const std::string& path);

SnoopV1Frame FrameFromLogTimings(uint32_t pid, const ParsedLogTimings& m);

} // namespace llamaspy
