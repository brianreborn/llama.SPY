#pragma once
// Shared parser for scripts/llama_decode.d and scripts/llama_decode.bt lines:
//   timestamp_ns decode_count avg_latency_ns

#include <cstdint>
#include <string>

namespace llamaspy {

struct TraceSample {
  uint64_t timestamp_ns = 0;
  uint64_t decode_count = 0;
  uint64_t avg_latency_ns = 0;
};

// False for blanks, '#' comments, and anything that is not three integers.
bool ParseTraceSummaryLine(const char* line, TraceSample* out);

// True when `bpftrace` is on PATH.
bool BpftraceOnPath();

}  // namespace llamaspy
