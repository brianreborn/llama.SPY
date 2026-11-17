#include "llamaspy/trace_parse.hpp"

#include <cctype>
#include <cstdlib>
#include <cstring>

#if !defined(_WIN32)
#  include <unistd.h>
#endif

namespace llamaspy {
namespace {

bool AllDigits(const char* s) {
  if (!s || !*s) return false;
  for (const char* p = s; *p; ++p) {
    if (*p < '0' || *p > '9') return false;
  }
  return true;
}

}  // namespace

bool ParseTraceSummaryLine(const char* line, TraceSample* out) {
  if (!line || !out) return false;
  while (*line == ' ' || *line == '\t') ++line;
  if (*line == '\0' || *line == '#' || *line == '\n' || *line == '\r') return false;
  char* end = nullptr;
  unsigned long long ts = std::strtoull(line, &end, 10);
  if (end == line || *end == '\0') return false;
  while (*end == ' ' || *end == '\t') ++end;
  char* end2 = nullptr;
  unsigned long long n = std::strtoull(end, &end2, 10);
  if (end2 == end) return false;
  while (*end2 == ' ' || *end2 == '\t') ++end2;
  char* end3 = nullptr;
  unsigned long long avg = std::strtoull(end2, &end3, 10);
  if (end3 == end2) return false;
  while (*end3 == ' ' || *end3 == '\t' || *end3 == '\r' || *end3 == '\n') ++end3;
  if (*end3 != '\0') return false;
  // Reject empty numeric tokens that strtoull would still accept (none here).
  (void)AllDigits;
  out->timestamp_ns = static_cast<uint64_t>(ts);
  out->decode_count = static_cast<uint64_t>(n);
  out->avg_latency_ns = static_cast<uint64_t>(avg);
  return true;
}

bool BpftraceOnPath() {
#if defined(_WIN32)
  return false;
#else
  const char* path = std::getenv("PATH");
  if (!path || !*path) return false;
  std::string dir;
  const char* p = path;
  auto check = [](const std::string& d) {
    if (d.empty()) return false;
    std::string full = d + "/bpftrace";
    return ::access(full.c_str(), X_OK) == 0;
  };
  while (*p) {
    if (*p == ':') {
      if (check(dir)) return true;
      dir.clear();
    } else {
      dir.push_back(*p);
    }
    ++p;
  }
  return check(dir);
#endif
}

}  // namespace llamaspy
