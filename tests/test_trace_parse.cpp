#include "llamaspy/trace_parse.hpp"

#include <fstream>
#include <iostream>
#include <string>

static int g_fail = 0;

#define CHECK(cond)                                              \
  do {                                                           \
    if (!(cond)) {                                               \
      std::cerr << "FAIL " << __LINE__ << " " << #cond << "\n"; \
      ++g_fail;                                                  \
    }                                                            \
  } while (0)

static std::string ReadFile(const std::string& path) {
  std::ifstream in(path);
  if (!in) return {};
  std::string s;
  std::string line;
  while (std::getline(in, line)) {
    s += line;
    s += '\n';
  }
  return s;
}

int main() {
  llamaspy::TraceSample s;
  CHECK(llamaspy::ParseTraceSummaryLine("123 4 50\n", &s));
  CHECK(s.timestamp_ns == 123 && s.decode_count == 4 && s.avg_latency_ns == 50);
  CHECK(llamaspy::ParseTraceSummaryLine("  9 8 7", &s));
  CHECK(s.timestamp_ns == 9 && s.decode_count == 8 && s.avg_latency_ns == 7);
  CHECK(!llamaspy::ParseTraceSummaryLine("# comment", &s));
  CHECK(!llamaspy::ParseTraceSummaryLine("", &s));
  CHECK(!llamaspy::ParseTraceSummaryLine("only-one", &s));
  CHECK(!llamaspy::ParseTraceSummaryLine("1 2", &s));
  CHECK(!llamaspy::ParseTraceSummaryLine("1 2 3 extra", &s));

  std::string root = LLAMASPY_SOURCE_DIR;
  std::string bt = ReadFile(root + "/scripts/llama_decode.bt");
  std::string d = ReadFile(root + "/scripts/llama_decode.d");
  CHECK(!bt.empty());
  CHECK(!d.empty());
  CHECK(bt.find("uprobe:@TARGET@:llama_decode") != std::string::npos);
  CHECK(bt.find("uretprobe:@TARGET@:llama_decode") != std::string::npos);
  CHECK(bt.find("%llu %llu %llu") != std::string::npos);
  CHECK(d.find("llama_decode") != std::string::npos);
  CHECK(d.find("timestamp_ns decode_count avg_latency_ns") != std::string::npos ||
        d.find("%d %d %d") != std::string::npos);

  if (g_fail) {
    std::cerr << g_fail << " failure(s)\n";
    return 1;
  }
  std::cout << "trace_parse ok\n";
  return 0;
}
