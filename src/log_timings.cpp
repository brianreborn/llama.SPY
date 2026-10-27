#include "llamaspy/log_timings.hpp"
#include "llamaspy/telemetry_provider.hpp"

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

namespace llamaspy {
namespace {

uint64_t NowNs() {
  using clock = std::chrono::steady_clock;
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(clock::now().time_since_epoch())
          .count());
}

// Extract "N.N tokens per second" from a line; returns true on match.
bool ExtractTokPerSec(const std::string& line, double& out) {
  const std::string needle = "tokens per second";
  auto pos = line.find(needle);
  if (pos == std::string::npos) return false;
  // Walk backward past spaces/parens to the number.
  size_t end = pos;
  while (end > 0 && (line[end - 1] == ' ' || line[end - 1] == '\t' || line[end - 1] == '(')) {
    --end;
  }
  if (end == 0) return false;
  size_t start = end;
  while (start > 0) {
    char c = line[start - 1];
    if ((c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+') {
      --start;
      continue;
    }
    break;
  }
  if (start >= end) return false;
  char* e = nullptr;
  double v = std::strtod(line.c_str() + start, &e);
  if (e == line.c_str() + start) return false;
  out = v;
  return true;
}

bool LineLooksLikePromptEval(const std::string& line) {
  return line.find("prompt eval") != std::string::npos ||
         line.find("prompt_eval") != std::string::npos;
}

bool LineLooksLikeGenEval(const std::string& line) {
  // "eval time" but not "prompt eval"
  if (LineLooksLikePromptEval(line)) return false;
  return line.find("eval time") != std::string::npos ||
         line.find("eval_time") != std::string::npos ||
         (line.find("tokens per second") != std::string::npos &&
          line.find("runs") != std::string::npos);
}

class LogTimingsProvider final : public TelemetryProvider {
 public:
  const char* name() const override { return "log-timings"; }

  AttachStatus Attach(const AttachOptions& opts) override {
    if (opts.log_file.empty()) return AttachStatus::Failed;
    opts_ = opts;
    // Probe open once so Attach fails early on missing path.
    std::ifstream in(opts_.log_file);
    if (!in) {
      std::cerr << "[log-timings] cannot open --log-file: " << opts_.log_file << "\n";
      return AttachStatus::Failed;
    }
    attached_ = true;
    return AttachStatus::Ok;
  }

  bool StreamMetrics(MetricsCallback cb) override {
    if (!attached_) return false;
    auto parsed = ParseLlamaTimingFile(opts_.log_file);
    if (!parsed) {
      std::cerr << "[log-timings] read failed: " << opts_.log_file << "\n";
      std::this_thread::sleep_for(std::chrono::seconds(1));
      return true;
    }
    if (!parsed->any) {
      std::cerr << "[log-timings] no timing lines yet in " << opts_.log_file << "\n";
    }
    cb(FrameFromLogTimings(opts_.pid, *parsed));
    std::this_thread::sleep_for(std::chrono::seconds(1));
    return true;
  }

  void Detach() override { attached_ = false; }

 private:
  AttachOptions opts_{};
  bool attached_ = false;
};

} // namespace

ParsedLogTimings ParseLlamaTimingText(const std::string& text) {
  ParsedLogTimings m;
  std::istringstream in(text);
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    double v = 0;
    if (!ExtractTokPerSec(line, v)) continue;
    if (LineLooksLikePromptEval(line)) {
      m.prompt_tok_s = v;
      m.any = true;
    } else if (LineLooksLikeGenEval(line)) {
      m.predicted_tok_s = v;
      m.any = true;
    } else {
      // Ambiguous "tokens per second" line — treat as generation if unset.
      if (m.predicted_tok_s == 0.0) {
        m.predicted_tok_s = v;
        m.any = true;
      }
    }
  }
  return m;
}

std::optional<ParsedLogTimings> ParseLlamaTimingFile(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return std::nullopt;
  std::ostringstream ss;
  ss << in.rdbuf();
  return ParseLlamaTimingText(ss.str());
}

SnoopV1Frame FrameFromLogTimings(uint32_t pid, const ParsedLogTimings& m) {
  SnoopV1Frame f{};
  f.magic = kSnoopMagic;
  f.version = kSnoopVersion;
  f.flags = 0;
  f.timestamp_ns = NowNs();
  f.pid = pid;
  f.decode_count = 0;
  f.predicted_tok_s = m.predicted_tok_s;
  f.prompt_tok_s = m.prompt_tok_s;
  f.requests_processing = 0;
  f.requests_deferred = 0;
  f.decode_latency_ns_sum = 0;
  f.decode_latency_n = 0;
  f.reserved = 0;
  return f;
}

std::unique_ptr<TelemetryProvider> MakeLogTimingsProvider() {
  return std::make_unique<LogTimingsProvider>();
}

} // namespace llamaspy
