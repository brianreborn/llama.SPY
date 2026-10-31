#pragma once
// TelemetryProvider — abstract ingestion backend for llama.SPY.
// FreeBSD DTrace (pid provider on llama_decode) is the primary v1 backend.
// HTTP /metrics (+ optional /slots) is the portable fallback.
// Log timings (--log-file) is a cooperative stub (no FD hijack yet).

#include "llamaspy/snoop_v1.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace llamaspy {

enum class AttachStatus {
  Ok = 0,
  NotSupported,
  Failed,
  NeedPrivileges,
};

struct AttachOptions {
  uint32_t pid = 0;
  std::string metrics_url;       // e.g. http://127.0.0.1:8080/metrics
  std::string slots_url;         // optional override; default = same host/port /slots
  std::string api_key;           // optional Bearer for /metrics and /slots
  std::string log_file;          // cooperative timing log path (--log-file)
  std::string dtrace_script_path; // path to scripts/llama_decode.d
};

using MetricsCallback = std::function<void(const SnoopV1Frame&)>;

class TelemetryProvider {
 public:
  virtual ~TelemetryProvider() = default;

  virtual const char* name() const = 0;
  virtual AttachStatus Attach(const AttachOptions& opts) = 0;
  // Poll or block briefly; invoke cb with the latest aggregated frame.
  // Returns false when the stream should stop (detach / fatal).
  virtual bool StreamMetrics(MetricsCallback cb) = 0;
  virtual void Detach() = 0;
};

std::unique_ptr<TelemetryProvider> MakeHttpMetricsProvider();
std::unique_ptr<TelemetryProvider> MakeDtraceFreeBsdProvider();
std::unique_ptr<TelemetryProvider> MakeBpftraceLinuxProvider();  // Linux uprobes
std::unique_ptr<TelemetryProvider> MakeLogTimingsProvider();

} // namespace llamaspy
