#pragma once
// Portable HTTP GET /metrics (+ optional /slots) poller for llama-server.

#include "llamaspy/snoop_v1.hpp"

#include <optional>
#include <string>

namespace llamaspy {

struct ParsedLlamaMetrics {
  double predicted_tok_s = 0.0;
  double prompt_tok_s = 0.0;
  double requests_processing = 0.0;
  double requests_deferred = 0.0;
  double tokens_predicted_total = 0.0;
  double prompt_tokens_total = 0.0;
  double n_decode_total = 0.0;
  bool any = false;
  bool saw_requests_processing = false;
  bool saw_requests_deferred = false;
};

struct ParsedSlotsSummary {
  uint32_t busy = 0;   // is_processing == true
  uint32_t idle = 0;   // is_processing == false
  bool any = false;
};

// Minimal HTTP/1.0 GET. url must be http://host[:port]/path]
// Optional bearer_token adds Authorization: Bearer …
// Returns response body on success, nullopt on network/parse URL failure.
std::optional<std::string> HttpGet(const std::string& url, int timeout_sec = 2,
                                   const std::string& bearer_token = {});

// Same host/port as metrics_url, path forced to /slots.
std::string DeriveSlotsUrl(const std::string& metrics_url);

// Parse Prometheus text exposition for known llamacpp:* gauges/counters.
ParsedLlamaMetrics ParsePrometheusLlamaMetrics(const std::string& body);

// Count busy/idle from llama-server GET /slots JSON array (is_processing).
ParsedSlotsSummary ParseSlotsJson(const std::string& body);

// When Prometheus lacks request gauges, fill from /slots (idle → deferred-ish).
void MergeSlotsIntoMetrics(ParsedLlamaMetrics& m, const ParsedSlotsSummary& slots);

// Fill a host-order SnoopV1Frame from parsed metrics (+ pid/time).
SnoopV1Frame FrameFromParsed(uint32_t pid, const ParsedLlamaMetrics& m);

} // namespace llamaspy
