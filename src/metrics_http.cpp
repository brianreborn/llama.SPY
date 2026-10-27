#include "llamaspy/metrics_http.hpp"
#include "llamaspy/telemetry_provider.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>

namespace llamaspy {
namespace {

struct UrlParts {
  std::string host;
  int port = 80;
  std::string path = "/";
};

bool ParseHttpUrl(const std::string& url, UrlParts& out) {
  const std::string prefix = "http://";
  if (url.rfind(prefix, 0) != 0) return false;
  std::string rest = url.substr(prefix.size());
  auto slash = rest.find('/');
  std::string hostport = slash == std::string::npos ? rest : rest.substr(0, slash);
  out.path = slash == std::string::npos ? "/" : rest.substr(slash);
  auto colon = hostport.find(':');
  if (colon == std::string::npos) {
    out.host = hostport;
    out.port = 80;
  } else {
    out.host = hostport.substr(0, colon);
    out.port = std::atoi(hostport.substr(colon + 1).c_str());
    if (out.port <= 0) return false;
  }
  return !out.host.empty();
}

bool MatchMetricName(const std::string& line, const char* name, double& value) {
  // Prometheus text: name[{labels}] value [timestamp]
  if (line.empty() || line[0] == '#') return false;
  const size_t nlen = std::strlen(name);
  if (line.compare(0, nlen, name) != 0) return false;
  char next = line.size() > nlen ? line[nlen] : '\0';
  if (next != ' ' && next != '{' && next != '\t') return false;
  size_t i = nlen;
  if (next == '{') {
    i = line.find('}');
    if (i == std::string::npos) return false;
    ++i;
  }
  while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
  if (i >= line.size()) return false;
  char* end = nullptr;
  value = std::strtod(line.c_str() + i, &end);
  return end != line.c_str() + i;
}

uint64_t NowNs() {
  using clock = std::chrono::steady_clock;
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(clock::now().time_since_epoch())
          .count());
}

// Tiny JSON helpers for /slots — no full parser; count "is_processing": true/false.
void CountIsProcessing(const std::string& body, uint32_t& busy, uint32_t& idle, bool& any) {
  busy = 0;
  idle = 0;
  any = false;
  const std::string key = "\"is_processing\"";
  size_t pos = 0;
  while ((pos = body.find(key, pos)) != std::string::npos) {
    pos += key.size();
    while (pos < body.size() &&
           (body[pos] == ' ' || body[pos] == '\t' || body[pos] == '\n' || body[pos] == '\r' ||
            body[pos] == ':')) {
      ++pos;
    }
    if (body.compare(pos, 4, "true") == 0) {
      ++busy;
      any = true;
      pos += 4;
    } else if (body.compare(pos, 5, "false") == 0) {
      ++idle;
      any = true;
      pos += 5;
    }
  }
}

} // namespace

std::string DeriveSlotsUrl(const std::string& metrics_url) {
  UrlParts parts;
  if (!ParseHttpUrl(metrics_url, parts)) {
    // Best-effort: if already looks like http://host:port/..., swap path.
    auto scheme = metrics_url.find("://");
    if (scheme == std::string::npos) return {};
    auto path_start = metrics_url.find('/', scheme + 3);
    if (path_start == std::string::npos) return metrics_url + "/slots";
    return metrics_url.substr(0, path_start) + "/slots";
  }
  std::ostringstream out;
  out << "http://" << parts.host;
  if (parts.port != 80) out << ':' << parts.port;
  out << "/slots";
  return out.str();
}

std::optional<std::string> HttpGet(const std::string& url, int timeout_sec,
                                   const std::string& bearer_token) {
  UrlParts parts;
  if (!ParseHttpUrl(url, parts)) return std::nullopt;

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  const std::string port_str = std::to_string(parts.port);
  if (getaddrinfo(parts.host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
    return std::nullopt;
  }

  int fd = -1;
  for (addrinfo* p = res; p; p = p->ai_next) {
    fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    timeval tv{};
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) return std::nullopt;

  std::ostringstream req;
  req << "GET " << parts.path << " HTTP/1.0\r\n"
      << "Host: " << parts.host << "\r\n"
      << "User-Agent: llamaspy/0.1\r\n"
      << "Accept: */*\r\n";
  if (!bearer_token.empty()) {
    req << "Authorization: Bearer " << bearer_token << "\r\n";
  }
  req << "Connection: close\r\n\r\n";
  const std::string req_s = req.str();
  ssize_t sent = 0;
  while (sent < static_cast<ssize_t>(req_s.size())) {
    ssize_t n = ::send(fd, req_s.data() + sent, req_s.size() - sent, 0);
    if (n <= 0) {
      ::close(fd);
      return std::nullopt;
    }
    sent += n;
  }

  std::string raw;
  char buf[4096];
  for (;;) {
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
      ::close(fd);
      return std::nullopt;
    }
    if (n == 0) break;
    raw.append(buf, static_cast<size_t>(n));
  }
  ::close(fd);

  auto hdr_end = raw.find("\r\n\r\n");
  if (hdr_end == std::string::npos) return std::nullopt;
  // Require 200
  if (raw.find("HTTP/1.") != 0) return std::nullopt;
  auto sp = raw.find(' ');
  if (sp == std::string::npos || raw.compare(sp + 1, 3, "200") != 0) return std::nullopt;
  return raw.substr(hdr_end + 4);
}

ParsedLlamaMetrics ParsePrometheusLlamaMetrics(const std::string& body) {
  ParsedLlamaMetrics m;
  std::istringstream in(body);
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    double v = 0;
    if (MatchMetricName(line, "llamacpp:predicted_tokens_seconds", v)) {
      m.predicted_tok_s = v;
      m.any = true;
    } else if (MatchMetricName(line, "llamacpp:prompt_tokens_seconds", v)) {
      m.prompt_tok_s = v;
      m.any = true;
    } else if (MatchMetricName(line, "llamacpp:requests_processing", v)) {
      m.requests_processing = v;
      m.saw_requests_processing = true;
      m.any = true;
    } else if (MatchMetricName(line, "llamacpp:requests_deferred", v)) {
      m.requests_deferred = v;
      m.saw_requests_deferred = true;
      m.any = true;
    } else if (MatchMetricName(line, "llamacpp:tokens_predicted_total", v)) {
      m.tokens_predicted_total = v;
      m.any = true;
    } else if (MatchMetricName(line, "llamacpp:prompt_tokens_total", v)) {
      m.prompt_tokens_total = v;
      m.any = true;
    } else if (MatchMetricName(line, "llamacpp:n_decode_total", v)) {
      m.n_decode_total = v;
      m.any = true;
    }
  }
  return m;
}

ParsedSlotsSummary ParseSlotsJson(const std::string& body) {
  ParsedSlotsSummary s;
  CountIsProcessing(body, s.busy, s.idle, s.any);
  return s;
}

void MergeSlotsIntoMetrics(ParsedLlamaMetrics& m, const ParsedSlotsSummary& slots) {
  if (!slots.any) return;
  if (!m.saw_requests_processing) {
    m.requests_processing = static_cast<double>(slots.busy);
    m.saw_requests_processing = true;
    m.any = true;
  }
  if (!m.saw_requests_deferred) {
    // Idle capacity as deferred-ish stand-in when Prometheus omitted deferred.
    m.requests_deferred = static_cast<double>(slots.idle);
    m.saw_requests_deferred = true;
    m.any = true;
  }
}

SnoopV1Frame FrameFromParsed(uint32_t pid, const ParsedLlamaMetrics& m) {
  SnoopV1Frame f{};
  f.magic = kSnoopMagic;
  f.version = kSnoopVersion;
  f.flags = 0;
  f.timestamp_ns = NowNs();
  f.pid = pid;
  f.decode_count = static_cast<uint32_t>(m.n_decode_total);
  f.predicted_tok_s = m.predicted_tok_s;
  f.prompt_tok_s = m.prompt_tok_s;
  f.requests_processing = static_cast<uint32_t>(m.requests_processing);
  f.requests_deferred = static_cast<uint32_t>(m.requests_deferred);
  f.decode_latency_ns_sum = 0;
  f.decode_latency_n = 0;
  f.reserved = 0;
  return f;
}

namespace {

class HttpMetricsProvider final : public TelemetryProvider {
 public:
  const char* name() const override { return "http-metrics"; }

  AttachStatus Attach(const AttachOptions& opts) override {
    if (opts.metrics_url.empty()) return AttachStatus::Failed;
    opts_ = opts;
    if (opts_.slots_url.empty()) {
      opts_.slots_url = DeriveSlotsUrl(opts_.metrics_url);
    }
    attached_ = true;
    return AttachStatus::Ok;
  }

  bool StreamMetrics(MetricsCallback cb) override {
    if (!attached_) return false;
    auto body = HttpGet(opts_.metrics_url, 2, opts_.api_key);
    if (!body) {
      std::cerr << "[http-metrics] GET failed: " << opts_.metrics_url << "\n";
      std::this_thread::sleep_for(std::chrono::seconds(1));
      return true; // keep trying
    }
    auto parsed = ParsePrometheusLlamaMetrics(*body);
    if (!parsed.any) {
      std::cerr << "[http-metrics] no llamacpp:* metrics in body\n";
    }

    // Enrich with /slots when Prometheus lacks busy/deferred gauges.
    const bool need_slots =
        !parsed.saw_requests_processing || !parsed.saw_requests_deferred;
    if (need_slots && !opts_.slots_url.empty()) {
      auto slots_body = HttpGet(opts_.slots_url, 2, opts_.api_key);
      if (slots_body) {
        auto slots = ParseSlotsJson(*slots_body);
        MergeSlotsIntoMetrics(parsed, slots);
      } else {
        std::cerr << "[http-metrics] GET /slots failed: " << opts_.slots_url
                  << " (continuing with /metrics only)\n";
      }
    }

    cb(FrameFromParsed(opts_.pid, parsed));
    std::this_thread::sleep_for(std::chrono::seconds(1));
    return true;
  }

  void Detach() override { attached_ = false; }

 private:
  AttachOptions opts_{};
  bool attached_ = false;
};

} // namespace

std::unique_ptr<TelemetryProvider> MakeHttpMetricsProvider() {
  return std::make_unique<HttpMetricsProvider>();
}

} // namespace llamaspy
