#include "llamaspy/tui_stub.hpp"
#include "llamaspy/i18n.hpp"

#include <cstdio>
#include <cstring>
#include <string>

namespace llamaspy {

const char* AttachModeBadgeName(AttachModeBadge mode) {
  switch (mode) {
    case AttachModeBadge::Dtrace:
      return "dtrace";
    case AttachModeBadge::Http:
      return "http";
    case AttachModeBadge::Log:
      return "log";
    case AttachModeBadge::Auto:
    default:
      return "auto";
  }
}

AttachModeBadge BadgeFromBackendName(const char* provider_name,
                                     const char* cli_backend) {
  const char* s = (cli_backend && cli_backend[0]) ? cli_backend : provider_name;
  if (!s) return AttachModeBadge::Auto;
  if (std::strstr(s, "dtrace") != nullptr || std::strstr(s, "bpftrace") != nullptr) return AttachModeBadge::Dtrace;  // live-attach badge
  if (std::strstr(s, "http") != nullptr) return AttachModeBadge::Http;
  if (std::strstr(s, "log") != nullptr) return AttachModeBadge::Log;
  if (std::strcmp(s, "auto") == 0) return AttachModeBadge::Auto;
  return AttachModeBadge::Auto;
}

void BeginHud(HudState& st) {
  st.active = true;
  // Hide cursor; clear screen once so subsequent home redraws stay clean.
  std::fputs("\033[?25l\033[2J\033[H", stdout);
  std::fflush(stdout);
}

void EndHud(HudState& st) {
  if (!st.active) return;
  st.active = false;
  // Show cursor again; leave last frame on screen, then newline.
  std::fputs("\033[?25h\n", stdout);
  std::fflush(stdout);
}

void RenderHud(HudState& st, const SnoopV1Frame& f) {
  // Derive decode rate from decode_count deltas when timestamps advance.
  if (st.primed && f.timestamp_ns > st.last_timestamp_ns) {
    const double dt_s =
        static_cast<double>(f.timestamp_ns - st.last_timestamp_ns) * 1e-9;
    if (dt_s > 0.0 && f.decode_count >= st.last_decode_count) {
      st.decode_rate_hz =
          static_cast<double>(f.decode_count - st.last_decode_count) / dt_s;
    }
  }
  st.last_decode_count = f.decode_count;
  st.last_timestamp_ns = f.timestamp_ns;
  st.primed = true;

  double avg_lat_us = 0.0;
  if (f.decode_latency_n > 0) {
    avg_lat_us = (static_cast<double>(f.decode_latency_ns_sum) /
                  static_cast<double>(f.decode_latency_n)) /
                 1000.0;
  }

  // Home cursor; redraw a fixed one-pane block (no ncurses).
  std::fputs("\033[H", stdout);
  // I18N: labels via T(); CJK may shift the right border slightly.
  const std::string title(T("hud.title"));
  const std::string mode_l(T("hud.mode"));
  const std::string gen_l(T("hud.gen"));
  const std::string ingest_l(T("hud.ingest"));
  const std::string busy_l(T("hud.busy"));
  const std::string def_l(T("hud.deferred"));
  const std::string avg_l(T("hud.avg_decode"));
  std::printf(
      "╭─ %s ──────────────────────────────────────╮\n"
      "│ %s %-6s                          pid %-8u │\n"
      "├──────────────────────────────────────────────────┤\n"
      "│ %-12s %8.1f tok/s                     │\n"
      "│ %-12s %8.1f tok/s                     │\n"
      "│ %-12s %8u   %-8s %8u         │\n"
      "│ n_decode     %8u   rate     %8.1f /s      │\n"
      "│ %-12s %8.1f µs                        │\n"
      "╰──────────────────────────────────────────────────╯\n",
      title.c_str(), mode_l.c_str(),
      AttachModeBadgeName(st.mode), f.pid, gen_l.c_str(),
      f.predicted_tok_s, ingest_l.c_str(), f.prompt_tok_s,
      busy_l.c_str(), f.requests_processing, def_l.c_str(),
      f.requests_deferred, f.decode_count, st.decode_rate_hz,
      avg_l.c_str(), avg_lat_us);
  std::fflush(stdout);
}

std::string FormatHudLine(const SnoopV1Frame& f) {
  char buf[256];
  std::snprintf(buf, sizeof(buf),
                "llama.SPY | pid=%u | gen=%.1f tok/s | prompt=%.1f tok/s | "
                "busy=%u deferred=%u | decodes=%u",
                f.pid, f.predicted_tok_s, f.prompt_tok_s, f.requests_processing,
                f.requests_deferred, f.decode_count);
  return std::string(buf);
}

} // namespace llamaspy
