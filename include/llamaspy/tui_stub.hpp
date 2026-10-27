#pragma once
// Minimal terminal HUD for llama.SPY — no ncurses yet.
// FreeBSD-first: collector feeds SnoopV1; this formats a one-pane refresh.

#include "llamaspy/snoop_v1.hpp"

#include <cstdint>
#include <string>

namespace llamaspy {

// Attach-mode badge shown in the HUD (dtrace|http|log|auto).
enum class AttachModeBadge : uint8_t {
  Dtrace = 0,
  Http,
  Log,
  Auto,
};

const char* AttachModeBadgeName(AttachModeBadge mode);

// Map TelemetryProvider::name() / CLI --backend to a badge.
AttachModeBadge BadgeFromBackendName(const char* provider_name,
                                     const char* cli_backend);

struct HudState {
  AttachModeBadge mode = AttachModeBadge::Auto;
  uint32_t last_decode_count = 0;
  uint64_t last_timestamp_ns = 0;
  double decode_rate_hz = 0.0; // derived n_decode / Δt
  bool primed = false;
  bool active = false; // true after BeginHud; restores cursor on EndHud
};

// ANSI clear + home, then a multi-line one-pane HUD:
//   ingest/gen tok/s, busy slots, n_decode / decode rate, mode badge.
void BeginHud(HudState& st);
void RenderHud(HudState& st, const SnoopV1Frame& f);
void EndHud(HudState& st);

// One-line formatter (kept for logs / non-TUI callers).
std::string FormatHudLine(const SnoopV1Frame& f);

} // namespace llamaspy
