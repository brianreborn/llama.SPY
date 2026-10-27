#pragma once
// SnoopV1 — frozen binary interchange for llama.SPY (FreeBSD-first).
// Magic 'LLMS' = 0x4C4C4D53.
// Byte order: SHM ring = host order; snoop_hton only at network/socketpair
// privilege boundary (see docs/DESIGN.md IPC section).

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace llamaspy {

inline constexpr uint32_t kSnoopMagic = 0x4C4C4D53u; // 'LLMS'
inline constexpr uint16_t kSnoopVersion = 1;

#if defined(_MSC_VER)
#  include <stdlib.h>
#  define LLAMASPY_BSWAP32(x) _byteswap_ulong(x)
#  define LLAMASPY_BSWAP64(x) _byteswap_uint64(x)
#  define LLAMASPY_BSWAP16(x) _byteswap_ushort(x)
#else
#  define LLAMASPY_BSWAP32(x) __builtin_bswap32(x)
#  define LLAMASPY_BSWAP64(x) __builtin_bswap64(x)
#  define LLAMASPY_BSWAP16(x) __builtin_bswap16(x)
#endif

inline bool host_is_little_endian() {
  const uint16_t x = 1;
  return *reinterpret_cast<const uint8_t*>(&x) == 1;
}

inline uint16_t hton16(uint16_t v) {
  return host_is_little_endian() ? LLAMASPY_BSWAP16(v) : v;
}
inline uint32_t hton32(uint32_t v) {
  return host_is_little_endian() ? LLAMASPY_BSWAP32(v) : v;
}
inline uint64_t hton64(uint64_t v) {
  return host_is_little_endian() ? LLAMASPY_BSWAP64(v) : v;
}
inline uint16_t ntoh16(uint16_t v) { return hton16(v); }
inline uint32_t ntoh32(uint32_t v) { return hton32(v); }
inline uint64_t ntoh64(uint64_t v) { return hton64(v); }

// Packed on-wire / SHM slot frame (64 bytes). SHM stores host byte order;
// call snoop_hton before crossing socketpair/network privilege boundary.
#pragma pack(push, 1)
struct SnoopV1Frame {
  uint32_t magic;                 // kSnoopMagic
  uint16_t version;               // kSnoopVersion
  uint16_t flags;                 // bit0: little-endian payload before hton
  uint64_t timestamp_ns;          // monotonic or wall clock (producer choice)
  uint32_t pid;
  uint32_t decode_count;          // llama_decode calls observed in window
  double   predicted_tok_s;       // generation throughput
  double   prompt_tok_s;          // prompt throughput
  uint32_t requests_processing;
  uint32_t requests_deferred;
  uint64_t decode_latency_ns_sum; // sum of decode durations in window
  uint32_t decode_latency_n;      // sample count for average
  uint32_t reserved;
};
#pragma pack(pop)

static_assert(sizeof(SnoopV1Frame) == 64, "SnoopV1Frame must stay 64 bytes");

inline SnoopV1Frame snoop_hton(SnoopV1Frame f) {
  f.magic = hton32(f.magic);
  f.version = hton16(f.version);
  f.flags = hton16(f.flags);
  f.timestamp_ns = hton64(f.timestamp_ns);
  f.pid = hton32(f.pid);
  f.decode_count = hton32(f.decode_count);
  // IEEE-754 doubles: swap bytes on little-endian hosts for wire form
  auto swap_f64 = [](double d) {
    uint64_t u;
    static_assert(sizeof(u) == sizeof(d));
    std::memcpy(&u, &d, sizeof(u));
    u = hton64(u);
    std::memcpy(&d, &u, sizeof(d));
    return d;
  };
  f.predicted_tok_s = swap_f64(f.predicted_tok_s);
  f.prompt_tok_s = swap_f64(f.prompt_tok_s);
  f.requests_processing = hton32(f.requests_processing);
  f.requests_deferred = hton32(f.requests_deferred);
  f.decode_latency_ns_sum = hton64(f.decode_latency_ns_sum);
  f.decode_latency_n = hton32(f.decode_latency_n);
  f.reserved = hton32(f.reserved);
  return f;
}

inline SnoopV1Frame snoop_ntoh(SnoopV1Frame f) { return snoop_hton(f); }

// Shared-memory ring header (Race Review harden).
// Each of head, tail, and meta lives on its own 64-byte cache line so producer
// advances of head do not false-share with consumer advances of tail, and
// neither pings capacity/magic/version on the meta line.
// Header is POD atomics only — no mutex in the SHM path.
// Cross-process atomics: is_always_lock_free frozen below.
struct SharedRingHeader {
  alignas(64) std::atomic<uint64_t> head{0}; // producer advances (release)
  alignas(64) std::atomic<uint64_t> tail{0}; // consumer advances (release)
  // Meta cache line — NOT on tail's line (Race Review #1).
  alignas(64) uint32_t capacity_frames{0};
  uint32_t frame_bytes{sizeof(SnoopV1Frame)};
  uint32_t magic{kSnoopMagic};
  uint32_t version{kSnoopVersion};
  // Reserved for collector-restart poison / remap detection (Race Review #5).
  // Protocol sketch in DESIGN.md; publish/consume not implemented yet.
  uint64_t generation{0};
};

static_assert(alignof(SharedRingHeader) >= 64, "SharedRingHeader cache-line align");
static_assert(std::atomic<uint64_t>::is_always_lock_free,
              "SHM ring requires lock-free atomic<uint64_t>");
static_assert(offsetof(SharedRingHeader, head) % 64 == 0, "head cache-line aligned");
static_assert(offsetof(SharedRingHeader, tail) % 64 == 0, "tail cache-line aligned");
static_assert(offsetof(SharedRingHeader, capacity_frames) % 64 == 0,
              "meta cache-line aligned");
static_assert(offsetof(SharedRingHeader, tail) - offsetof(SharedRingHeader, head) >= 64,
              "head/tail on distinct cache lines");
static_assert(offsetof(SharedRingHeader, capacity_frames) -
                  offsetof(SharedRingHeader, tail) >=
              64,
              "meta not on tail's cache line");

} // namespace llamaspy
