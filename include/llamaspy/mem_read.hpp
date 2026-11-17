#pragma once
// Read-only memory backend for Game Genie / HookScript bindings.
// Never writes the target. Linux: process_vm_readv, then /proc/PID/mem.
// FreeBSD: /proc/PID/mem when procfs is mounted, else ptrace(PT_IO, PIOD_READ_D).
// Address model: load_bias + symbol_st_value + off (off is a displacement;
// 0 reads the symbol itself). See docs/GAME_GENIE.md and scripts/gen-gg-offsets.sh.

#include "llamaspy/game_genie.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace llamaspy {

enum class MemStatus {
  Ok = 0,
  NoPid,
  NoSuchProcess,
  PermissionDenied,
  FingerprintMismatch,
  SymbolNotFound,
  Unsupported,
  ReadError,
  BadBinding,
};

enum class MemBackend {
  Auto,
  ProcessVmReadv,  // Linux process_vm_readv
  ProcMem,         // /proc/PID/mem (Linux or FreeBSD procfs)
  PtraceIo,        // FreeBSD PT_IO / PIOD_READ_D (briefly stops the target)
};

struct MapRange {
  uint64_t start = 0;
  uint64_t end = 0;
  uint64_t file_offset = 0;
  bool has_file_offset = false;
  std::string perms;
  std::string path;
};

struct BindingRead {
  MemStatus status = MemStatus::ReadError;
  std::string error;
  std::string sym;
  uint64_t displacement = 0;
  uint64_t address = 0;
  uint32_t width = 0;
  GgValueType type = GgValueType::Unknown;
  bool has_value = false;
  uint64_t raw_bits = 0;  // integer bits, or the low 8 bytes
  double number = 0;      // decoded numeric value when has_value
  std::string hex;        // raw bytes, lowercase hex
  std::string module_path;
  std::string build_id;  // lowercase hex, no prefix
};

// Lowercase hex GNU build-id, or empty if the file has none.
std::string GnuBuildIdFromFile(const std::string& path);

// empty fp_field means "no constraint" (accepted).
// Otherwise the field must name the same id (buildid:<hex> or the raw hex).
bool FingerprintAccepts(const std::string& module_build_id_hex, const std::string& fp_field);

std::vector<MapRange> ParseLinuxMapsText(std::string_view text);
std::vector<MapRange> ParseProcstatVText(std::string_view text);

// Read exactly n bytes. On failure buf is untouched and *err explains why.
// Permission errors name ptrace_scope / same-uid. This function never writes.
bool ReadProcessBytes(uint32_t pid, uint64_t addr, void* buf, size_t n,
                      std::string* err, MemBackend backend = MemBackend::Auto);

BindingRead ReadBinding(uint32_t pid, const GgBinding& binding,
                        MemBackend backend = MemBackend::Auto);

// JSON object. value is null when the read did not succeed.
std::string BindingReadJson(const BindingRead& r);

// Target for readBinding() / read_binding: handlers. Single-threaded CLI.
void SetMemTargetPid(uint32_t pid);
uint32_t MemTargetPid();
void SetMemCodebook(const GgCodebook* book);
const GgCodebook* MemCodebook();

}  // namespace llamaspy
