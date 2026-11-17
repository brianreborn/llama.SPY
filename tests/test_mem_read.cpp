#include "llamaspy/mem_read.hpp"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/prctl.h>
#endif

extern "C" {
volatile uint64_t llamaspy_test_u64 = 0x1122334455667788ULL;
volatile uint32_t llamaspy_test_u32 = 0xA1B2C3D4u;
struct LlamaspyTestStruct {
  uint64_t head;
  uint32_t tail;
};
volatile LlamaspyTestStruct llamaspy_test_struct = {0x1111111111111111ULL, 0x22222222u};
}

static int g_fail = 0;

#define CHECK(cond)                                                                 \
  do {                                                                              \
    if (!(cond)) {                                                                  \
      std::cerr << "FAIL " << __LINE__ << " " << #cond << "\n";                     \
      ++g_fail;                                                                     \
    }                                                                               \
  } while (0)

static void CheckParsers() {
  const char* maps =
      "55a3c0000000-55a3c0001000 r--p 00000000 08:01 1 /tmp/llama-server\n"
      "55a3c0001000-55a3c0020000 r-xp 00001000 08:01 1 /tmp/llama-server\n"
      "7fff00000000-7fff00021000 rw-p 00000000 00:00 0 [stack]\n"
      "7f0000000000-7f0000001000 r-xp 00000000 08:01 2 /tmp/libllama.so\n";
  auto ranges = llamaspy::ParseLinuxMapsText(maps);
  CHECK(ranges.size() == 4);
  if (ranges.size() == 4) {
    CHECK(ranges[0].path == "/tmp/llama-server");
    CHECK(ranges[0].start == 0x55a3c0000000ULL);
    CHECK(ranges[0].has_file_offset);
    CHECK(ranges[0].file_offset == 0);
    CHECK(ranges[1].file_offset == 0x1000);
    CHECK(ranges[2].path.empty());
    CHECK(ranges[3].path == "/tmp/libllama.so");
  }

  const char* ps =
      "  PID              START                END PRT  RES PRES REF SHD FLAG  TP PATH\n"
      "   12           0x200000           0x240000 r-x    4    0   1   0 CN--- vn "
      "/usr/local/bin/llama-server\n"
      "   12           0x400000           0x410000 rw-    1    0   1   0 CN--- vn "
      "/usr/local/bin/llama-server\n";
  auto fr = llamaspy::ParseProcstatVText(ps);
  CHECK(fr.size() == 2);
  if (fr.size() == 2) {
    CHECK(fr[0].start == 0x200000);
    CHECK(fr[0].end == 0x240000);
    CHECK(fr[0].path == "/usr/local/bin/llama-server");
  }

  CHECK(llamaspy::FingerprintAccepts("abc", ""));
  CHECK(llamaspy::FingerprintAccepts("AbC", "buildid:abc"));
  CHECK(!llamaspy::FingerprintAccepts("abc", "buildid:nope"));
  CHECK(!llamaspy::FingerprintAccepts("abc", "llama.cpp@fake"));
  CHECK(!llamaspy::FingerprintAccepts("", "buildid:abc"));
}

static llamaspy::GgBinding Binding(const char* sym, uint64_t off, llamaspy::GgValueType ty,
                                   const std::string& fp) {
  llamaspy::GgBinding b;
  b.symbol = sym;
  b.offset = off;
  b.has_offset = true;
  b.type = ty;
  b.width = llamaspy::DefaultWidth(ty);
  b.build_fp = fp;
  return b;
}

int main() {
  CheckParsers();

  const uint64_t kChildU64 = 0x8877665544332211ULL;
  const uint32_t kChildU32 = 0x01020304u;
  const uint32_t kChildTail = 0xAABBCCDDu;

  pid_t child = ::fork();
  if (child < 0) {
    std::cerr << "fork failed\n";
    return 1;
  }
  if (child == 0) {
#if defined(__linux__)
    ::prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
#endif
    llamaspy_test_u64 = kChildU64;
    llamaspy_test_u32 = kChildU32;
    llamaspy_test_struct.tail = kChildTail;
    ::raise(SIGSTOP);
    _exit(0);
  }
  int st = 0;
  ::waitpid(child, &st, WUNTRACED);
  if (!WIFSTOPPED(st)) {
    std::cerr << "child did not stop\n";
    ::kill(child, SIGKILL);
    ::waitpid(child, nullptr, 0);
    return 1;
  }

  std::string build = llamaspy::GnuBuildIdFromFile("/proc/self/exe");
  std::cerr << "build-id=" << (build.empty() ? "(none)" : build) << "\n";
  std::string fp = build.empty() ? "" : "buildid:" + build;

  auto u64 = Binding("llamaspy_test_u64", 0, llamaspy::GgValueType::U64, fp);
  auto rd = llamaspy::ReadBinding(static_cast<uint32_t>(child), u64);
  if (rd.status != llamaspy::MemStatus::Ok) {
    std::cerr << "u64 read failed: " << rd.error << "\n";
    ++g_fail;
  } else {
    CHECK(rd.address == reinterpret_cast<uint64_t>(&llamaspy_test_u64));
    CHECK(rd.raw_bits == kChildU64);
    CHECK(rd.raw_bits != llamaspy_test_u64);
    CHECK(rd.hex.size() == 16);
  }

#if defined(__linux__)
  auto via_vm = llamaspy::ReadBinding(static_cast<uint32_t>(child), u64,
                                     llamaspy::MemBackend::ProcessVmReadv);
  CHECK(via_vm.status == llamaspy::MemStatus::Ok);
  if (via_vm.status == llamaspy::MemStatus::Ok) CHECK(via_vm.raw_bits == kChildU64);

  std::string ptrace_err;
  uint8_t scratch[4] = {};
  bool ptrace_ok = llamaspy::ReadProcessBytes(static_cast<uint32_t>(child), rd.address, scratch,
                                              sizeof(scratch), &ptrace_err,
                                              llamaspy::MemBackend::PtraceIo);
  CHECK(!ptrace_ok);
  CHECK(ptrace_err.find("FreeBSD") != std::string::npos);

  auto via_proc = llamaspy::ReadBinding(static_cast<uint32_t>(child), u64, llamaspy::MemBackend::ProcMem);
  if (via_proc.status != llamaspy::MemStatus::Ok) {
    std::cerr << "proc mem fallback failed: " << via_proc.error << "\n";
    ++g_fail;
  } else {
    CHECK(via_proc.raw_bits == kChildU64);
  }
#else
  auto via_vm = llamaspy::ReadBinding(static_cast<uint32_t>(child), u64,
                                     llamaspy::MemBackend::ProcessVmReadv);
  CHECK(via_vm.status == llamaspy::MemStatus::Unsupported);
  auto via_ptr = llamaspy::ReadBinding(static_cast<uint32_t>(child), u64,
                                      llamaspy::MemBackend::PtraceIo);
  if (via_ptr.status != llamaspy::MemStatus::Ok) {
    std::cerr << "ptrace read failed: " << via_ptr.error << "\n";
    ++g_fail;
  } else {
    CHECK(via_ptr.raw_bits == kChildU64);
  }
#endif

  auto u32 = Binding("llamaspy_test_u32", 0, llamaspy::GgValueType::U32, fp);
  auto rd32 = llamaspy::ReadBinding(static_cast<uint32_t>(child), u32);
  CHECK(rd32.status == llamaspy::MemStatus::Ok);
  if (rd32.status == llamaspy::MemStatus::Ok) CHECK(rd32.raw_bits == kChildU32);

  auto tail = Binding("llamaspy_test_struct", 8, llamaspy::GgValueType::U32, fp);
  auto rdt = llamaspy::ReadBinding(static_cast<uint32_t>(child), tail);
  CHECK(rdt.status == llamaspy::MemStatus::Ok);
  if (rdt.status == llamaspy::MemStatus::Ok) {
    CHECK(rdt.address == reinterpret_cast<uint64_t>(&llamaspy_test_struct) + 8);
    CHECK(rdt.raw_bits == kChildTail);
  }

  auto bad = Binding("llamaspy_test_u64", 0, llamaspy::GgValueType::U64, "buildid:00000000deadbeef");
  auto mismatch = llamaspy::ReadBinding(static_cast<uint32_t>(child), bad);
  CHECK(mismatch.status == llamaspy::MemStatus::FingerprintMismatch);
  CHECK(!mismatch.has_value);
  CHECK(mismatch.error.find("mismatch") != std::string::npos);

  auto missing = Binding("this_symbol_does_not_exist", 0, llamaspy::GgValueType::U64, fp);
  auto nosym = llamaspy::ReadBinding(static_cast<uint32_t>(child), missing);
  CHECK(nosym.status == llamaspy::MemStatus::SymbolNotFound);
  CHECK(!nosym.has_value);

  llamaspy::GgCodebook book;
  book.bindings.push_back(u64);
  std::string detail;
  auto apply = llamaspy::ApplyReadOnly(static_cast<uint32_t>(child), book, &detail);
  CHECK(apply == llamaspy::GgApplyStatus::Ok);
  CHECK(detail.find("8877665544332211") != std::string::npos ||
        detail.find("hex=") != std::string::npos);

  std::string perr;
  bool poked = llamaspy::ReadProcessBytes(1, 0x1000, &st, sizeof(st), &perr);
  if (!poked && perr.find("Permission denied") != std::string::npos) {
    CHECK(perr.find("never writes") != std::string::npos);
#if defined(__linux__)
    CHECK(perr.find("ptrace") != std::string::npos);
#endif
  }

  std::string js = llamaspy::BindingReadJson(rd);
  if (rd.status == llamaspy::MemStatus::Ok) {
    CHECK(js.find("\"ok\":true") != std::string::npos);
    // Raw hex is little-endian memory order of 0x8877665544332211.
    CHECK(rd.hex == "1122334455667788");
    CHECK(js.find("1122334455667788") != std::string::npos);
  }

  auto ident = llamaspy::CaptureProcIdentity(static_cast<uint32_t>(child));
  CHECK(ident.alive);
  CHECK(llamaspy::ProcIdentityStill(ident));
  ::kill(child, SIGKILL);
  ::waitpid(child, nullptr, 0);
  CHECK(!llamaspy::ProcIdentityStill(ident));
  llamaspy::ReleaseProcIdentity(&ident);

  if (g_fail) {
    std::cerr << g_fail << " failure(s)\n";
    return 1;
  }
  std::cout << "mem_read ok\n";
  return 0;
}
