// FreeBSD DTrace backend — primary v1 TelemetryProvider for llama.SPY.
//
// On FreeBSD (__FreeBSD__): Attach may spawn
//   dtrace -p <PID> -s <dtrace_script_path>
// and parse the per-second summary lines from scripts/llama_decode.d.
//
// On non-FreeBSD hosts (e.g. this Linux CI/box): the provider compiles as a
// stub that returns AttachStatus::NotSupported so CMake still links.

#include "llamaspy/proc_util.hpp"
#include "llamaspy/telemetry_provider.hpp"
#include "llamaspy/trace_parse.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#if defined(LLAMASPY_FREEBSD) || defined(__FreeBSD__)
#  include <signal.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

namespace llamaspy {
namespace {

#if defined(LLAMASPY_FREEBSD) || defined(__FreeBSD__)

class DtraceFreeBsdProvider final : public TelemetryProvider {
 public:
  const char* name() const override { return "dtrace-freebsd"; }

  AttachStatus Attach(const AttachOptions& opts) override {
    if (opts.pid == 0) return AttachStatus::Failed;
    script_ = opts.dtrace_script_path.empty()
                  ? "scripts/llama_decode.d"
                  : opts.dtrace_script_path;
    pid_ = opts.pid;

    // Spawn: dtrace -p PID -s script
    // TODO: prefer libdtrace embedding for tighter SnoopV1 integration.
    int pipefd[2];
    if (PipeCloexec(pipefd) != 0) return AttachStatus::Failed;
    const pid_t self = ::getpid();
    child_ = fork();
    if (child_ < 0) {
      close(pipefd[0]);
      close(pipefd[1]);
      return AttachStatus::Failed;
    }
    if (child_ == 0) {
      ArmParentDeath(SIGTERM, self);
      ::setpgid(0, 0);
      close(pipefd[0]);
      dup2(pipefd[1], STDOUT_FILENO);
      close(pipefd[1]);
      std::string pid_s = std::to_string(pid_);
      const char* over = std::getenv("LLAMASPY_DTRACE");
      std::string bin = (over && *over) ? std::string(over) : ResolveTrusted("dtrace");
      if (!bin.empty())
        execl(bin.c_str(), "dtrace", "-p", pid_s.c_str(), "-s", script_.c_str(),
              static_cast<char*>(nullptr));
      _exit(127);
    }
    close(pipefd[1]);
    fp_ = fdopen(pipefd[0], "r");
    if (!fp_) {
      kill(child_, SIGTERM);
      waitpid(child_, nullptr, 0);
      child_ = -1;
      return AttachStatus::NeedPrivileges;
    }
    attached_ = true;
    return AttachStatus::Ok;
  }

  bool StreamMetrics(MetricsCallback cb) override {
    if (!attached_ || !fp_) return false;
    char line[512];
    errno = 0;
    if (!fgets(line, sizeof(line), fp_)) {
      if (ferror(fp_) && errno == EINTR) {
        clearerr(fp_);
        return true;
      }
      return false;
    }
    TraceSample sample;
    if (!ParseTraceSummaryLine(line, &sample)) return true;
    SnoopV1Frame f{};
    f.magic = kSnoopMagic;
    f.version = kSnoopVersion;
    f.timestamp_ns = sample.timestamp_ns;
    f.pid = pid_;
    f.decode_count = static_cast<uint32_t>(sample.decode_count);
    f.decode_latency_ns_sum = sample.avg_latency_ns * sample.decode_count;
    f.decode_latency_n = static_cast<uint32_t>(sample.decode_count);
    // Self-calculated tok/s left 0 here; TUI/collector may derive from deltas.
    cb(f);
    return true;
  }

  void Detach() override {
    attached_ = false;
    if (fp_) {
      fclose(fp_);
      fp_ = nullptr;
    }
    if (child_ > 0) {
      ReapChild(child_, SIGTERM);
      child_ = -1;
    }
  }

  ~DtraceFreeBsdProvider() override { Detach(); }

 private:
  AttachOptions opts_{};
  std::string script_;
  uint32_t pid_ = 0;
  pid_t child_ = -1;
  FILE* fp_ = nullptr;
  bool attached_ = false;
};

#else // !__FreeBSD__

class DtraceFreeBsdProvider final : public TelemetryProvider {
 public:
  const char* name() const override { return "dtrace-freebsd"; }

  AttachStatus Attach(const AttachOptions&) override {
    // Primary path exists only on FreeBSD. Linux/macOS/Windows peers land later.
    std::cerr << "[dtrace-freebsd] not supported on this OS. "
                 "On Linux use --backend bpftrace (uprobe on llama_decode) or "
                 "--backend http --metrics-url URL. "
                 "Build on FreeBSD for the pid provider and scripts/llama_decode.d.\n";
    return AttachStatus::NotSupported;
  }

  bool StreamMetrics(MetricsCallback) override { return false; }
  void Detach() override {}
};

#endif

} // namespace

std::unique_ptr<TelemetryProvider> MakeDtraceFreeBsdProvider() {
  return std::make_unique<DtraceFreeBsdProvider>();
}

} // namespace llamaspy
