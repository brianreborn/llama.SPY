// Linux live-attach backend: bpftrace uprobes on llama_decode (parity with
// FreeBSD DTrace pid provider). Spawns `bpftrace -p PID <generated.bt>` and
// parses the same "ts n avg" lines into SnoopV1 frames. Read-only; no ptrace.
// Requires root or CAP_BPF+CAP_PERFMON. Non-Linux builds get a stub.
#include "llamaspy/telemetry_provider.hpp"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#if defined(__linux__)
#  include <signal.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

namespace llamaspy {
namespace {
#if defined(__linux__)
std::string FindTargetElf(uint32_t pid) {
  std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
  std::string line;
  while (std::getline(maps, line)) {
    auto p = line.find('/');
    if (p == std::string::npos) continue;
    std::string path = line.substr(p);
    if (path.find("libllama") != std::string::npos &&
        path.find(".so") != std::string::npos)
      return path;
  }
  char buf[4096];
  std::string exe = "/proc/" + std::to_string(pid) + "/exe";
  ssize_t n = readlink(exe.c_str(), buf, sizeof(buf) - 1);
  if (n > 0) { buf[n] = 0; return buf; }
  return {};
}

class BpftraceLinuxProvider final : public TelemetryProvider {
 public:
  const char* name() const override { return "bpftrace-linux"; }
  AttachStatus Attach(const AttachOptions& opts) override {
    if (opts.pid == 0) return AttachStatus::Failed;
    pid_ = opts.pid;
    std::string tmpl = opts.dtrace_script_path;
    auto dot = tmpl.rfind(".d");
    if (dot != std::string::npos && dot + 2 == tmpl.size())
      tmpl = tmpl.substr(0, dot) + ".bt";
    if (const char* e = std::getenv("LLAMASPY_BPFTRACE_SCRIPT"); e && *e) tmpl = e;
    std::ifstream in(tmpl);
    if (!in) { std::cerr << "[bpftrace-linux] script not found: " << tmpl << "\n"; return AttachStatus::Failed; }
    std::stringstream ss; ss << in.rdbuf();
    std::string s = ss.str();
    std::string target = FindTargetElf(pid_);
    if (target.empty()) { std::cerr << "[bpftrace-linux] cannot read /proc/" << pid_ << "\n"; return AttachStatus::NeedPrivileges; }
    for (auto [k, v] : {std::pair<std::string, std::string>{"@TARGET@", target}, {"@PID@", std::to_string(pid_)}})
      for (size_t i; (i = s.find(k)) != std::string::npos;) s.replace(i, k.size(), v);
    gen_ = "/tmp/llamaspy-" + std::to_string(getpid()) + ".bt";
    { std::ofstream o(gen_); o << s; }
    std::cerr << "[bpftrace-linux] target " << target << "\n";
    int pipefd[2];
    if (pipe(pipefd) != 0) return AttachStatus::Failed;
    child_ = fork();
    if (child_ < 0) return AttachStatus::Failed;
    if (child_ == 0) {
      close(pipefd[0]); dup2(pipefd[1], STDOUT_FILENO); close(pipefd[1]);
      std::string p = std::to_string(pid_);
      execlp("bpftrace", "bpftrace", "-q", "-p", p.c_str(), gen_.c_str(), (char*)nullptr);
      _exit(127);
    }
    close(pipefd[1]);
    fp_ = fdopen(pipefd[0], "r");
    if (!fp_) { Detach(); return AttachStatus::Failed; }
    attached_ = true;
    return AttachStatus::Ok;
  }
  bool StreamMetrics(MetricsCallback cb) override {
    if (!attached_ || !fp_) return false;
    char line[512];
    if (!fgets(line, sizeof(line), fp_)) {
      int st = 0;
      if (child_ > 0 && waitpid(child_, &st, 0) > 0) {
        child_ = -1;
        if (WIFEXITED(st) && WEXITSTATUS(st) == 127)
          std::cerr << "[bpftrace-linux] bpftrace not installed (apt/dnf install bpftrace)\n";
        else if (!(WIFEXITED(st) && WEXITSTATUS(st) == 0))
          std::cerr << "[bpftrace-linux] bpftrace exited; need root or CAP_BPF+CAP_PERFMON\n";
      }
      return false;
    }
    if (line[0] == '#' || line[0] == '\n') return true;
    unsigned long long ts = 0, n = 0, avg = 0;
    if (std::sscanf(line, "%llu %llu %llu", &ts, &n, &avg) != 3) return true;
    SnoopV1Frame f{};
    f.magic = kSnoopMagic; f.version = kSnoopVersion; f.timestamp_ns = ts; f.pid = pid_;
    f.decode_count = static_cast<uint32_t>(n);
    f.decode_latency_ns_sum = static_cast<uint64_t>(avg) * n;
    f.decode_latency_n = static_cast<uint32_t>(n);
    cb(f);
    return true;
  }
  void Detach() override {
    attached_ = false;
    if (fp_) { fclose(fp_); fp_ = nullptr; }
    if (child_ > 0) { kill(child_, SIGINT); waitpid(child_, nullptr, 0); child_ = -1; }
    if (!gen_.empty()) { unlink(gen_.c_str()); gen_.clear(); }
  }
  ~BpftraceLinuxProvider() override { Detach(); }
 private:
  uint32_t pid_ = 0; pid_t child_ = -1; FILE* fp_ = nullptr; bool attached_ = false; std::string gen_;
};
#else
class BpftraceLinuxProvider final : public TelemetryProvider {
 public:
  const char* name() const override { return "bpftrace-linux"; }
  AttachStatus Attach(const AttachOptions&) override {
    std::cerr << "[bpftrace-linux] stub: Linux only (use --backend dtrace on FreeBSD)\n";
    return AttachStatus::NotSupported;
  }
  bool StreamMetrics(MetricsCallback) override { return false; }
  void Detach() override {}
};
#endif
} // namespace
std::unique_ptr<TelemetryProvider> MakeBpftraceLinuxProvider() {
  return std::make_unique<BpftraceLinuxProvider>();
}
} // namespace llamaspy
