// Linux live-attach backend: bpftrace uprobes on llama_decode (parity with
// FreeBSD DTrace pid provider). Spawns `bpftrace -p PID <generated.bt>` and
// parses the same "ts n avg" lines into SnoopV1 frames. Read-only; no ptrace.
// Requires root or CAP_BPF+CAP_PERFMON. Non-Linux builds get a stub.
#include "llamaspy/proc_util.hpp"
#include "llamaspy/telemetry_provider.hpp"
#include "llamaspy/trace_parse.hpp"

#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
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
bool SafeUprobePath(const std::string& path) {
  if (path.size() < 2 || path.size() > 400 || path[0] != '/') return false;
  if (path.find("/../") != std::string::npos) return false;
  if (path.size() >= 3 && path.compare(path.size() - 3, 3, "/..") == 0) return false;
  for (unsigned char c : path) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '/' || c == '.' || c == '_' || c == '-' || c == '+';
    if (!ok) return false;
  }
  return true;
}

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
    if (!BpftraceOnPath()) {
      std::cerr << "[bpftrace-linux] bpftrace not installed; live uprobes unavailable "
                   "(install bpftrace, or use --backend http)\n";
      return AttachStatus::NotSupported;
    }
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
    if (!SafeUprobePath(target)) {
      std::cerr << "[bpftrace-linux] refusing target path with unsafe characters\n";
      return AttachStatus::Failed;
    }
    for (auto [k, v] : {std::pair<std::string, std::string>{"@TARGET@", target}, {"@PID@", std::to_string(pid_)}})
      for (size_t i; (i = s.find(k)) != std::string::npos;) s.replace(i, k.size(), v);
    char dir_tmpl[] = "/tmp/llamaspy-XXXXXX";
    char* made = ::mkdtemp(dir_tmpl);
    if (!made) { std::cerr << "[bpftrace-linux] mkdtemp failed\n"; return AttachStatus::Failed; }
    dir_ = made;
    gen_ = dir_ + "/prog.bt";
    int bfd = ::open(gen_.c_str(), O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_WRONLY, 0600);
    if (bfd < 0) { std::cerr << "[bpftrace-linux] cannot create program file\n"; Detach(); return AttachStatus::Failed; }
    size_t off = 0;
    while (off < s.size()) {
      ssize_t w = ::write(bfd, s.data() + off, s.size() - off);
      if (w < 0) { ::close(bfd); Detach(); return AttachStatus::Failed; }
      off += static_cast<size_t>(w);
    }
    ::close(bfd);
    std::cerr << "[bpftrace-linux] target " << target << "\n";
    int pipefd[2];
    if (PipeCloexec(pipefd) != 0) return AttachStatus::Failed;
    const pid_t self = ::getpid();
    child_ = fork();
    if (child_ < 0) { close(pipefd[0]); close(pipefd[1]); return AttachStatus::Failed; }
    if (child_ == 0) {
      ArmParentDeath(SIGTERM, self);
      ::setpgid(0, 0);
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
    errno = 0;
    if (!fgets(line, sizeof(line), fp_)) {
      if (ferror(fp_) && errno == EINTR) {
        clearerr(fp_);
        return true;
      }
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
    TraceSample sample;
    if (!ParseTraceSummaryLine(line, &sample)) return true;
    SnoopV1Frame f{};
    f.magic = kSnoopMagic; f.version = kSnoopVersion;
    f.timestamp_ns = sample.timestamp_ns; f.pid = pid_;
    f.decode_count = static_cast<uint32_t>(sample.decode_count);
    f.decode_latency_ns_sum = sample.avg_latency_ns * sample.decode_count;
    f.decode_latency_n = static_cast<uint32_t>(sample.decode_count);
    cb(f);
    return true;
  }
  void Detach() override {
    attached_ = false;
    if (fp_) { fclose(fp_); fp_ = nullptr; }
    if (child_ > 0) { ReapChild(child_, SIGINT); child_ = -1; }
    if (!gen_.empty()) { unlink(gen_.c_str()); gen_.clear(); }
    if (!dir_.empty()) { rmdir(dir_.c_str()); dir_.clear(); }
  }
  ~BpftraceLinuxProvider() override { Detach(); }
 private:
  uint32_t pid_ = 0; pid_t child_ = -1; FILE* fp_ = nullptr; bool attached_ = false;
  std::string gen_; std::string dir_;
};
#else
class BpftraceLinuxProvider final : public TelemetryProvider {
 public:
  const char* name() const override { return "bpftrace-linux"; }
  AttachStatus Attach(const AttachOptions&) override {
    std::cerr << "[bpftrace-linux] not supported on this OS "
                 "(FreeBSD uses --backend dtrace; elsewhere use --backend http)\n";
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
