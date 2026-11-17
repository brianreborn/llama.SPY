#include "llamaspy/serve.hpp"

#include "llamaspy/snoop_v1.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fstream>
#include <grp.h>
#include <iostream>
#include <poll.h>
#include <pwd.h>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

#if defined(__linux__)
#  include <linux/audit.h>
#  include <linux/filter.h>
#  include <linux/landlock.h>
#  include <linux/seccomp.h>
#  include <sys/prctl.h>
#  include <sys/syscall.h>
#endif

#if defined(__FreeBSD__) || defined(LLAMASPY_FREEBSD)
#  include <sys/capsicum.h>
#endif

namespace llamaspy {
namespace {

std::string Trim(std::string s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' ||
                        s.front() == '\n')) {
    s.erase(s.begin());
  }
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' ||
                        s.back() == '\n')) {
    s.pop_back();
  }
  return s;
}

std::string Lower(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return s;
}

bool ConstTimeEqual(const std::string& a, const std::string& b) {
  const size_t n = a.size() > b.size() ? a.size() : b.size();
  unsigned char diff = (a.size() == b.size()) ? 0 : 1;
  for (size_t i = 0; i < n; ++i) {
    unsigned char ca = i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
    unsigned char cb = i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
    diff = static_cast<unsigned char>(diff | (ca ^ cb));
  }
  return diff == 0;
}

void ScrubFds(int keep) {
  long max = ::sysconf(_SC_OPEN_MAX);
  if (max < 0 || max > 4096) max = 4096;
  for (int fd = 3; fd < static_cast<int>(max); ++fd) {
    if (fd == keep) continue;
    ::close(fd);
  }
}

#if defined(__linux__)
sock_filter Sf(uint16_t code, uint8_t jt, uint8_t jf, uint32_t k) {
  sock_filter s{};
  s.code = code;
  s.jt = jt;
  s.jf = jf;
  s.k = k;
  return s;
}

void InstallSeccompDeny(const int* nrs, size_t count) {
#  if defined(__x86_64__)
  const uint32_t arch = AUDIT_ARCH_X86_64;
#  elif defined(__aarch64__)
  const uint32_t arch = AUDIT_ARCH_AARCH64;
#  elif defined(__i386__)
  const uint32_t arch = AUDIT_ARCH_I386;
#  else
  std::cerr << "llama.SPY: seccomp skipped on this architecture\n";
  return;
#  endif
  std::vector<sock_filter> prog;
  prog.push_back(Sf(BPF_LD | BPF_W | BPF_ABS,
                    0, 0, static_cast<uint32_t>(offsetof(struct seccomp_data, arch))));
  prog.push_back(Sf(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, arch));
  prog.push_back(Sf(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW));
  prog.push_back(Sf(BPF_LD | BPF_W | BPF_ABS,
                    0, 0, static_cast<uint32_t>(offsetof(struct seccomp_data, nr))));
  for (size_t i = 0; i < count; ++i) {
    prog.push_back(Sf(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, static_cast<uint32_t>(nrs[i])));
    prog.push_back(Sf(BPF_RET | BPF_K, 0, 0,
                      SECCOMP_RET_ERRNO | (static_cast<uint32_t>(EPERM) & SECCOMP_RET_DATA)));
  }
  prog.push_back(Sf(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW));
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    std::cerr << "llama.SPY: PR_SET_NO_NEW_PRIVS failed: " << std::strerror(errno) << "\n";
    return;
  }
  sock_fprog fp{};
  fp.len = static_cast<unsigned short>(prog.size());
  fp.filter = prog.data();
  if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fp) != 0) {
    std::cerr << "llama.SPY: seccomp install failed: " << std::strerror(errno) << "\n";
  }
}

void DenyBindFamily(bool strict) {
  int nrs[12];
  size_t n = 0;
  nrs[n++] = SYS_bind;
  nrs[n++] = SYS_listen;
  nrs[n++] = SYS_accept;
#  ifdef SYS_accept4
  nrs[n++] = SYS_accept4;
#  endif
  if (strict) {
    nrs[n++] = SYS_connect;
#  ifdef SYS_open
    nrs[n++] = SYS_open;
#  endif
    nrs[n++] = SYS_openat;
    nrs[n++] = SYS_execve;
#  ifdef SYS_execveat
    nrs[n++] = SYS_execveat;
#  endif
#  ifdef SYS_ptrace
    nrs[n++] = SYS_ptrace;
#  endif
#  ifdef SYS_process_vm_writev
    nrs[n++] = SYS_process_vm_writev;
#  endif
  }
  InstallSeccompDeny(nrs, n);
}

void TryLandlock() {
#  if defined(LANDLOCK_ACCESS_FS_READ_FILE) && defined(SYS_landlock_create_ruleset)
  int abi = static_cast<int>(::syscall(SYS_landlock_create_ruleset, nullptr, 0,
                                       LANDLOCK_CREATE_RULESET_VERSION));
  if (abi < 1) {
    std::cerr << "llama.SPY serve: landlock unavailable (" << std::strerror(errno) << ")\n";
    return;
  }
  landlock_ruleset_attr attr{};
  attr.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                           LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                           LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
                           LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
                           LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
                           LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                           LANDLOCK_ACCESS_FS_MAKE_SYM;
#    ifdef LANDLOCK_ACCESS_FS_REFER
  if (abi >= 2) attr.handled_access_fs |= LANDLOCK_ACCESS_FS_REFER;
#    endif
#    ifdef LANDLOCK_ACCESS_FS_TRUNCATE
  if (abi >= 3) attr.handled_access_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
#    endif
  int fd = static_cast<int>(::syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0));
  if (fd < 0) {
    std::cerr << "llama.SPY serve: landlock ruleset failed: " << std::strerror(errno) << "\n";
    return;
  }
  if (::syscall(SYS_landlock_restrict_self, fd, 0) != 0) {
    std::cerr << "llama.SPY serve: landlock restrict failed: " << std::strerror(errno) << "\n";
  } else {
    std::cerr << "llama.SPY serve: landlock (no filesystem access)\n";
  }
  ::close(fd);
#  endif
}

void DenyServeSyscalls() {
  int nrs[12];
  size_t n = 0;
  nrs[n++] = SYS_bind;
  nrs[n++] = SYS_listen;
  nrs[n++] = SYS_connect;
  nrs[n++] = SYS_execve;
#  ifdef SYS_execveat
  nrs[n++] = SYS_execveat;
#  endif
#  ifdef SYS_ptrace
  nrs[n++] = SYS_ptrace;
#  endif
#  ifdef SYS_process_vm_readv
  nrs[n++] = SYS_process_vm_readv;
#  endif
#  ifdef SYS_process_vm_writev
  nrs[n++] = SYS_process_vm_writev;
#  endif
  InstallSeccompDeny(nrs, n);
}
#endif  // __linux__

#if defined(__FreeBSD__) || defined(LLAMASPY_FREEBSD)
void CapLimit(int fd, cap_rights_t* rights) {
  if (fd >= 0) ::cap_rights_limit(fd, rights);
}

void CapsicumServe(int ipc, int listen_fd) {
  cap_rights_t r;
  cap_rights_init(&r, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_FCNTL, CAP_FSTAT);
  CapLimit(STDIN_FILENO, &r);
  CapLimit(STDOUT_FILENO, &r);
  CapLimit(STDERR_FILENO, &r);
  cap_rights_init(&r, CAP_RECV, CAP_READ, CAP_EVENT, CAP_FCNTL);
  CapLimit(ipc, &r);
  cap_rights_init(&r, CAP_ACCEPT, CAP_READ, CAP_WRITE, CAP_EVENT, CAP_SETSOCKOPT,
                  CAP_GETSOCKOPT, CAP_SHUTDOWN, CAP_FCNTL, CAP_FSTAT);
  CapLimit(listen_fd, &r);
  if (::cap_enter() != 0) {
    std::cerr << "llama.SPY serve: cap_enter failed: " << std::strerror(errno) << "\n";
    _exit(1);
  }
  std::cerr << "llama.SPY serve: cap_enter\n";
}

void CapsicumCollector(int ipc, bool strict) {
  cap_rights_t r;
  cap_rights_init(&r, CAP_READ, CAP_WRITE, CAP_SEEK, CAP_FSTAT, CAP_FCNTL, CAP_EVENT, CAP_SEND,
                  CAP_RECV);
  long max = ::sysconf(_SC_OPEN_MAX);
  if (max < 0 || max > 256) max = 256;
  for (int fd = 0; fd < static_cast<int>(max); ++fd) {
    if (::fcntl(fd, F_GETFD) < 0) continue;
    CapLimit(fd, &r);
  }
  (void)ipc;
  if (!strict) {
    std::cerr << "llama.SPY collector: capsicum rights limited; cap_enter skipped "
                 "for http/log (needs open/connect)\n";
    return;
  }
  if (::cap_enter() != 0) {
    std::cerr << "llama.SPY collector: cap_enter failed: " << std::strerror(errno) << "\n";
    _exit(1);
  }
  std::cerr << "llama.SPY collector: cap_enter\n";
}
#endif

void DropToNobody() {
  if (::geteuid() != 0) {
    std::cerr << "llama.SPY serve: not root, staying uid " << ::getuid() << "\n";
    return;
  }
  struct passwd* pw = ::getpwnam("nobody");
  if (!pw) {
    std::cerr << "llama.SPY serve: user nobody not found; refusing to listen as root\n";
    _exit(1);
  }
  if (::setgroups(0, nullptr) != 0) {
    std::cerr << "llama.SPY serve: setgroups failed: " << std::strerror(errno) << "\n";
    _exit(1);
  }
  if (::setgid(pw->pw_gid) != 0 || ::setuid(pw->pw_uid) != 0) {
    std::cerr << "llama.SPY serve: drop to nobody failed: " << std::strerror(errno) << "\n";
    _exit(1);
  }
  std::cerr << "llama.SPY serve: dropped to nobody\n";
}

int BindLoopback(const ListenSpec& spec, std::string* err) {
  const bool v6 = spec.ipv6;
  int fd = ::socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    if (err) *err = std::string("socket: ") + std::strerror(errno);
    return -1;
  }
  int yes = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  if (!v6) {
    std::string host = (spec.host == "localhost") ? "127.0.0.1" : spec.host;
    sockaddr_in in{};
    in.sin_family = AF_INET;
    in.sin_port = htons(static_cast<uint16_t>(spec.port));
    if (::inet_pton(AF_INET, host.c_str(), &in.sin_addr) != 1 ||
        in.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
      if (err) *err = "listen address is not 127.0.0.1";
      ::close(fd);
      return -1;
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&in), sizeof(in)) != 0) {
      if (err) *err = std::string("bind: ") + std::strerror(errno);
      ::close(fd);
      return -1;
    }
  } else {
    sockaddr_in6 in6{};
    in6.sin6_family = AF_INET6;
    in6.sin6_port = htons(static_cast<uint16_t>(spec.port));
    if (::inet_pton(AF_INET6, spec.host.c_str(), &in6.sin6_addr) != 1 ||
        !IN6_IS_ADDR_LOOPBACK(&in6.sin6_addr)) {
      if (err) *err = "listen address is not ::1";
      ::close(fd);
      return -1;
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&in6), sizeof(in6)) != 0) {
      if (err) *err = std::string("bind: ") + std::strerror(errno);
      ::close(fd);
      return -1;
    }
  }
  if (::listen(fd, 16) != 0) {
    if (err) *err = std::string("listen: ") + std::strerror(errno);
    ::close(fd);
    return -1;
  }
  return fd;
}

void PrintBound(int fd) {
  sockaddr_storage ss{};
  socklen_t sl = sizeof(ss);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&ss), &sl) != 0) return;
  char host[128];
  int port = 0;
  if (ss.ss_family == AF_INET) {
    auto* in = reinterpret_cast<sockaddr_in*>(&ss);
    if (!::inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host))) return;
    port = ntohs(in->sin_port);
  } else if (ss.ss_family == AF_INET6) {
    auto* in6 = reinterpret_cast<sockaddr_in6*>(&ss);
    if (!::inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host))) return;
    port = ntohs(in6->sin6_port);
  } else {
    return;
  }
  std::cerr << "llama.SPY serve listening on " << host << ":" << port
            << " (API key required)\n";
}

std::string HeaderValue(const std::string& req, const std::string& name) {
  std::string want = Lower(name);
  size_t pos = 0;
  while (pos < req.size()) {
    size_t eol = req.find("\r\n", pos);
    if (eol == std::string::npos) eol = req.size();
    std::string line = req.substr(pos, eol - pos);
    pos = eol + 2;
    if (line.empty()) break;
    auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    if (Lower(Trim(line.substr(0, colon))) == want) return Trim(line.substr(colon + 1));
  }
  return {};
}

bool Authorized(const std::string& req, const std::string& key) {
  std::string got;
  std::string auth = HeaderValue(req, "authorization");
  std::string auth_l = Lower(auth);
  const std::string prefix = "bearer ";
  if (auth_l.compare(0, prefix.size(), prefix) == 0) got = Trim(auth.substr(prefix.size()));
  else got = HeaderValue(req, "x-api-key");
  return ConstTimeEqual(got, key);
}

void SendAll(int fd, const std::string& s) {
  size_t off = 0;
  while (off < s.size()) {
    ssize_t n = ::send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR) continue;
      return;
    }
    if (n == 0) return;
    off += static_cast<size_t>(n);
  }
}

void SendResponse(int fd, int code, const char* reason, const std::string& body,
                  const char* type, bool auth_fail) {
  std::ostringstream o;
  o << "HTTP/1.0 " << code << " " << reason << "\r\n"
    << "Content-Type: " << type << "\r\n"
    << "Content-Length: " << body.size() << "\r\n"
    << "Connection: close\r\n"
    << "Cache-Control: no-store\r\n";
  if (auth_fail) o << "WWW-Authenticate: Bearer\r\n";
  o << "\r\n" << body;
  SendAll(fd, o.str());
}

std::string MetricsText(const SnoopV1Frame* frame) {
  SnoopV1Frame z{};
  const SnoopV1Frame& f = frame ? *frame : z;
  std::ostringstream o;
  o.setf(std::ios::fixed);
  o.precision(6);
  o << "# llama.SPY SnoopV1\n";
  if (!frame) o << "# no frame yet\n";
  o << "llamacpp:predicted_tokens_seconds " << f.predicted_tok_s << "\n";
  o << "llamacpp:prompt_tokens_seconds " << f.prompt_tok_s << "\n";
  o << "llamacpp:requests_processing " << f.requests_processing << "\n";
  o << "llamacpp:requests_deferred " << f.requests_deferred << "\n";
  o << "llamacpp:n_decode_total " << f.decode_count << "\n";
  double avg = 0;
  if (f.decode_latency_n > 0) {
    avg = static_cast<double>(f.decode_latency_ns_sum) / static_cast<double>(f.decode_latency_n);
  }
  o << "llamaspy:decode_latency_ns_avg " << avg << "\n";
  o << "llamaspy:pid " << f.pid << "\n";
  return o.str();
}

void HandleClient(int fd, const std::string& key, const SnoopV1Frame* frame) {
  timeval tv{};
  tv.tv_sec = 2;
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  std::string raw;
  char buf[1024];
  while (raw.size() < 8192 && raw.find("\r\n\r\n") == std::string::npos) {
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (n == 0) break;
    raw.append(buf, static_cast<size_t>(n));
  }
  if (raw.find("\r\n\r\n") == std::string::npos) {
    SendResponse(fd, 400, "Bad Request", "bad request\n", "text/plain", false);
    return;
  }
  if (!Authorized(raw, key)) {
    SendResponse(fd, 401, "Unauthorized", "unauthorized\n", "text/plain", true);
    return;
  }
  std::string line = raw.substr(0, raw.find("\r\n"));
  if (line.compare(0, 4, "GET ") != 0) {
    SendResponse(fd, 405, "Method Not Allowed", "method not allowed\n", "text/plain", false);
    return;
  }
  std::string rest = line.substr(4);
  auto sp = rest.find(' ');
  std::string path = sp == std::string::npos ? rest : rest.substr(0, sp);
  auto q = path.find('?');
  if (q != std::string::npos) path = path.substr(0, q);
  if (path == "/health") {
    SendResponse(fd, 200, "OK", "ok\n", "text/plain", false);
  } else if (path == "/metrics" || path == "/") {
    SendResponse(fd, 200, "OK", MetricsText(frame), "text/plain; version=0.0.4", false);
  } else {
    SendResponse(fd, 404, "Not Found", "not found\n", "text/plain", false);
  }
}

bool Admit(const uint8_t* buf, SnoopV1Frame* out) {
  SnoopV1Frame wire{};
  std::memcpy(&wire, buf, sizeof(wire));
  SnoopV1Frame host = snoop_ntoh(wire);
  if (host.magic != kSnoopMagic || host.version != kSnoopVersion) return false;
  *out = host;
  return true;
}

int ServeChild(int ipc, const ServeConfig& cfg) {
  std::string berr;
  int lfd = BindLoopback(cfg.listen, &berr);
  if (lfd < 0) {
    std::cerr << "llama.SPY serve: " << berr << "\n";
    return 1;
  }
  PrintBound(lfd);
  std::cerr << "llama.SPY serve pid=" << ::getpid() << "\n";
  DropToNobody();
#if defined(__linux__)
  TryLandlock();
  DenyServeSyscalls();
#endif
#if defined(__FreeBSD__) || defined(LLAMASPY_FREEBSD)
  CapsicumServe(ipc, lfd);
#endif

  int so_type = 0;
  socklen_t tl = sizeof(so_type);
  ::getsockopt(ipc, SOL_SOCKET, SO_TYPE, &so_type, &tl);
  const bool seq = so_type == SOCK_SEQPACKET;

  SnoopV1Frame latest{};
  bool have = false;
  std::string acc;
  for (;;) {
    pollfd pf[2];
    pf[0].fd = ipc;
    pf[0].events = POLLIN;
    pf[0].revents = 0;
    pf[1].fd = lfd;
    pf[1].events = POLLIN;
    pf[1].revents = 0;
    int pr = ::poll(pf, 2, 1000);
    if (pr < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (pf[0].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) {
      if (seq) {
        uint8_t buf[64];
        ssize_t n = ::recv(ipc, buf, sizeof(buf), 0);
        if (n == 0) break;
        if (n < 0) {
          if (errno == EINTR) continue;
          break;
        }
        if (n == 64 && Admit(buf, &latest)) have = true;
      } else {
        char buf[256];
        ssize_t n = ::recv(ipc, buf, sizeof(buf), 0);
        if (n == 0) break;
        if (n < 0) {
          if (errno == EINTR) continue;
          break;
        }
        acc.append(buf, static_cast<size_t>(n));
        while (acc.size() >= sizeof(SnoopV1Frame)) {
          if (Admit(reinterpret_cast<const uint8_t*>(acc.data()), &latest)) have = true;
          acc.erase(0, sizeof(SnoopV1Frame));
        }
      }
      if ((pf[0].revents & (POLLHUP | POLLERR | POLLNVAL)) && !(pf[0].revents & POLLIN)) break;
    }
    if (pf[1].revents & POLLIN) {
      int c = ::accept(lfd, nullptr, nullptr);
      if (c >= 0) {
        HandleClient(c, cfg.api_key, have ? &latest : nullptr);
        ::close(c);
      }
    }
  }
  ::close(lfd);
  ::close(ipc);
  return 0;
}

pid_t g_coll = -1;
pid_t g_serve_pid = -1;
volatile sig_atomic_t g_stop = 0;

void OnStop(int) {
  g_stop = 1;
  if (g_coll > 0) ::kill(g_coll, SIGTERM);
  if (g_serve_pid > 0) ::kill(g_serve_pid, SIGTERM);
}

int ChildStatus(int st) {
  if (WIFEXITED(st)) return WEXITSTATUS(st);
  if (WIFSIGNALED(st)) {
    int sig = WTERMSIG(st);
    if (sig == SIGTERM || sig == SIGINT) return 0;
  }
  return 1;
}

int Reap(pid_t coll, pid_t serve) {
  g_coll = coll;
  g_serve_pid = serve;
  struct sigaction sa {};
  sa.sa_handler = OnStop;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  ::sigaction(SIGINT, &sa, nullptr);
  ::sigaction(SIGTERM, &sa, nullptr);

  bool got_c = false;
  bool got_s = false;
  int code_c = 0;
  int code_s = 0;
  while (!got_c || !got_s) {
    int st = 0;
    pid_t p = ::waitpid(-1, &st, 0);
    if (p < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (p == coll) {
      got_c = true;
      code_c = ChildStatus(st);
      if (!got_s) ::kill(serve, SIGTERM);
    } else if (p == serve) {
      got_s = true;
      code_s = ChildStatus(st);
      if (!got_c) ::kill(coll, SIGTERM);
    }
  }
  if (!got_c) {
    ::kill(coll, SIGKILL);
    ::waitpid(coll, nullptr, 0);
  }
  if (!got_s) {
    ::kill(serve, SIGKILL);
    ::waitpid(serve, nullptr, 0);
  }
  if (g_stop) return 0;
  if (code_s != 0) return code_s;
  return code_c;
}

}  // namespace

ListenSpec ParseListenSpec(std::string_view text) {
  ListenSpec s;
  std::string t = Trim(std::string(text));
  if (t.empty()) {
    s.host = "127.0.0.1";
    s.port = 9100;
    s.ok = true;
    return s;
  }
  if (t.front() == '[') {
    auto rb = t.find(']');
    if (rb == std::string::npos || rb + 1 >= t.size() || t[rb + 1] != ':') {
      s.error = "ipv6 listen spec must look like [::1]:port";
      return s;
    }
    s.host = t.substr(1, rb - 1);
    s.ipv6 = true;
    s.port = std::atoi(t.c_str() + rb + 2);
  } else if (t.find(':') != t.rfind(':')) {
    s.error = "ipv6 listen spec must look like [::1]:port";
    return s;
  } else {
    auto colon = t.rfind(':');
    if (colon == std::string::npos) {
      s.host = "127.0.0.1";
      s.port = std::atoi(t.c_str());
    } else {
      s.host = t.substr(0, colon);
      if (s.host.empty()) {
        s.error = "empty host is not loopback; use 127.0.0.1:9100";
        return s;
      }
      s.port = std::atoi(t.c_str() + colon + 1);
    }
  }
  if (s.port < 0 || s.port > 65535) {
    s.error = "listen port out of range";
    return s;
  }
  s.ok = true;
  return s;
}

std::string ListenerPolicyError(const ListenSpec& spec, const std::string& api_key) {
  std::ostringstream o;
  if (!spec.ok) {
    o << (spec.error.empty() ? "invalid listen address" : spec.error) << "\n";
  } else {
    std::string host = Lower(spec.host);
    const bool loop = host == "127.0.0.1" || host == "localhost" || host == "::1";
    if (!loop) {
      o << "refusing to listen on " << spec.host << ":" << spec.port
        << ": non-loopback bind is not allowed (docs/PRIVSEP.md LS1). "
        << "Bind 127.0.0.1 (the default). ";
      if (host == "0.0.0.0" || host == "::" || host == "*" || host == "[::]") {
        o << "Refusing 0.0.0.0 / wildcard even when an API key is set; "
          << "a key does not lift the loopback-only rule. ";
      }
      o << "\n";
    }
  }
  std::string key = api_key;
  bool blank = true;
  for (char c : key) {
    if (c != ' ' && c != '\t') blank = false;
  }
  if (blank) {
    o << "refusing to listen: network listeners require an API key "
         "(--api-key or --api-key-file). "
         "This applies to every listener, including 127.0.0.1. "
         "0.0.0.0 without a key is refused.\n";
  } else if (key.find('\n') != std::string::npos || key.find('\r') != std::string::npos ||
             key.size() > 256) {
    o << "API key must be a single line of at most 256 bytes\n";
  }
  return o.str();
}

std::string ReadApiKeyFile(const std::string& path, std::string* err) {
  std::ifstream in(path);
  if (!in) {
    if (err) *err = "cannot open API key file: " + path;
    return {};
  }
  std::string line;
  if (!std::getline(in, line)) {
    if (err) *err = "API key file is empty: " + path;
    return {};
  }
  if (!line.empty() && line.back() == '\r') line.pop_back();
  line = Trim(line);
  if (line.empty()) {
    if (err) *err = "API key file is empty: " + path;
    return {};
  }
  struct stat st {};
  if (::stat(path.c_str(), &st) == 0 && (st.st_mode & (S_IRWXG | S_IRWXO))) {
    std::cerr << "llama.SPY: warning: API key file is readable by group or other: " << path
              << "\n";
  }
  return line;
}

void SandboxCollector(int ipc_fd, bool strict) {
  (void)ipc_fd;
#if defined(__linux__)
  DenyBindFamily(strict);
  if (strict) {
    std::cerr << "llama.SPY collector: seccomp denies bind/listen/accept/connect/open\n";
  } else {
    std::cerr << "llama.SPY collector: seccomp denies bind/listen/accept\n";
  }
#elif defined(__FreeBSD__) || defined(LLAMASPY_FREEBSD)
  CapsicumCollector(ipc_fd, strict);
#else
  (void)strict;
  std::cerr << "llama.SPY collector: no sandbox primitive on this OS "
               "(collector still does not bind)\n";
#endif
}

int RunPrivsepServe(const ServeConfig& cfg, const std::function<int(int ipc_fd)>& collector) {
  std::string policy = ListenerPolicyError(cfg.listen, cfg.api_key);
  if (!policy.empty()) {
    std::cerr << "llama.SPY: " << policy;
    return 2;
  }
  ::signal(SIGPIPE, SIG_IGN);
  int sv[2] = {-1, -1};
  if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) != 0) {
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) {
      std::cerr << "llama.SPY: socketpair failed: " << std::strerror(errno) << "\n";
      return 1;
    }
  }
  std::fflush(nullptr);
  pid_t coll = ::fork();
  if (coll < 0) {
    std::cerr << "llama.SPY: fork collector failed\n";
    ::close(sv[0]);
    ::close(sv[1]);
    return 1;
  }
  if (coll == 0) {
    ::close(sv[1]);
    ::signal(SIGPIPE, SIG_IGN);
#if defined(__linux__)
    ::prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
    ScrubFds(sv[0]);
    std::cerr << "llama.SPY collector running pid=" << ::getpid() << " (no network listen)\n";
    int rc = 1;
    try {
      rc = collector(sv[0]);
    } catch (...) {
      rc = 1;
    }
    _exit(rc);
  }
  pid_t serve = ::fork();
  if (serve < 0) {
    ::kill(coll, SIGTERM);
    ::waitpid(coll, nullptr, 0);
    ::close(sv[0]);
    ::close(sv[1]);
    std::cerr << "llama.SPY: fork serve failed\n";
    return 1;
  }
  if (serve == 0) {
    ::close(sv[0]);
    ::signal(SIGPIPE, SIG_IGN);
#if defined(__linux__)
    ::prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
    ScrubFds(sv[1]);
    int rc = ServeChild(sv[1], cfg);
    _exit(rc);
  }
  ::close(sv[0]);
  ::close(sv[1]);
  std::cerr << "llama.SPY parent reaper pid=" << ::getpid() << " collector=" << coll
            << " serve=" << serve << "\n";
  return Reap(coll, serve);
}

}  // namespace llamaspy
