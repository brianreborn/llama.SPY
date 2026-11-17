#include "llamaspy/mem_read.hpp"

#include <atomic>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/uio.h>
extern "C" ssize_t process_vm_readv(pid_t pid, const struct iovec* local_iov,
                                     unsigned long liovcnt,
                                     const struct iovec* remote_iov,
                                     unsigned long riovcnt, unsigned long flags);
#endif

#if defined(__FreeBSD__) || defined(LLAMASPY_FREEBSD)
#  include <sys/ptrace.h>
#  include <sys/wait.h>
#endif

namespace llamaspy {
namespace {

std::string ErrnoText() {
  return std::strerror(errno);
}

std::string Trim(std::string s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
  return s;
}

std::string ToLower(std::string s) {
  for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

bool ParseHex(std::string_view s, uint64_t* out) {
  if (s.empty() || !out) return false;
  if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.remove_prefix(2);
  if (s.empty()) return false;
  uint64_t v = 0;
  for (char c : s) {
    int d;
    if (c >= '0' && c <= '9') d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else return false;
    if (v > (UINT64_MAX >> 4)) return false;
    v = (v << 4) | static_cast<uint64_t>(d);
  }
  *out = v;
  return true;
}

std::string HexEncode(const uint8_t* p, size_t n) {
  static const char* k = "0123456789abcdef";
  std::string o;
  o.resize(n * 2);
  for (size_t i = 0; i < n; ++i) {
    o[i * 2] = k[p[i] >> 4];
    o[i * 2 + 1] = k[p[i] & 0xf];
  }
  return o;
}

std::string JsonEscape(std::string_view s) {
  std::string o;
  o.reserve(s.size());
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') {
      o.push_back('\\');
      o.push_back(static_cast<char>(c));
    } else if (c == '\n') {
      o += "\\n";
    } else if (c < 0x20) {
      char b[8];
      std::snprintf(b, sizeof(b), "\\u%04x", c);
      o += b;
    } else {
      o.push_back(static_cast<char>(c));
    }
  }
  return o;
}

// --- ELF --------------------------------------------------------------------

constexpr uint8_t kElfMag0 = 0x7f;
constexpr int kElfClass64 = 2;
constexpr int kElfData2Lsb = 1;
constexpr int kElfData2Msb = 2;
constexpr uint32_t kPtLoad = 1;
constexpr uint32_t kPtNote = 4;
constexpr uint32_t kShtSymtab = 2;
constexpr uint32_t kShtDynsym = 11;
constexpr uint32_t kNtGnuBuildId = 3;
constexpr uint16_t kShnUndef = 0;
constexpr uint16_t kShnAbs = 0xfff1;

struct ElfLoad {
  uint64_t vaddr = 0;
  uint64_t offset = 0;
  uint64_t filesz = 0;
};

struct ElfSym {
  std::string name;
  uint64_t value = 0;
  uint16_t shndx = 0;
  uint8_t bind = 0;
};

struct ElfView {
  bool ok = false;
  std::string error;
  bool be = false;
  std::string build_id;  // lowercase hex
  std::vector<ElfLoad> loads;
  std::vector<ElfSym> syms;
};

class FdReader {
 public:
  explicit FdReader(const std::string& path) {
    fd_ = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  }
  FdReader(const FdReader&) = delete;
  FdReader& operator=(const FdReader&) = delete;
  FdReader(FdReader&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
  FdReader& operator=(FdReader&& o) noexcept {
    if (this != &o) {
      if (fd_ >= 0) ::close(fd_);
      fd_ = o.fd_;
      o.fd_ = -1;
    }
    return *this;
  }
  ~FdReader() {
    if (fd_ >= 0) ::close(fd_);
  }
  bool ok() const { return fd_ >= 0; }
  bool Read(uint64_t off, void* buf, size_t n) const {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t got = 0;
    while (got < n) {
      ssize_t r = ::pread(fd_, p + got, n - got, static_cast<off_t>(off + got));
      if (r < 0) {
        if (errno == EINTR) continue;
        return false;
      }
      if (r == 0) return false;
      got += static_cast<size_t>(r);
    }
    return true;
  }

 private:
  int fd_ = -1;
};

uint16_t U16(const uint8_t* p, bool file_be) {
  if (file_be) return static_cast<uint16_t>((p[0] << 8) | p[1]);
  return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t U32(const uint8_t* p, bool file_be) {
  if (file_be) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
  }
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t U64(const uint8_t* p, bool file_be) {
  if (file_be) return (static_cast<uint64_t>(U32(p, true)) << 32) | U32(p + 4, true);
  return static_cast<uint64_t>(U32(p, false)) | (static_cast<uint64_t>(U32(p + 4, false)) << 32);
}

uint32_t Align4(uint32_t n) { return (n + 3u) & ~3u; }

void ParseNotes(const uint8_t* buf, size_t n, bool file_be, std::string* build_id) {
  size_t off = 0;
  while (off + 12 <= n) {
    uint32_t namesz = U32(buf + off, file_be);
    uint32_t descsz = U32(buf + off + 4, file_be);
    uint32_t type = U32(buf + off + 8, file_be);
    off += 12;
    if (namesz > n || descsz > n || off + namesz > n) break;
    std::string name(reinterpret_cast<const char*>(buf + off),
                     namesz ? static_cast<size_t>(namesz - 1) : 0);
    off += Align4(namesz);
    if (off + descsz > n) break;
    if (type == kNtGnuBuildId && name == "GNU" && descsz > 0 && build_id->empty()) {
      *build_id = HexEncode(buf + off, descsz);
    }
    off += Align4(descsz);
  }
}

ElfView ParseElf(const FdReader& rd) {
  ElfView ev;
  uint8_t eh[64];
  if (!rd.Read(0, eh, sizeof(eh))) {
    ev.error = "short ELF header";
    return ev;
  }
  if (eh[0] != kElfMag0 || eh[1] != 'E' || eh[2] != 'L' || eh[3] != 'F') {
    ev.error = "not an ELF file";
    return ev;
  }
  if (eh[4] != kElfClass64) {
    ev.error = "only ELF64 targets are supported";
    return ev;
  }
  if (eh[5] == kElfData2Lsb) ev.be = false;
  else if (eh[5] == kElfData2Msb) ev.be = true;
  else {
    ev.error = "unknown ELF endian";
    return ev;
  }
  const bool be = ev.be;
  const uint64_t phoff = U64(eh + 32, be);
  const uint16_t phentsize = U16(eh + 54, be);
  uint16_t phnum = U16(eh + 56, be);
  const uint64_t shoff = U64(eh + 40, be);
  const uint16_t shentsize = U16(eh + 58, be);
  uint16_t shnum = U16(eh + 60, be);
  if (phentsize < 56 || phnum > 512) {
    ev.error = "unreasonable program headers";
    return ev;
  }
  std::vector<uint8_t> ph(static_cast<size_t>(phentsize) * phnum);
  if (phnum > 0 && !rd.Read(phoff, ph.data(), ph.size())) {
    ev.error = "cannot read program headers";
    return ev;
  }
  for (uint16_t i = 0; i < phnum; ++i) {
    const uint8_t* p = ph.data() + static_cast<size_t>(i) * phentsize;
    uint32_t type = U32(p, be);
    uint64_t offset = U64(p + 8, be);
    uint64_t vaddr = U64(p + 16, be);
    uint64_t filesz = U64(p + 32, be);
    if (type == kPtLoad) {
      ElfLoad ld;
      ld.vaddr = vaddr;
      ld.offset = offset;
      ld.filesz = filesz;
      ev.loads.push_back(ld);
    } else if (type == kPtNote && filesz > 0 && filesz < (1u << 20)) {
      std::vector<uint8_t> note(static_cast<size_t>(filesz));
      if (rd.Read(offset, note.data(), note.size())) {
        ParseNotes(note.data(), note.size(), be, &ev.build_id);
      }
    }
  }
  if (shentsize < 64 || shnum > 10000 || shoff == 0) {
    ev.ok = true;
    return ev;
  }
  if (shnum == 0) {
    uint8_t sh0[64];
    if (rd.Read(shoff, sh0, 64)) shnum = static_cast<uint16_t>(U64(sh0 + 32, be));
  }
  if (shnum == 0 || shnum > 10000) {
    ev.ok = true;
    return ev;
  }
  std::vector<uint8_t> sh(static_cast<size_t>(shentsize) * shnum);
  if (!rd.Read(shoff, sh.data(), sh.size())) {
    ev.ok = true;
    return ev;
  }
  auto sh_at = [&](uint16_t i) -> const uint8_t* {
    return sh.data() + static_cast<size_t>(i) * shentsize;
  };
  for (int pass = 0; pass < 2; ++pass) {
    const uint32_t want = pass == 0 ? kShtDynsym : kShtSymtab;
    for (uint16_t i = 0; i < shnum; ++i) {
      const uint8_t* s = sh_at(i);
      uint32_t type = U32(s + 4, be);
      if (type != want) continue;
      uint64_t soff = U64(s + 24, be);
      uint64_t ssize = U64(s + 32, be);
      uint32_t link = U32(s + 40, be);
      if (link >= shnum || ssize > (64ull << 20) || ssize < 24) continue;
      const uint8_t* strh = sh_at(static_cast<uint16_t>(link));
      uint64_t stroff = U64(strh + 24, be);
      uint64_t strsz = U64(strh + 32, be);
      if (strsz > (32ull << 20)) continue;
      std::vector<uint8_t> strtab(static_cast<size_t>(strsz));
      std::vector<uint8_t> syms(static_cast<size_t>(ssize));
      if (!rd.Read(stroff, strtab.data(), strtab.size())) continue;
      if (!rd.Read(soff, syms.data(), syms.size())) continue;
      const size_t nsym = syms.size() / 24;
      for (size_t si = 0; si < nsym; ++si) {
        const uint8_t* sy = syms.data() + si * 24;
        uint32_t name_off = U32(sy, be);
        uint8_t info = sy[4];
        uint16_t shndx = U16(sy + 6, be);
        uint64_t value = U64(sy + 8, be);
        if (shndx == kShnUndef) continue;
        if (name_off >= strtab.size()) continue;
        const char* nm = reinterpret_cast<const char*>(strtab.data() + name_off);
        size_t maxn = strtab.size() - name_off;
        size_t len = 0;
        while (len < maxn && nm[len] != '\0') ++len;
        if (len == 0) continue;
        ElfSym es;
        es.name.assign(nm, len);
        es.value = value;
        es.shndx = shndx;
        es.bind = static_cast<uint8_t>(info >> 4);
        ev.syms.push_back(std::move(es));
      }
    }
  }
  ev.ok = true;
  return ev;
}

const ElfSym* FindSym(const ElfView& ev, const std::string& name) {
  const ElfSym* local = nullptr;
  for (const auto& s : ev.syms) {
    if (s.name != name) continue;
    if (s.bind == 1) return &s;  // STB_GLOBAL
    if (!local) local = &s;
  }
  return local;
}

// --- maps -------------------------------------------------------------------

std::string NormalizeModulePath(std::string path) {
  const std::string del = " (deleted)";
  if (path.size() >= del.size() && path.compare(path.size() - del.size(), del.size(), del) == 0) {
    path.erase(path.size() - del.size());
  }
  return path;
}

std::string PermissionAdvice(uint32_t pid) {
  std::ostringstream o;
  o << "Permission denied reading pid " << pid << ". "
    << "llama.SPY never writes to the target. ";
#if defined(__linux__)
  o << "Reads use process_vm_readv and, if that fails, /proc/" << pid
    << "/mem. Both require the same rights as ptrace attach. ";
  std::ifstream scope("/proc/sys/kernel/yama/ptrace_scope");
  int yama = -1;
  if (scope) scope >> yama;
  if (yama >= 0) {
    o << "kernel.yama.ptrace_scope=" << yama << ". ";
    if (yama == 0) {
      o << "Scope 0 is classic ptrace: same-uid reads should succeed. ";
    } else if (yama == 1) {
      o << "Scope 1 restricts same-uid reads to a parent of a dumpable "
           "target (or CAP_SYS_PTRACE / root). An unrelated process you "
           "own is still denied. ";
    } else if (yama == 2) {
      o << "Scope 2 allows only CAP_SYS_PTRACE (admin) attaches. ";
    } else if (yama == 3) {
      o << "Scope 3 denies every ptrace-style read, including same-uid. ";
    }
  } else {
    o << "yama ptrace_scope is not readable on this kernel. ";
  }
  std::ifstream st("/proc/" + std::to_string(pid) + "/status");
  std::string line;
  while (std::getline(st, line)) {
    if (line.compare(0, 4, "Uid:") == 0) {
      o << "target " << line << "; euid=" << ::geteuid() << ". ";
      break;
    }
  }
#else
  o << "Reads try /proc/" << pid << "/mem (procfs) then ptrace(PT_IO, PIOD_READ_D), "
    << "which briefly stops the target. A denial often means "
    << "security.bsd.unprivileged_proc_debug=0 or a different uid. ";
  o << "euid=" << ::geteuid() << ". ";
#endif
  o << "Own-process only: attach solely to a process you already control.";
  return o.str();
}

bool ProcExists(uint32_t pid) {
  std::string p = "/proc/" + std::to_string(pid);
  struct stat st {};
  return ::stat(p.c_str(), &st) == 0;
}

#if defined(__linux__)
bool ReadVm(uint32_t pid, uint64_t addr, void* buf, size_t n, std::string* err) {
  uint8_t* out = static_cast<uint8_t*>(buf);
  size_t got = 0;
  while (got < n) {
    iovec local {};
    local.iov_base = out + got;
    local.iov_len = n - got;
    iovec remote {};
    remote.iov_base = reinterpret_cast<void*>(static_cast<uintptr_t>(addr + got));
    remote.iov_len = n - got;
    ssize_t r = ::process_vm_readv(static_cast<pid_t>(pid), &local, 1, &remote, 1, 0);
    if (r < 0) {
      if (errno == EINTR) continue;
      if (err) {
        if (errno == EPERM || errno == EACCES) *err = PermissionAdvice(pid) + " (" + ErrnoText() + ")";
        else *err = std::string("process_vm_readv: ") + ErrnoText();
      }
      return false;
    }
    if (r == 0) {
      if (err) *err = "process_vm_readv: short read";
      return false;
    }
    got += static_cast<size_t>(r);
  }
  return true;
}
#endif

bool ReadProcMem(uint32_t pid, uint64_t addr, void* buf, size_t n, std::string* err) {
  std::string path = "/proc/" + std::to_string(pid) + "/mem";
  int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    if (err) {
      if (errno == EPERM || errno == EACCES) *err = PermissionAdvice(pid) + " (" + ErrnoText() + ")";
      else if (errno == ENOENT) *err = "cannot open " + path + " (procfs not mounted or no such process)";
      else *err = "open " + path + ": " + ErrnoText();
    }
    return false;
  }
  uint8_t* out = static_cast<uint8_t*>(buf);
  size_t got = 0;
  while (got < n) {
    ssize_t r = ::pread(fd, out + got, n - got, static_cast<off_t>(addr + got));
    if (r < 0) {
      if (errno == EINTR) continue;
      if (err) {
        if (errno == EPERM || errno == EACCES) *err = PermissionAdvice(pid) + " (" + ErrnoText() + ")";
        else *err = std::string("pread /proc/PID/mem: ") + ErrnoText();
      }
      ::close(fd);
      return false;
    }
    if (r == 0) {
      if (err) *err = "pread /proc/PID/mem: short read (address not mapped?)";
      ::close(fd);
      return false;
    }
    got += static_cast<size_t>(r);
  }
  ::close(fd);
  return true;
}

#if defined(__FreeBSD__) || defined(LLAMASPY_FREEBSD)
bool ReadPtrace(uint32_t pid, uint64_t addr, void* buf, size_t n, std::string* err) {
  if (::ptrace(PT_ATTACH, static_cast<pid_t>(pid), nullptr, 0) != 0) {
    if (err) {
      if (errno == EPERM || errno == EACCES) *err = PermissionAdvice(pid) + " (" + ErrnoText() + ")";
      else *err = std::string("ptrace PT_ATTACH: ") + ErrnoText();
    }
    return false;
  }
  int st = 0;
  ::waitpid(static_cast<pid_t>(pid), &st, 0);
  struct ptrace_io_desc iod {};
  iod.piod_op = PIOD_READ_D;
  iod.piod_offs = reinterpret_cast<void*>(static_cast<uintptr_t>(addr));
  iod.piod_addr = buf;
  iod.piod_len = n;
  bool ok = ::ptrace(PT_IO, static_cast<pid_t>(pid), reinterpret_cast<caddr_t>(&iod),
                     static_cast<int>(sizeof(iod))) == 0;
  if (!ok && err) {
    if (errno == EPERM || errno == EACCES) *err = PermissionAdvice(pid) + " (" + ErrnoText() + ")";
    else *err = std::string("ptrace PT_IO PIOD_READ_D: ") + ErrnoText();
  }
  // Always detach. data 0 continues the target with no signal.
  ::ptrace(PT_DETACH, static_cast<pid_t>(pid), reinterpret_cast<caddr_t>(1), 0);
  return ok;
}
#endif

std::vector<MapRange> MapsFromProc(uint32_t pid, std::string* err) {
  std::string path = "/proc/" + std::to_string(pid) + "/maps";
  std::ifstream in(path);
  if (!in) {
    if (err) *err = "cannot read " + path;
    return {};
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ParseLinuxMapsText(ss.str());
}

std::string CaptureCommand(const char* file, const char* const argv[]) {
  int fds[2];
  if (::pipe(fds) != 0) return {};
  pid_t c = ::fork();
  if (c < 0) {
    ::close(fds[0]);
    ::close(fds[1]);
    return {};
  }
  if (c == 0) {
    ::dup2(fds[1], STDOUT_FILENO);
    ::close(fds[0]);
    ::close(fds[1]);
    int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      ::dup2(devnull, STDERR_FILENO);
      ::close(devnull);
    }
    ::execvp(file, const_cast<char* const*>(argv));
    _exit(127);
  }
  ::close(fds[1]);
  std::string out;
  char buf[1024];
  for (;;) {
    ssize_t n = ::read(fds[0], buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (n == 0) break;
    out.append(buf, static_cast<size_t>(n));
  }
  ::close(fds[0]);
  int st = 0;
  ::waitpid(c, &st, 0);
  return out;
}

std::vector<MapRange> MapsForPid(uint32_t pid, std::string* err) {
#if defined(__linux__)
  auto m = MapsFromProc(pid, err);
  if (!m.empty()) return m;
#endif
  std::string procmap = "/proc/" + std::to_string(pid) + "/map";
  std::ifstream in(procmap);
  if (in) {
    std::ostringstream ss;
    ss << in.rdbuf();
    auto parsed = ParseProcstatVText(ss.str());
    if (!parsed.empty()) return parsed;
  }
  std::string ps = std::to_string(pid);
  const char* argv[] = {"procstat", "-v", ps.c_str(), nullptr};
  std::string text = CaptureCommand("procstat", argv);
  auto parsed = ParseProcstatVText(text);
  if (parsed.empty() && err) {
    *err = "cannot enumerate address space (no /proc/PID/maps and procstat -v failed)";
  }
  return parsed;
}

struct ModuleImage {
  std::string path;
  std::vector<MapRange> ranges;
  uint64_t lowest = 0;
  ElfView elf;
  uint64_t bias = 0;
  bool bias_ok = false;
};

uint64_t ComputeBias(const ModuleImage& m) {
  if (m.elf.loads.empty() || m.ranges.empty()) return 0;
  const ElfLoad* first = &m.elf.loads[0];
  for (const auto& ld : m.elf.loads) {
    if (ld.vaddr < first->vaddr) first = &ld;
  }
  for (const auto& r : m.ranges) {
    if (r.has_file_offset && r.file_offset == first->offset) {
      return r.start - first->vaddr;
    }
  }
  uint64_t low = m.ranges[0].start;
  for (const auto& r : m.ranges)
    if (r.start < low) low = r.start;
  return low - first->vaddr;
}

std::vector<ModuleImage> LoadModules(uint32_t pid, std::string* err) {
  auto ranges = MapsForPid(pid, err);
  std::vector<std::string> order;
  std::vector<std::vector<MapRange>> groups;
  for (const auto& r : ranges) {
    if (r.path.empty() || r.path[0] != '/') continue;
    std::string path = NormalizeModulePath(r.path);
    size_t idx = order.size();
    for (size_t i = 0; i < order.size(); ++i) {
      if (order[i] == path) {
        idx = i;
        break;
      }
    }
    if (idx == order.size()) {
      order.push_back(path);
      groups.emplace_back();
    }
    groups[idx].push_back(r);
  }
  // Prefer the live inode of the main executable when maps name a deleted path.
  char exe_buf[4096];
  std::string exe_link = "/proc/" + std::to_string(pid) + "/exe";
  ssize_t en = ::readlink(exe_link.c_str(), exe_buf, sizeof(exe_buf) - 1);
  std::string exe_path;
  if (en > 0) {
    exe_buf[en] = 0;
    exe_path = NormalizeModulePath(exe_buf);
  }
  std::vector<ModuleImage> mods;
  for (size_t i = 0; i < order.size(); ++i) {
    ModuleImage m;
    m.path = order[i];
    m.ranges = groups[i];
    m.lowest = m.ranges[0].start;
    for (const auto& r : m.ranges)
      if (r.start < m.lowest) m.lowest = r.start;
    std::string open_path = m.path;
    FdReader rd(open_path);
    if (!rd.ok() && !exe_path.empty()) {
      // Same basename fallback: try /proc/PID/exe for the main binary.
      if (m.path == exe_path || open_path == exe_path) {
        rd = FdReader(exe_link);
        open_path = exe_link;
      }
    }
    if (!rd.ok()) {
      rd = FdReader(exe_link);
      // only accept if this group is the executable
      if (m.path != exe_path) {
        continue;
      }
      open_path = exe_link;
    }
    m.elf = ParseElf(rd);
    if (!m.elf.ok) continue;
    m.bias = ComputeBias(m);
    m.bias_ok = !m.elf.loads.empty();
    mods.push_back(std::move(m));
  }
  return mods;
}

bool DecodeValue(const uint8_t* bytes, size_t n, GgValueType type, BindingRead* out) {
  auto need = [&](size_t w) { return n >= w; };
  switch (type) {
    case GgValueType::U8:
      if (!need(1)) return false;
      out->raw_bits = bytes[0];
      out->number = static_cast<double>(bytes[0]);
      return true;
    case GgValueType::U16: {
      if (!need(2)) return false;
      uint16_t v;
      std::memcpy(&v, bytes, 2);
      out->raw_bits = v;
      out->number = static_cast<double>(v);
      return true;
    }
    case GgValueType::U32: {
      if (!need(4)) return false;
      uint32_t v;
      std::memcpy(&v, bytes, 4);
      out->raw_bits = v;
      out->number = static_cast<double>(v);
      return true;
    }
    case GgValueType::U64: {
      if (!need(8)) return false;
      uint64_t v;
      std::memcpy(&v, bytes, 8);
      out->raw_bits = v;
      out->number = static_cast<double>(v);
      return true;
    }
    case GgValueType::I32: {
      if (!need(4)) return false;
      int32_t v;
      std::memcpy(&v, bytes, 4);
      out->raw_bits = static_cast<uint32_t>(v);
      out->number = static_cast<double>(v);
      return true;
    }
    case GgValueType::I64: {
      if (!need(8)) return false;
      int64_t v;
      std::memcpy(&v, bytes, 8);
      std::memcpy(&out->raw_bits, &v, 8);
      out->number = static_cast<double>(v);
      return true;
    }
    case GgValueType::F32: {
      if (!need(4)) return false;
      float v;
      std::memcpy(&v, bytes, 4);
      out->number = static_cast<double>(v);
      uint32_t bits;
      std::memcpy(&bits, bytes, 4);
      out->raw_bits = bits;
      return true;
    }
    case GgValueType::F64: {
      if (!need(8)) return false;
      double v;
      std::memcpy(&v, bytes, 8);
      out->number = v;
      std::memcpy(&out->raw_bits, bytes, 8);
      return true;
    }
    default:
      // Unknown type: still expose the raw bytes.
      if (n >= 8) std::memcpy(&out->raw_bits, bytes, 8);
      else std::memcpy(&out->raw_bits, bytes, n);
      out->number = 0;
      return true;
  }
}

}  // namespace

namespace {
std::atomic<uint32_t> g_pid{0};
const GgCodebook* g_book = nullptr;
}  // namespace

std::string GnuBuildIdFromFile(const std::string& path) {
  FdReader rd(path);
  if (!rd.ok()) return {};
  ElfView ev = ParseElf(rd);
  return ev.build_id;
}

bool FingerprintAccepts(const std::string& module_build_id_hex, const std::string& fp_field) {
  std::string fp = Trim(fp_field);
  if (fp.empty()) return true;
  std::string want = ToLower(fp);
  const std::string prefix = "buildid:";
  if (want.compare(0, prefix.size(), prefix) == 0) want = want.substr(prefix.size());
  std::string got = ToLower(module_build_id_hex);
  if (want.empty() || got.empty()) return false;
  return want == got;
}

std::vector<MapRange> ParseLinuxMapsText(std::string_view text) {
  std::vector<MapRange> out;
  size_t pos = 0;
  while (pos < text.size()) {
    size_t eol = text.find('\n', pos);
    std::string line(text.substr(pos, eol == std::string_view::npos ? text.size() - pos : eol - pos));
    pos = eol == std::string_view::npos ? text.size() : eol + 1;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::istringstream iss(line);
    std::string address, perms, offset, dev, inode;
    if (!(iss >> address >> perms >> offset >> dev >> inode)) continue;
    auto dash = address.find('-');
    if (dash == std::string::npos) continue;
    MapRange r;
    if (!ParseHex(address.substr(0, dash), &r.start)) continue;
    if (!ParseHex(address.substr(dash + 1), &r.end)) continue;
    r.perms = perms;
    if (ParseHex(offset, &r.file_offset)) r.has_file_offset = true;
    std::string path;
    std::getline(iss, path);
    path = Trim(path);
    if (!path.empty() && path[0] != '[') r.path = path;
    out.push_back(std::move(r));
  }
  return out;
}

std::vector<MapRange> ParseProcstatVText(std::string_view text) {
  std::vector<MapRange> out;
  size_t pos = 0;
  while (pos < text.size()) {
    size_t eol = text.find('\n', pos);
    std::string line(text.substr(pos, eol == std::string_view::npos ? text.size() - pos : eol - pos));
    pos = eol == std::string_view::npos ? text.size() : eol + 1;
    if (!line.empty() && line.back() == '\r') line.pop_back();
    std::istringstream iss(line);
    std::vector<std::string> tok;
    std::string t;
    while (iss >> t) tok.push_back(t);
    std::vector<uint64_t> addrs;
    std::string path;
    for (const auto& w : tok) {
      if (!w.empty() && w[0] == '/') {
        path = w;
        continue;
      }
      if (w.size() > 2 && w[0] == '0' && (w[1] == 'x' || w[1] == 'X')) {
        uint64_t v = 0;
        if (ParseHex(w, &v)) addrs.push_back(v);
      }
    }
    if (addrs.size() < 2 || path.empty()) continue;
    MapRange r;
    r.start = addrs[0];
    r.end = addrs[1];
    r.path = path;
    out.push_back(std::move(r));
  }
  return out;
}

bool ReadProcessBytes(uint32_t pid, uint64_t addr, void* buf, size_t n, std::string* err,
                      MemBackend backend) {
  if (pid == 0 || buf == nullptr || n == 0 || n > 64) {
    if (err) *err = "invalid read (pid, buffer, or length)";
    return false;
  }
  if (!ProcExists(pid)) {
    if (err) *err = "no such process: pid " + std::to_string(pid);
    errno = ESRCH;
    return false;
  }
  auto fail_perm = [&](const std::string& detail) {
    if (err) *err = detail;
    return false;
  };

#if defined(__linux__)
  if (backend == MemBackend::PtraceIo) {
    if (err) *err = "ptrace PT_IO is the FreeBSD backend; this host is Linux";
    return false;
  }
  if (backend == MemBackend::Auto || backend == MemBackend::ProcessVmReadv) {
    if (ReadVm(pid, addr, buf, n, err)) return true;
    if (backend == MemBackend::ProcessVmReadv) return false;
    int saved = errno;
    std::string first = err ? *err : "";
    if (saved == EPERM || saved == EACCES) return fail_perm(first);
    // Fall through to /proc/PID/mem for EIO / ENOSYS / other.
    std::string second;
    if (ReadProcMem(pid, addr, buf, n, &second)) return true;
    if (errno == EPERM || errno == EACCES) return fail_perm(second);
    if (err) *err = first.empty() ? second : first + "; fallback " + second;
    return false;
  }
  if (backend == MemBackend::ProcMem) return ReadProcMem(pid, addr, buf, n, err);
  if (err) *err = "unsupported mem backend";
  return false;
#elif defined(__FreeBSD__) || defined(LLAMASPY_FREEBSD)
  if (backend == MemBackend::ProcessVmReadv) {
    if (err) *err = "process_vm_readv is the Linux backend; this host is FreeBSD";
    return false;
  }
  if (backend == MemBackend::Auto || backend == MemBackend::ProcMem) {
    if (ReadProcMem(pid, addr, buf, n, err)) return true;
    if (backend == MemBackend::ProcMem) return false;
    if (errno == EPERM || errno == EACCES) return false;
  }
  if (backend == MemBackend::Auto || backend == MemBackend::PtraceIo) {
    return ReadPtrace(pid, addr, buf, n, err);
  }
  if (err) *err = "unsupported mem backend";
  return false;
#else
  (void)addr;
  (void)backend;
  if (err) *err = "no read-only mem backend on this OS";
  return false;
#endif
}

BindingRead ReadBinding(uint32_t pid, const GgBinding& binding, MemBackend backend) {
  BindingRead r;
  r.sym = binding.symbol;
  r.displacement = binding.offset;
  r.width = binding.width ? binding.width : DefaultWidth(binding.type);
  r.type = binding.type;
  if (r.width == 0 || r.width > 64) {
    r.status = MemStatus::BadBinding;
    r.error = "binding width must be 1..64";
    return r;
  }
  if (pid == 0) {
    r.status = MemStatus::NoPid;
    r.error = "no target pid; pass --pid to read the binding";
    return r;
  }
  if (!ProcExists(pid)) {
    r.status = MemStatus::NoSuchProcess;
    r.error = "no such process: pid " + std::to_string(pid);
    return r;
  }
  std::string map_err;
  auto mods = LoadModules(pid, &map_err);
  if (mods.empty()) {
    r.status = MemStatus::ReadError;
    r.error = map_err.empty() ? "no mapped ELF modules" : map_err;
    return r;
  }

  const bool constrained = !Trim(binding.build_fp).empty();
  std::vector<ModuleImage*> candidates;
  bool saw_any_id = false;
  for (auto& m : mods) {
    if (!m.elf.build_id.empty()) saw_any_id = true;
    if (FingerprintAccepts(m.elf.build_id, binding.build_fp)) candidates.push_back(&m);
  }
  if (constrained && candidates.empty()) {
    r.status = MemStatus::FingerprintMismatch;
    std::ostringstream o;
    o << "build fingerprint mismatch for sym=" << binding.symbol
      << " fp=" << binding.build_fp << ". Refusing to read. Running modules:";
    for (const auto& m : mods) {
      o << " " << m.path << "="
        << (m.elf.build_id.empty() ? "(no build-id)" : "buildid:" + m.elf.build_id);
    }
    if (!saw_any_id) o << " (no GNU build-id found; regenerate with scripts/gen-gg-offsets.sh)";
    r.error = o.str();
    return r;
  }
  if (!constrained) {
    candidates.clear();
    for (auto& m : mods) candidates.push_back(&m);
  }

  ModuleImage* chosen = nullptr;
  const ElfSym* sym = nullptr;
  for (auto* m : candidates) {
    const ElfSym* s = FindSym(m->elf, binding.symbol);
    if (s) {
      chosen = m;
      sym = s;
      // Prefer a global in the main executable (first match is fine; globals return immediately).
      if (s->bind == 1) break;
    }
  }

  uint64_t addr = 0;
  if (sym && chosen) {
    if (sym->shndx == kShnAbs) addr = sym->value + binding.offset;
    else addr = chosen->bias + sym->value + binding.offset;
    r.module_path = chosen->path;
    r.build_id = chosen->elf.build_id;
  } else if (binding.offset != 0 && candidates.size() == 1 && candidates[0]->bias_ok) {
    // Symbol is a label only. off is module-relative (load bias + off).
    chosen = candidates[0];
    addr = chosen->bias + binding.offset;
    r.module_path = chosen->path;
    r.build_id = chosen->elf.build_id;
  } else {
    r.status = MemStatus::SymbolNotFound;
    std::ostringstream o;
    o << "symbol '" << binding.symbol << "' not found";
    if (constrained) o << " in the module whose build-id matches " << binding.build_fp;
    o << ". off is a displacement from the symbol (0 = the symbol). "
      << "Generate lines with scripts/gen-gg-offsets.sh. Mapped ELFs:";
    for (const auto& m : mods) o << " " << m.path;
    r.error = o.str();
    return r;
  }
  r.address = addr;

  std::vector<uint8_t> bytes(r.width);
  std::string rerr;
  if (!ReadProcessBytes(pid, addr, bytes.data(), bytes.size(), &rerr, backend)) {
    if (rerr.find("Permission denied") != std::string::npos ||
        rerr.find("ptrace_scope") != std::string::npos) {
      r.status = MemStatus::PermissionDenied;
    } else if (rerr.find("no such process") != std::string::npos) {
      r.status = MemStatus::NoSuchProcess;
    } else if (rerr.find("no read-only") != std::string::npos ||
               rerr.find("not the") != std::string::npos) {
      r.status = MemStatus::Unsupported;
    } else {
      r.status = MemStatus::ReadError;
    }
    r.error = rerr.empty() ? "read failed" : rerr;
    return r;
  }
  r.hex = HexEncode(bytes.data(), bytes.size());
  if (!DecodeValue(bytes.data(), bytes.size(), binding.type, &r)) {
    r.status = MemStatus::ReadError;
    r.error = "decoded width does not match type";
    return r;
  }
  r.has_value = true;
  r.status = MemStatus::Ok;
  return r;
}

std::string BindingReadJson(const BindingRead& r) {
  std::ostringstream o;
  o << "{\"ok\":" << (r.status == MemStatus::Ok ? "true" : "false")
    << ",\"sym\":\"" << JsonEscape(r.sym) << "\""
    << ",\"offset\":" << r.displacement
    << ",\"width\":" << r.width
    << ",\"type\":\"" << GgValueTypeName(r.type) << "\""
    << ",\"declared\":true";
  if (!r.module_path.empty()) o << ",\"module\":\"" << JsonEscape(r.module_path) << "\"";
  if (!r.build_id.empty()) o << ",\"build_id\":\"" << JsonEscape(r.build_id) << "\"";
  if (r.address != 0 || r.status == MemStatus::Ok) {
    char abuf[32];
    std::snprintf(abuf, sizeof(abuf), "0x%llx", static_cast<unsigned long long>(r.address));
    o << ",\"address\":\"" << abuf << "\"";
  }
  if (r.has_value) {
    o << ",\"hex\":\"" << r.hex << "\"";
    const bool is_float = r.type == GgValueType::F32 || r.type == GgValueType::F64;
    if (is_float) {
      o << ",\"value\":" << r.number;
    } else if (r.type == GgValueType::I64) {
      int64_t s;
      std::memcpy(&s, &r.raw_bits, 8);
      o << ",\"value\":" << s;
    } else if (r.raw_bits <= 9007199254740991ULL) {
      o << ",\"value\":" << r.raw_bits;
    } else {
      o << ",\"value\":\"" << r.raw_bits << "\"";
    }
    o << ",\"error\":null";
  } else {
    o << ",\"value\":null,\"error\":\"" << JsonEscape(r.error) << "\"";
  }
  o << "}";
  return o.str();
}

void SetMemTargetPid(uint32_t pid) { g_pid.store(pid); }
uint32_t MemTargetPid() { return g_pid.load(); }
void SetMemCodebook(const GgCodebook* book) { g_book = book; }
const GgCodebook* MemCodebook() { return g_book; }

GgApplyStatus ApplyReadOnly(uint32_t pid, const GgCodebook& book, std::string* detail_out) {
  if (book.bindings.empty()) {
    if (detail_out) *detail_out = "no bindings to apply\n";
    return GgApplyStatus::Empty;
  }
  if (pid == 0) {
    if (detail_out) *detail_out = "pid required for mem read (got 0)\n";
    return GgApplyStatus::InvalidArg;
  }
  std::ostringstream o;
  o << "ApplyReadOnly pid=" << pid << " bindings=" << book.bindings.size() << "\n";
  GgApplyStatus worst = GgApplyStatus::Ok;
  auto rank = [](GgApplyStatus s) {
    switch (s) {
      case GgApplyStatus::PermissionDenied: return 5;
      case GgApplyStatus::FingerprintMismatch: return 4;
      case GgApplyStatus::NotImplemented: return 3;
      case GgApplyStatus::ReadError: return 2;
      case GgApplyStatus::InvalidArg: return 2;
      case GgApplyStatus::Empty: return 1;
      default: return 0;
    }
  };
  for (const auto& b : book.bindings) {
    BindingRead rd = ReadBinding(pid, b);
    o << "  sym=" << b.symbol;
    if (rd.status == MemStatus::Ok) {
      o << " addr=0x" << std::hex << rd.address << std::dec << " value=" << rd.number
        << " hex=" << rd.hex;
      if (!rd.module_path.empty()) o << " module=" << rd.module_path;
    } else {
      o << " ERROR " << rd.error;
      GgApplyStatus st = GgApplyStatus::ReadError;
      if (rd.status == MemStatus::PermissionDenied) st = GgApplyStatus::PermissionDenied;
      else if (rd.status == MemStatus::FingerprintMismatch) st = GgApplyStatus::FingerprintMismatch;
      else if (rd.status == MemStatus::Unsupported) st = GgApplyStatus::NotImplemented;
      else if (rd.status == MemStatus::NoPid) st = GgApplyStatus::InvalidArg;
      if (rank(st) > rank(worst)) worst = st;
    }
    o << "\n";
  }
  if (detail_out) *detail_out = o.str();
  return worst;
}

}  // namespace llamaspy
