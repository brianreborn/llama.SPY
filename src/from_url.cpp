#include "llamaspy/from_url.hpp"

#include "llamaspy/hook_script.hpp"
#include "llamaspy/proc_util.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/syscall.h>
#  ifndef RENAME_NOREPLACE
#    define RENAME_NOREPLACE 1
#  endif
#endif

namespace llamaspy {
namespace {

constexpr size_t kMaxBody = 1u << 20;

std::string Trim(std::string s) {
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
  while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
  return s;
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
    } else if (c == '\r') {
      o += "\\r";
    } else if (c == '\t') {
      o += "\\t";
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

std::string Quote(std::string_view s) { return "\"" + JsonEscape(s) + "\""; }

std::string SanitizeName(std::string_view raw) {
  std::string o;
  bool dash = false;
  for (unsigned char c : raw) {
    char l = static_cast<char>(std::tolower(c));
    if ((l >= 'a' && l <= 'z') || (l >= '0' && l <= '9')) {
      o.push_back(l);
      dash = false;
    } else if (!o.empty() && !dash) {
      o.push_back('-');
      dash = true;
    }
    if (o.size() >= 48) break;
  }
  while (!o.empty() && o.back() == '-') o.pop_back();
  if (o.empty()) o = "draft";
  return o;
}

struct UrlParts {
  std::string host;
  int port = 80;
  std::string path = "/";
};

bool AuthorityOk(const std::string& hostport) {
  for (unsigned char c : hostport) {
    if (c == '@' || c == '\\' || c == '?' || c == '#' || c <= 0x20 || c == 0x7f) return false;
  }
  return !hostport.empty();
}

bool ParsePort(const char* text, int* port) {
  if (!text || !*text) return false;
  char* end = nullptr;
  errno = 0;
  long v = std::strtol(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || v <= 0 || v > 65535) return false;
  *port = static_cast<int>(v);
  return true;
}

bool ParseNumericAddress(const std::string& host, sockaddr_storage* ss, socklen_t* len);

bool HostIsLdhOrLiteral(const std::string& host) {
  sockaddr_storage ss{};
  socklen_t len = 0;
  if (ParseNumericAddress(host, &ss, &len)) return true;
  if (host.empty() || host.size() > 253 || host.front() == '.' || host.back() == '.') return false;
  size_t i = 0;
  while (i < host.size()) {
    size_t dot = host.find('.', i);
    std::string lab = host.substr(i, dot == std::string::npos ? std::string::npos : dot - i);
    if (lab.empty() || lab.size() > 63 || lab.front() == '-' || lab.back() == '-') return false;
    for (unsigned char c : lab) {
      bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
      if (!ok) return false;
    }
    if (lab.size() >= 4 &&
        (lab[0] == 'x' || lab[0] == 'X') && (lab[1] == 'n' || lab[1] == 'N') &&
        lab[2] == '-' && lab[3] == '-') {
      return false;
    }
    if (dot == std::string::npos) break;
    i = dot + 1;
  }
  return true;
}

bool SplitAuthority(const std::string& hostport, int default_port, UrlParts* out) {
  if (!AuthorityOk(hostport)) return false;
  if (hostport.front() == '[') {
    auto rb = hostport.find(']');
    if (rb == std::string::npos) return false;
    out->host = hostport.substr(1, rb - 1);
    if (out->host.empty() || !AuthorityOk(out->host)) return false;
    if (rb + 1 < hostport.size()) {
      if (hostport[rb + 1] != ':') return false;
      if (!ParsePort(hostport.c_str() + rb + 2, &out->port)) return false;
    } else {
      out->port = default_port;
    }
  } else {
    auto colon = hostport.rfind(':');
    if (colon == std::string::npos) {
      out->host = hostport;
      out->port = default_port;
    } else {
      out->host = hostport.substr(0, colon);
      if (!ParsePort(hostport.c_str() + colon + 1, &out->port)) return false;
    }
  }
  return !out->host.empty() && HostIsLdhOrLiteral(out->host);
}

bool ParseHttpUrl(const std::string& url, UrlParts* out) {
  const std::string prefix = "http://";
  if (url.rfind(prefix, 0) != 0) return false;
  std::string rest = url.substr(prefix.size());
  auto slash = rest.find('/');
  std::string hostport = slash == std::string::npos ? rest : rest.substr(0, slash);
  out->path = slash == std::string::npos ? "/" : rest.substr(slash);
  return SplitAuthority(hostport, 80, out);
}

struct HttpResp {
  int status = 0;
  std::string headers;
  std::string body;
};

std::string HeaderOf(const std::string& headers, const std::string& name) {
  std::string want;
  for (char c : name) want.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  size_t pos = 0;
  while (pos < headers.size()) {
    size_t eol = headers.find("\r\n", pos);
    if (eol == std::string::npos) break;
    std::string line = headers.substr(pos, eol - pos);
    pos = eol + 2;
    auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string key = line.substr(0, colon);
    for (char& c : key) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (Trim(key) == want) return Trim(line.substr(colon + 1));
  }
  return {};
}

bool Ipv4Blocked(uint32_t ip) {
  unsigned a = (ip >> 24) & 0xff;
  unsigned b = (ip >> 16) & 0xff;
  if (a == 0 || a == 10 || a == 127) return true;
  if (a == 100 && b >= 64 && b <= 127) return true;  // CGNAT 100.64/10
  if (a == 169 && b == 254) return true;
  if (a == 172 && b >= 16 && b <= 31) return true;
  if (a == 192 && b == 168) return true;
  if (a == 192 && b == 0) return true;
  if (a == 198 && (b == 18 || b == 19)) return true;
  if (a >= 224) return true;  // multicast and reserved
  return false;
}

bool SockaddrBlocked(const sockaddr* sa) {
  if (!sa) return true;
  if (sa->sa_family == AF_INET) {
    uint32_t ip = ntohl(reinterpret_cast<const sockaddr_in*>(sa)->sin_addr.s_addr);
    return Ipv4Blocked(ip);
  }
  if (sa->sa_family == AF_INET6) {
    const auto* in6 = reinterpret_cast<const sockaddr_in6*>(sa);
    const in6_addr& a = in6->sin6_addr;
    if (IN6_IS_ADDR_V4MAPPED(&a)) {
      uint32_t v4 = 0;
      std::memcpy(&v4, a.s6_addr + 12, 4);
      return Ipv4Blocked(ntohl(v4));
    }
    if (IN6_IS_ADDR_UNSPECIFIED(&a) || IN6_IS_ADDR_LOOPBACK(&a)) return true;
    if (IN6_IS_ADDR_LINKLOCAL(&a) || IN6_IS_ADDR_MULTICAST(&a)) return true;
#ifdef IN6_IS_ADDR_SITELOCAL
    if (IN6_IS_ADDR_SITELOCAL(&a)) return true;
#endif
    unsigned char b0 = a.s6_addr[0];
    if ((b0 & 0xfe) == 0xfc) return true;
    // NAT64 64:ff9b::/96 and 6to4 2002::/16 carry an embedded IPv4 address.
    bool nat64 = a.s6_addr[0] == 0x00 && a.s6_addr[1] == 0x64 && a.s6_addr[2] == 0xff &&
                 a.s6_addr[3] == 0x9b;
    if (nat64) {
      for (int i = 4; i < 12; ++i)
        if (a.s6_addr[i] != 0) nat64 = false;
    }
    if (nat64) {
      uint32_t v4 = 0;
      std::memcpy(&v4, a.s6_addr + 12, 4);
      return Ipv4Blocked(ntohl(v4));
    }
    if (a.s6_addr[0] == 0x20 && a.s6_addr[1] == 0x02) {
      uint32_t v4 = 0;
      std::memcpy(&v4, a.s6_addr + 2, 4);
      return Ipv4Blocked(ntohl(v4));
    }
    bool v4compat = true;
    for (int i = 0; i < 12; ++i) {
      if (a.s6_addr[i] != 0) v4compat = false;
    }
    if (v4compat) {
      uint32_t v4 = 0;
      std::memcpy(&v4, a.s6_addr + 12, 4);
      uint32_t host = ntohl(v4);
      if (host > 1) return Ipv4Blocked(host);
    }
    return false;
  }
  return true;
}

bool NameBlocked(const std::string& host) {
  std::string h = host;
  for (char& c : h) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return h == "localhost" || h == "localhost." || h == "localhost.localdomain";
}

// inet_aton accepts 127.1, 0x7f000001, 2130706433, and octal. inet_pton does not.
bool ParseNumericAddress(const std::string& host, sockaddr_storage* ss, socklen_t* len) {
  std::string h = host;
  if (h.size() >= 2 && h.front() == '[' && h.back() == ']') h = h.substr(1, h.size() - 2);
  std::memset(ss, 0, sizeof(*ss));
  in6_addr a6{};
  if (::inet_pton(AF_INET6, h.c_str(), &a6) == 1) {
    auto* in = reinterpret_cast<sockaddr_in6*>(ss);
    in->sin6_family = AF_INET6;
    in->sin6_addr = a6;
    *len = sizeof(sockaddr_in6);
    return true;
  }
  in_addr a4{};
  if (::inet_pton(AF_INET, h.c_str(), &a4) == 1 || ::inet_aton(h.c_str(), &a4) == 1) {
    auto* in = reinterpret_cast<sockaddr_in*>(ss);
    in->sin_family = AF_INET;
    in->sin_addr = a4;
    *len = sizeof(sockaddr_in);
    return true;
  }
  return false;
}

struct ResolvedAddr {
  sockaddr_storage addr{};
  socklen_t len = 0;
  std::string ip;
};

std::string AddrText(const sockaddr* sa) {
  char buf[INET6_ADDRSTRLEN];
  if (!sa) return {};
  if (sa->sa_family == AF_INET) {
    if (!::inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(sa)->sin_addr, buf, sizeof(buf)))
      return {};
    return buf;
  }
  if (sa->sa_family == AF_INET6) {
    if (!::inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr, buf, sizeof(buf)))
      return {};
    return buf;
  }
  return {};
}

// Resolve once. Any blocked address rejects the whole set, so a public A record
// cannot hide a loopback one. The caller pins these addresses and does not resolve again.
bool ResolveHost(const std::string& host, int port, bool allow_private,
                 std::vector<ResolvedAddr>* out, std::string* err) {
  out->clear();
  if (host.empty() || NameBlocked(host)) {
    if (!allow_private) {
      if (err) *err = "refusing private or loopback host (pass --from-url-allow-private)";
      return false;
    }
  }
  std::vector<ResolvedAddr> found;
  sockaddr_storage numeric{};
  socklen_t nlen = 0;
  if (ParseNumericAddress(host, &numeric, &nlen)) {
    if (numeric.ss_family == AF_INET) {
      reinterpret_cast<sockaddr_in*>(&numeric)->sin_port = htons(static_cast<uint16_t>(port));
    } else if (numeric.ss_family == AF_INET6) {
      reinterpret_cast<sockaddr_in6*>(&numeric)->sin6_port = htons(static_cast<uint16_t>(port));
    }
    ResolvedAddr r;
    r.addr = numeric;
    r.len = nlen;
    r.ip = AddrText(reinterpret_cast<sockaddr*>(&r.addr));
    if (r.ip.empty()) {
      if (err) *err = "unreadable numeric address";
      return false;
    }
    found.push_back(std::move(r));
  } else {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    std::string port_s = std::to_string(port);
    if (::getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0 || !res) {
      if (err) *err = "DNS lookup failed for " + host;
      return false;
    }
    for (addrinfo* p = res; p; p = p->ai_next) {
      if (!p->ai_addr || p->ai_addrlen <= 0) continue;
      ResolvedAddr r;
      std::memcpy(&r.addr, p->ai_addr, std::min(sizeof(r.addr), static_cast<size_t>(p->ai_addrlen)));
      r.len = static_cast<socklen_t>(p->ai_addrlen);
      r.ip = AddrText(reinterpret_cast<sockaddr*>(&r.addr));
      if (!r.ip.empty()) found.push_back(std::move(r));
    }
    ::freeaddrinfo(res);
    if (found.empty()) {
      if (err) *err = "DNS lookup failed for " + host;
      return false;
    }
  }
  bool blocked = false;
  for (const auto& r : found) {
    if (SockaddrBlocked(reinterpret_cast<const sockaddr*>(&r.addr))) blocked = true;
  }
  if (blocked && !allow_private) {
    if (err) *err = "refusing private, loopback, link-local, or non-global address";
    return false;
  }
  *out = std::move(found);
  return true;
}

bool LocationSafe(const std::string& loc) {
  if (loc.empty()) return false;
  for (unsigned char c : loc) {
    if (c < 0x20 || c == 0x7f) return false;
  }
  return loc.rfind("https://", 0) == 0 || loc.rfind("http://", 0) == 0;
}

long MonoMsFetch() {
  timespec ts{};
  ::clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

bool ConnectWithin(int fd, const sockaddr* sa, socklen_t len, long deadline_ms, std::string* err) {
  int fl = ::fcntl(fd, F_GETFL, 0);
  if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) != 0) {
    if (err) *err = "fcntl failed";
    return false;
  }
  int rc = ::connect(fd, sa, len);
  if (rc != 0 && errno != EINPROGRESS) {
    if (err) *err = std::string("connect failed: ") + std::strerror(errno);
    return false;
  }
  if (rc != 0) {
    long remain = deadline_ms - MonoMsFetch();
    if (remain < 0) remain = 0;
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLOUT;
    int pr = ::poll(&pfd, 1, static_cast<int>(remain));
    if (pr <= 0) {
      if (err) *err = pr == 0 ? "http connect timed out" : "poll failed";
      return false;
    }
    int so = 0;
    socklen_t sl = sizeof(so);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so, &sl) != 0 || so != 0) {
      if (err) *err = std::string("connect failed: ") + std::strerror(so != 0 ? so : errno);
      return false;
    }
  }
  ::fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
  return true;
}

bool HttpExchange(const std::string& url, HttpResp* out, std::string* err, bool allow_private,
                  long deadline_ms) {
  UrlParts parts;
  if (!ParseHttpUrl(url, &parts)) {
    if (err) *err = "not an http URL";
    return false;
  }
  if (MonoMsFetch() > deadline_ms) {
    if (err) *err = "http timed out";
    return false;
  }
  std::vector<ResolvedAddr> addrs;
  if (!ResolveHost(parts.host, parts.port, allow_private, &addrs, err)) return false;
  int fd = -1;
  for (const auto& a : addrs) {
    if (MonoMsFetch() > deadline_ms) break;
    fd = ::socket(a.addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) continue;
    timeval tv{};
    tv.tv_sec = 20;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (ConnectWithin(fd, reinterpret_cast<const sockaddr*>(&a.addr), a.len, deadline_ms, err)) break;
    ::close(fd);
    fd = -1;
  }
  if (fd < 0) {
    if (err) *err = "connect failed for " + url;
    return false;
  }
  std::ostringstream req;
  req << "GET " << parts.path << " HTTP/1.0\r\n"
      << "Host: " << parts.host << "\r\n"
      << "User-Agent: llamaspy/0.2.0\r\n"
      << "Accept: text/plain, text/markdown, application/json\r\n"
      << "Connection: close\r\n\r\n";
  const std::string req_s = req.str();
  size_t sent = 0;
  while (sent < req_s.size()) {
    ssize_t n = ::send(fd, req_s.data() + sent, req_s.size() - sent, 0);
    if (n <= 0) {
      ::close(fd);
      if (err) *err = "send failed";
      return false;
    }
    sent += static_cast<size_t>(n);
  }
  std::string raw;
  char buf[4096];
  while (raw.size() <= kMaxBody + 8192) {
    if (MonoMsFetch() > deadline_ms) {
      ::close(fd);
      if (err) *err = "http read timed out";
      return false;
    }
    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
      if (errno == EINTR) continue;
      ::close(fd);
      if (err) *err = "recv failed";
      return false;
    }
    if (n == 0) break;
    raw.append(buf, static_cast<size_t>(n));
  }
  ::close(fd);
  auto hdr_end = raw.find("\r\n\r\n");
  if (hdr_end == std::string::npos || raw.compare(0, 5, "HTTP/") != 0) {
    if (err) *err = "not an HTTP response";
    return false;
  }
  auto sp = raw.find(' ');
  if (sp == std::string::npos) {
    if (err) *err = "bad status line";
    return false;
  }
  out->status = std::atoi(raw.c_str() + sp + 1);
  out->headers = raw.substr(0, hdr_end);
  out->body = raw.substr(hdr_end + 4);
  if (out->body.size() > kMaxBody) {
    if (err) *err = "response larger than 1 MiB; not saved";
    return false;
  }
  return true;
}

std::string ReadPipeLimited(int fd, std::string* err) {
  std::string body;
  char buf[4096];
  while (body.size() <= kMaxBody) {
    ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) continue;
      if (err) *err = "read failed";
      return {};
    }
    if (n == 0) break;
    body.append(buf, static_cast<size_t>(n));
  }
  if (body.size() > kMaxBody) {
    if (err) *err = "response larger than 1 MiB; not saved";
    return {};
  }
  return body;
}

std::string HttpsFetch(const std::string& url, std::string* err, const UrlFetchOptions& opt);

std::string HttpFetch(const std::string& url, std::string* err, const UrlFetchOptions& opt) {
  std::string current = url;
  const long deadline = MonoMsFetch() + 20000;
  for (int hop = 0; hop < 3; ++hop) {
    if (MonoMsFetch() > deadline) {
      if (err) *err = "http timed out";
      return {};
    }
    HttpResp resp;
    if (!HttpExchange(current, &resp, err, opt.allow_private, deadline)) return {};
    if (resp.status >= 300 && resp.status < 400) {
      std::string loc = HeaderOf(resp.headers, "location");
      if (!LocationSafe(loc)) {
        if (err) *err = "refusing redirect Location (control character or bad scheme)";
        return {};
      }
      if (loc.rfind("https://", 0) == 0) return HttpsFetch(loc, err, opt);
      if (!opt.allow_http || loc.rfind("http://", 0) != 0) {
        if (err) *err = "refusing non-https redirect";
        return {};
      }
      current = loc;
      continue;
    }
    if (resp.status != 200) {
      if (err) *err = "HTTP status " + std::to_string(resp.status);
      return {};
    }
    return resp.body;
  }
  if (err) *err = "too many redirects";
  return {};
}

bool ParseSchemeUrl(const std::string& url, const char* scheme, int default_port, UrlParts* out) {
  const std::string prefix = scheme;
  if (url.rfind(prefix, 0) != 0) return false;
  std::string rest = url.substr(prefix.size());
  auto slash = rest.find('/');
  std::string hostport = slash == std::string::npos ? rest : rest.substr(0, slash);
  out->path = slash == std::string::npos ? "/" : rest.substr(slash);
  return SplitAuthority(hostport, default_port, out);
}

std::string HttpsFetch(const std::string& url, std::string* err, const UrlFetchOptions& opt) {
  UrlParts parts;
  if (!ParseSchemeUrl(url, "https://", 443, &parts)) {
    if (err) {
      *err = url.rfind("https://", 0) == 0 ? "refusing URL authority"
                                           : "not an https URL";
    }
    return {};
  }
  std::vector<ResolvedAddr> addrs;
  if (!ResolveHost(parts.host, parts.port, opt.allow_private, &addrs, err)) return {};
  std::string resolve_host = parts.host.find(':') != std::string::npos ? "[" + parts.host + "]" : parts.host;
  std::string pinned;
  for (size_t i = 0; i < addrs.size(); ++i) {
    if (i) pinned += ",";
    if (addrs[i].ip.find(':') != std::string::npos) pinned += "[" + addrs[i].ip + "]";
    else pinned += addrs[i].ip;
  }
  std::string resolve_spec = resolve_host + ":" + std::to_string(parts.port) + ":" + pinned;
  std::string curl_url = "https://" + resolve_host + ":" + std::to_string(parts.port) + parts.path;
  int fds[2];
  if (PipeCloexec(fds) != 0) {
    if (err) *err = "pipe failed";
    return {};
  }
  pid_t c = ::fork();
  if (c < 0) {
    ::close(fds[0]);
    ::close(fds[1]);
    if (err) *err = "fork failed";
    return {};
  }
  if (c == 0) {
    ::dup2(fds[1], STDOUT_FILENO);
    ::close(fds[0]);
    ::close(fds[1]);
    int dn = ::open("/dev/null", O_RDWR);
    if (dn >= 0) {
      ::dup2(dn, STDIN_FILENO);
      ::dup2(dn, STDERR_FILENO);
      if (dn > 2) ::close(dn);
    }
    // argv only. Never a shell. --resolve pins the addresses we already checked
    // so curl cannot resolve the name again. -q ignores ~/.curlrc.
    ::unsetenv("http_proxy");
    ::unsetenv("https_proxy");
    ::unsetenv("HTTP_PROXY");
    ::unsetenv("HTTPS_PROXY");
    ::unsetenv("ALL_PROXY");
    ::unsetenv("all_proxy");
    std::string curl = ResolveTrusted("curl");
    if (curl.empty()) _exit(127);
    std::vector<std::string> args = {
        curl,     "-q",        "-fsSL", "--noproxy", "*", "--max-time", "20", "--proto", "=https",
        "--max-redirs", "0", "-A", "llamaspy/0.2.0", "--resolve", resolve_spec,
        "-w", "\nllamaspy-http:%{http_code}\n", "--", curl_url};
    std::vector<char*> av;
    av.reserve(args.size() + 1);
    for (auto& s : args) av.push_back(s.data());
    av.push_back(nullptr);
    ::execv(av[0], av.data());
    _exit(127);
  }
  ::close(fds[1]);
  std::string body = ReadPipeLimited(fds[0], err);
  ::close(fds[0]);
  int st = 0;
  for (;;) {
    pid_t w = ::waitpid(c, &st, 0);
    if (w == c) break;
    if (w < 0 && errno == EINTR) continue;
    if (err) *err = "https fetch wait failed";
    return {};
  }
  if (WIFEXITED(st) && WEXITSTATUS(st) == 127) {
    if (err) *err = "https fetch needs curl or fetch on PATH; remote code is not executed";
    return {};
  }
  if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
    if (err && err->empty()) *err = "https fetch failed";
    return {};
  }
  const std::string mark = "\nllamaspy-http:";
  auto pos = body.rfind(mark);
  if (pos == std::string::npos || pos + mark.size() + 3 > body.size()) {
    if (err) *err = "https response had no status";
    return {};
  }
  std::string code = body.substr(pos + mark.size(), 3);
  for (char c : code) {
    if (c < '0' || c > '9') {
      if (err) *err = "https response had no status";
      return {};
    }
  }
  int http = std::atoi(code.c_str());
  body.resize(pos);
  if (http < 200 || http >= 300) {
    if (err) *err = "https status " + std::to_string(http) + "; not saved";
    return {};
  }
  return body;
}

std::string FetchUrl(const std::string& url, std::string* err, const UrlFetchOptions& opt) {
  if (url.find('\n') != std::string::npos || url.find('\r') != std::string::npos) {
    if (err) *err = "URL contains a newline";
    return {};
  }
  if (url.rfind("https://", 0) == 0) return HttpsFetch(url, err, opt);
  if (url.rfind("http://", 0) == 0) {
    if (!opt.allow_http) {
      if (err) *err = "refusing plain http (pass --from-url-allow-http). https is the default.";
      return {};
    }
    return HttpFetch(url, err, opt);
  }
  if (err) {
    *err = "only https:// is fetched by default. "
           "file:, ftp:, and other schemes are refused. Nothing is executed.";
  }
  return {};
}

bool LooksLikeJs(std::string_view body) {
  return body.find("js_body") != std::string_view::npos ||
         body.find("registerTool") != std::string_view::npos ||
         body.find("function(") != std::string_view::npos ||
         body.find("function (") != std::string_view::npos;
}

std::string RenderDraft(const HookScript& h, std::string_view source, const std::string& note) {
  std::ostringstream o;
  o << "{\n";
  o << "  \"llamaspy_hook\": 1,\n";
  o << "  \"name\": " << Quote(h.name.empty() ? "draft" : h.name) << ",\n";
  o << "  \"note\": " << Quote(note) << ",\n";
  o << "  \"readonly\": true,\n";
  o << "  \"source_url\": " << Quote(source) << ",\n";
  o << "  \"tools\": [";
  if (!h.tools.empty()) o << "\n";
  for (size_t i = 0; i < h.tools.size(); ++i) {
    const auto& t = h.tools[i];
    o << "    {\"name\": " << Quote(t.name);
    if (!t.description.empty()) o << ", \"description\": " << Quote(t.description);
    if (!t.handler.empty()) o << ", \"handler\": " << Quote(t.handler);
    if (!t.json_schema.empty() && t.json_schema != "{}") {
      // Always a JSON string. A raw object could smuggle a nested js_body.
      std::string schema = t.json_schema;
      if (schema.find("js_body") != std::string::npos || schema.find("\"script\"") != std::string::npos) {
        schema = "{}";
      }
      o << ", \"json_schema\": " << Quote(schema);
    }
    o << "}";
    if (i + 1 != h.tools.size()) o << ",";
    o << "\n";
  }
  o << "  ],\n";
  o << "  \"bindings\": [";
  if (!h.codebook.bindings.empty()) o << "\n";
  for (size_t i = 0; i < h.codebook.bindings.size(); ++i) {
    const auto& b = h.codebook.bindings[i];
    std::string line = b.raw_line.empty() ? std::string("LLMS1|sym=") + b.symbol : b.raw_line;
    o << "    " << Quote(line);
    if (i + 1 != h.codebook.bindings.size()) o << ",";
    o << "\n";
  }
  o << "  ],\n";
  // Remote script text is never copied here.
  o << "  \"js_body\": \"\"\n";
  o << "}\n";
  return o.str();
}

std::string NoteFor(std::string_view source, bool had_js, bool forced_ro, bool saw_scriptish,
                    int skipped) {
  std::ostringstream n;
  n << "DRAFT from " << source
    << ". Review before --hook-file. Remote content was fetched and parsed only; "
       "it was not executed. js_body is empty.";
  if (had_js) n << " Remote js_body/script was discarded.";
  if (saw_scriptish && !had_js) n << " Remote script-looking text was not copied.";
  if (forced_ro) n << " Remote readonly:false was forced back to true.";
  if (skipped > 0) n << " " << skipped << " LLMS1 line(s) did not parse and were dropped.";
  n << " Real offsets: scripts/gen-gg-offsets.sh BINARY symbol ...";
  return n.str();
}

}  // namespace

std::string DraftHookScriptFromText(std::string_view body, std::string_view source_url) {
  std::string trimmed = Trim(std::string(body));
  if (!trimmed.empty() && trimmed.front() == '{' &&
      body.find("llamaspy_hook") != std::string_view::npos) {
    HookScript h = LoadHookScriptText(body, source_url);
    bool had_js = !h.js_body.empty();
    bool forced = !h.readonly;
    h.js_body.clear();
    h.readonly = true;
    if (h.name.empty()) h.name = "draft";
    std::string note = NoteFor(source_url, had_js, forced, false, 0);
    if (!h.note.empty()) note += " Original note kept out of js_body.";
    return RenderDraft(h, source_url, note);
  }

  std::string heading;
  std::vector<std::string> lines;
  size_t pos = 0;
  while (pos <= body.size()) {
    size_t eol = body.find('\n', pos);
    std::string_view raw =
        eol == std::string_view::npos ? body.substr(pos) : body.substr(pos, eol - pos);
    if (!raw.empty() && raw.back() == '\r') raw.remove_suffix(1);
    pos = eol == std::string_view::npos ? body.size() + 1 : eol + 1;
    std::string line = Trim(std::string(raw));
    if (heading.empty() && line.size() > 2 && line[0] == '#') {
      size_t i = 0;
      while (i < line.size() && line[i] == '#') ++i;
      heading = Trim(line.substr(i));
    }
    auto at = line.find("LLMS1|");
    if (at != std::string::npos) lines.push_back(line.substr(at));
    if (eol == std::string_view::npos) break;
  }

  std::ostringstream joined;
  joined << "LLMS1\n";
  for (const auto& ln : lines) joined << ln << "\n";
  GgCodebook book = lines.empty() ? GgCodebook{} : ParseGameGenie(joined.str(), source_url);
  int skipped = 0;
  if (!lines.empty()) skipped = static_cast<int>(book.errors.size());

  HookScript h;
  h.name = SanitizeName(heading);
  h.readonly = true;
  h.codebook.bindings = book.bindings;
  for (const auto& b : book.bindings) {
    ToolDesc t;
    t.name = "gg_read_" + SanitizeName(b.symbol);
    t.description = "Draft read of " + b.symbol + " (review the offset before use)";
    t.json_schema = "{}";
    t.handler = "read_binding:" + b.symbol;
    h.tools.push_back(std::move(t));
  }
  bool scriptish = LooksLikeJs(body);
  std::string note = NoteFor(source_url, false, false, scriptish, skipped);
  if (h.codebook.bindings.empty()) {
    note += " No LLMS1 bindings found in the README.";
  }
  return RenderDraft(h, source_url, note);
}

struct SigHold {
  sigset_t old{};
  bool on = false;
  SigHold() {
    sigset_t block;
    sigemptyset(&block);
    sigaddset(&block, SIGINT);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGHUP);
    if (::sigprocmask(SIG_BLOCK, &block, &old) == 0) on = true;
  }
  ~SigHold() {
    if (on) ::sigprocmask(SIG_SETMASK, &old, nullptr);
  }
};

// 0 on success. EEXIST when path is already there. The temp name is removed
// except when renameat2 has already turned it into path.
int PublishNoReplace(const std::string& tmp, const std::string& path, const std::string& json) {
#if defined(__linux__) && defined(SYS_renameat2)
  if (::syscall(SYS_renameat2, AT_FDCWD, tmp.c_str(), AT_FDCWD, path.c_str(), RENAME_NOREPLACE) == 0) {
    return 0;
  }
  int e = errno;
  if (e == EEXIST) return EEXIST;
  if (e != EINVAL && e != ENOSYS && e != ENOTSUP && e != EOPNOTSUPP && e != EPERM && e != EXDEV) {
    return e;
  }
#else
  if (::link(tmp.c_str(), path.c_str()) == 0) {
    ::unlink(tmp.c_str());
    return 0;
  }
  int e = errno;
  if (e == EEXIST) return EEXIST;
  if (e != EPERM && e != ENOTSUP && e != EOPNOTSUPP && e != EMLINK && e != EXDEV) return e;
#endif
  int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) return errno == 0 ? EIO : errno;
  size_t off = 0;
  while (off < json.size()) {
    ssize_t n = ::write(fd, json.data() + off, json.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      int we = errno;
      struct stat a {};
      struct stat b {};
      bool same = ::fstat(fd, &a) == 0 && ::lstat(path.c_str(), &b) == 0 && a.st_dev == b.st_dev &&
                  a.st_ino == b.st_ino;
      ::close(fd);
      if (same) ::unlink(path.c_str());
      return we == 0 ? EIO : we;
    }
    off += static_cast<size_t>(n);
  }
  if (::fsync(fd) != 0) {
    int fe = errno;
    struct stat a {};
    struct stat b {};
    bool same = ::fstat(fd, &a) == 0 && ::lstat(path.c_str(), &b) == 0 && a.st_dev == b.st_dev &&
                a.st_ino == b.st_ino;
    ::close(fd);
    if (same) ::unlink(path.c_str());
    return fe == 0 ? EIO : fe;
  }
  ::close(fd);
  ::unlink(tmp.c_str());
  return 0;
}

DraftWriteResult WriteHookDraftFromUrl(const std::string& url, const std::string& out_path,
                                       bool overwrite, UrlFetchOptions opt) {
  DraftWriteResult r;
  std::string err;
  std::string body = FetchUrl(url, &err, opt);
  if (body.empty()) {
    r.error = err.empty() ? "fetch failed" : err;
    return r;
  }
  std::string json = DraftHookScriptFromText(body, url);
  if (out_path == "-") {
    std::cout << json;
    r.ok = true;
    r.path = "-";
    return r;
  }
  std::string path = out_path.empty() ? "llamaspy-hook.draft.json" : out_path;
  struct stat lst {};
  if (::lstat(path.c_str(), &lst) == 0 && S_ISLNK(lst.st_mode)) {
    r.error = "refusing to replace symlink " + path;
    return r;
  }
  std::string dir = ".";
  auto slash = path.find_last_of('/');
  if (slash == 0) dir = "/";
  else if (slash != std::string::npos) dir = path.substr(0, slash);
  std::string pattern = dir + "/llamaspy-draft-XXXXXX";
  std::vector<char> tmpl(pattern.begin(), pattern.end());
  tmpl.push_back('\0');
  // Held until publish finishes so SIGINT cannot leave the temp name behind.
  SigHold hold;
  int tfd = ::mkstemp(tmpl.data());
  if (tfd < 0) {
    r.error = "mkstemp failed in " + dir;
    return r;
  }
  std::string tmp(tmpl.data());
  size_t off = 0;
  bool write_ok = true;
  while (off < json.size()) {
    ssize_t n = ::write(tfd, json.data() + off, json.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      write_ok = false;
      break;
    }
    off += static_cast<size_t>(n);
  }
  if (::fsync(tfd) != 0) {
    ::close(tfd);
    ::unlink(tmp.c_str());
    r.error = "fsync failed";
    return r;
  }
  ::fchmod(tfd, 0600);
  ::close(tfd);
  if (!write_ok) {
    ::unlink(tmp.c_str());
    r.error = "write failed";
    return r;
  }
  if (!overwrite) {
    int pe = PublishNoReplace(tmp, path, json);
    if (pe != 0) {
      ::unlink(tmp.c_str());
      if (pe == EEXIST) r.error = "refusing to overwrite " + path + " (pass --draft-force)";
      else r.error = std::string("could not publish draft: ") + std::strerror(pe);
      return r;
    }
  } else if (::rename(tmp.c_str(), path.c_str()) != 0) {
    r.error = "rename failed: " + path;
    ::unlink(tmp.c_str());
    return r;
  }
  int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd >= 0) {
    ::fsync(dfd);
    ::close(dfd);
  }
  r.ok = true;
  r.path = path;
  return r;
}

}  // namespace llamaspy
