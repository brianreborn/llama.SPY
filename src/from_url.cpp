#include "llamaspy/from_url.hpp"

#include "llamaspy/hook_script.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

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

bool ParseHttpUrl(const std::string& url, UrlParts* out) {
  const std::string prefix = "http://";
  if (url.rfind(prefix, 0) != 0) return false;
  std::string rest = url.substr(prefix.size());
  auto slash = rest.find('/');
  std::string hostport = slash == std::string::npos ? rest : rest.substr(0, slash);
  out->path = slash == std::string::npos ? "/" : rest.substr(slash);
  if (hostport.empty()) return false;
  if (hostport.front() == '[') {
    auto rb = hostport.find(']');
    if (rb == std::string::npos) return false;
    out->host = hostport.substr(1, rb - 1);
    if (rb + 1 < hostport.size() && hostport[rb + 1] == ':') {
      out->port = std::atoi(hostport.c_str() + rb + 2);
    } else {
      out->port = 80;
    }
  } else {
    auto colon = hostport.rfind(':');
    if (colon == std::string::npos) {
      out->host = hostport;
      out->port = 80;
    } else {
      out->host = hostport.substr(0, colon);
      out->port = std::atoi(hostport.c_str() + colon + 1);
    }
  }
  return !out->host.empty() && out->port > 0 && out->port <= 65535;
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

bool HttpExchange(const std::string& url, HttpResp* out, std::string* err) {
  UrlParts parts;
  if (!ParseHttpUrl(url, &parts)) {
    if (err) *err = "not an http URL";
    return false;
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* res = nullptr;
  std::string port = std::to_string(parts.port);
  if (getaddrinfo(parts.host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
    if (err) *err = "DNS lookup failed for " + parts.host;
    return false;
  }
  int fd = -1;
  for (addrinfo* p = res; p; p = p->ai_next) {
    fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (fd < 0) continue;
    timeval tv{};
    tv.tv_sec = 20;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) break;
    ::close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
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

std::string HttpsFetch(const std::string& url, std::string* err);

std::string HttpFetch(const std::string& url, std::string* err) {
  std::string current = url;
  for (int hop = 0; hop < 3; ++hop) {
    HttpResp resp;
    if (!HttpExchange(current, &resp, err)) return {};
    if (resp.status >= 300 && resp.status < 400) {
      std::string loc = HeaderOf(resp.headers, "location");
      if (loc.empty()) {
        if (err) *err = "redirect with no Location";
        return {};
      }
      if (loc.rfind("https://", 0) == 0) return HttpsFetch(loc, err);
      if (loc.rfind("http://", 0) != 0) {
        if (err) *err = "refusing non-http redirect";
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

std::string HttpsFetch(const std::string& url, std::string* err) {
  int fds[2];
  if (::pipe(fds) != 0) {
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
    // argv only. Never a shell. curl is preferred; fetch is the FreeBSD client.
    ::execlp("curl", "curl", "-fsSL", "--max-time", "20", "--proto", "=https", "--max-redirs",
             "2", "-A", "llamaspy/0.2.0", "--", url.c_str(), static_cast<char*>(nullptr));
    ::execlp("fetch", "fetch", "-q", "-T", "20", "-o", "-", url.c_str(),
             static_cast<char*>(nullptr));
    _exit(127);
  }
  ::close(fds[1]);
  std::string body = ReadPipeLimited(fds[0], err);
  ::close(fds[0]);
  int st = 0;
  ::waitpid(c, &st, 0);
  if (WIFEXITED(st) && WEXITSTATUS(st) == 127) {
    if (err) *err = "https fetch needs curl or fetch on PATH; remote code is not executed";
    return {};
  }
  if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
    if (err && err->empty()) *err = "https fetch failed";
    return {};
  }
  return body;
}

std::string FetchUrl(const std::string& url, std::string* err) {
  if (url.find('\n') != std::string::npos || url.find('\r') != std::string::npos) {
    if (err) *err = "URL contains a newline";
    return {};
  }
  if (url.rfind("https://", 0) == 0) return HttpsFetch(url, err);
  if (url.rfind("http://", 0) == 0) return HttpFetch(url, err);
  if (err) {
    *err = "only http:// and https:// are fetched. "
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
      if (!t.json_schema.empty() && (t.json_schema.front() == '{' || t.json_schema.front() == '[')) {
        o << ", \"json_schema\": " << t.json_schema;
      } else {
        o << ", \"json_schema\": " << Quote(t.json_schema);
      }
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

DraftWriteResult WriteHookDraftFromUrl(const std::string& url, const std::string& out_path) {
  DraftWriteResult r;
  std::string err;
  std::string body = FetchUrl(url, &err);
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
  std::string tmp = path + ".tmp";
  {
    std::ofstream out(tmp, std::ios::binary);
    if (!out) {
      r.error = "cannot write " + tmp;
      return r;
    }
    out << json;
    if (!out) {
      r.error = "write failed: " + tmp;
      return r;
    }
  }
  ::chmod(tmp.c_str(), 0644);
  if (::rename(tmp.c_str(), path.c_str()) != 0) {
    r.error = "rename failed: " + path;
    ::unlink(tmp.c_str());
    return r;
  }
  r.ok = true;
  r.path = path;
  return r;
}

}  // namespace llamaspy
