#include "llamaspy/from_url.hpp"
#include "llamaspy/hook_script.hpp"
#include "llamaspy/js_engine.hpp"
#include "llamaspy/tool_registry.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <unistd.h>

static int g_fail = 0;

#define CHECK(cond)                                              \
  do {                                                           \
    if (!(cond)) {                                               \
      std::cerr << "FAIL " << __LINE__ << " " << #cond << "\n"; \
      ++g_fail;                                                  \
    }                                                            \
  } while (0)

static bool Has(const std::string& s, const char* needle) {
  return s.find(needle) != std::string::npos;
}

static void CheckDraftText() {
  const char* readme =
      "# Slot Watch\n"
      "\n"
      "See `scripts/gen-gg-offsets.sh`.\n"
      "\n"
      "```\n"
      "LLMS1|sym=n_past|off=0x0|width=8|type=u64|fp=buildid:abc|note=template\n"
      "```\n"
      "\n"
      "registerTool({name:\"pwned\", handler:function(){ return 1; }});\n";
  std::string draft = llamaspy::DraftHookScriptFromText(readme, "http://example.test/README.md");
  CHECK(Has(draft, "\"js_body\": \"\""));
  CHECK(!Has(draft, "pwned"));
  CHECK(!Has(draft, "registerTool"));
  CHECK(Has(draft, "\"readonly\": true"));
  CHECK(Has(draft, "LLMS1|sym=n_past|"));
  CHECK(Has(draft, "read_binding:n_past"));
  CHECK(Has(draft, "slot-watch") || Has(draft, "\"name\":"));
  CHECK(Has(draft, "not executed") || Has(draft, "not copied") || Has(draft, "was not copied") ||
        Has(draft, "script-looking"));

  const char* remote =
      "{\n"
      "  \"llamaspy_hook\": 1,\n"
      "  \"name\": \"remote-hook\",\n"
      "  \"readonly\": false,\n"
      "  \"js_body\": \"registerTool({name:\\\"pwned\\\", handler:function(){ return 1; }});\",\n"
      "  \"tools\": [{\"name\": \"echo\", \"handler\": \"read_binding:n_past\"}]\n"
      "}\n";
  std::string from_json = llamaspy::DraftHookScriptFromText(remote, "http://example.test/hook.json");
  CHECK(Has(from_json, "\"name\": \"remote-hook\""));
  CHECK(Has(from_json, "\"js_body\": \"\""));
  CHECK(!Has(from_json, "pwned"));
  CHECK(Has(from_json, "echo"));
  CHECK(Has(from_json, "readonly"));
  CHECK(Has(from_json, "forced") || Has(from_json, "discarded"));
}

static void CheckFetch() {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  CHECK(fd >= 0);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  CHECK(::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
  CHECK(::listen(fd, 1) == 0);
  socklen_t sl = sizeof(addr);
  CHECK(::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &sl) == 0);
  int port = ntohs(addr.sin_port);

  pid_t child = ::fork();
  if (child == 0) {
    int c = ::accept(fd, nullptr, nullptr);
    if (c < 0) _exit(1);
    char buf[1024];
    (void)::recv(c, buf, sizeof(buf), 0);
    const char* body = "# Hello\n\nLLMS1|sym=llama_decode|off=0x0|width=8|type=u64|fp=buildid:abc\n";
    std::string resp = "HTTP/1.0 200 OK\r\nContent-Length: ";
    resp += std::to_string(std::strlen(body));
    resp += "\r\nConnection: close\r\n\r\n";
    resp += body;
    (void)::send(c, resp.data(), resp.size(), 0);
    ::close(c);
    _exit(0);
  }
  ::close(fd);

  std::string url = "http://127.0.0.1:" + std::to_string(port) + "/README.md";
  std::string out = "/tmp/llamaspy-from-url-test.json";
  ::unlink(out.c_str());
  llamaspy::UrlFetchOptions opt;
  opt.allow_http = true;
  opt.allow_private = true;
  auto wr = llamaspy::WriteHookDraftFromUrl(url, out, true, opt);
  if (!wr.ok) std::cerr << "fetch draft failed: " << wr.error << "\n";
  CHECK(wr.ok);
  CHECK(wr.path == out);
  FILE* f = std::fopen(out.c_str(), "r");
  CHECK(f != nullptr);
  if (f) {
    std::string text;
    char b[512];
    while (std::fgets(b, sizeof(b), f)) text += b;
    std::fclose(f);
    CHECK(Has(text, "\"js_body\": \"\""));
    CHECK(Has(text, "llama_decode"));
    CHECK(!Has(text, "function("));
  }
  ::unlink(out.c_str());

  auto bad = llamaspy::WriteHookDraftFromUrl("file:///etc/passwd", "/tmp/should-not-write.json", true, opt);
  CHECK(!bad.ok);
  CHECK(Has(bad.error, "http"));

  int st = 0;
  ::waitpid(child, &st, 0);
}

static void CheckNestedJsDoesNotRun() {
  const char* remote =
      "{\n"
      "  \"llamaspy_hook\": 1,\n"
      "  \"name\": \"evil\",\n"
      "  \"readonly\": true,\n"
      "  \"tools\": [{\n"
      "    \"name\": \"echo\",\n"
      "    \"json_schema\": {\"type\":\"object\",\"js_body\":\"registerTool({name:\\\"pwned\\\",handler:function(){return 1;}});\"}\n"
      "  }]\n"
      "}\n";
  std::string draft = llamaspy::DraftHookScriptFromText(remote, "https://example.test/hook.json");
  CHECK(!Has(draft, "pwned"));
  auto loaded = llamaspy::LoadHookScriptText(draft, "draft");
  CHECK(loaded.js_body.empty());
  llamaspy::ToolRegistry::Instance().Clear();
  llamaspy::ApplyHookTools(loaded);
  std::string jerr;
  llamaspy::JsEngine::Instance().EvalHook(loaded, &jerr);
  bool found = false;
  for (const auto& t : llamaspy::ToolRegistry::Instance().List()) {
    if (t.name == "pwned") found = true;
  }
  CHECK(!found);
  llamaspy::ToolRegistry::Instance().Clear();
}

int main() {
  CheckDraftText();
  CheckNestedJsDoesNotRun();
  CheckFetch();
  if (g_fail) {
    std::cerr << g_fail << " failure(s)\n";
    return 1;
  }
  std::cout << "from_url ok\n";
  return 0;
}
