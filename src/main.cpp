#include <filesystem>
#include <vector>
#include <cstdlib>
#include "llamaspy/from_url.hpp"
#include "llamaspy/game_genie.hpp"
#include "llamaspy/hook_script.hpp"
#include "llamaspy/js_engine.hpp"
#include "llamaspy/mem_read.hpp"
#include "llamaspy/serve.hpp"
#include "llamaspy/tool_registry.hpp"
#include "llamaspy/i18n.hpp"
#include "llamaspy/metrics_http.hpp"
#include "llamaspy/snoop_v1.hpp"
#include "llamaspy/telemetry_provider.hpp"
#include "llamaspy/tui_stub.hpp"

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
std::atomic<bool> g_run{true};
void OnSignal(int) { g_run = false; }

void InstallStopSignals() {
  struct sigaction sa {};
  sa.sa_handler = OnSignal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;  // no SA_RESTART: blocking reads return EINTR
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);
  sigaction(SIGHUP, &sa, nullptr);
}

void Usage(const char* argv0) {
  std::cerr
      << llamaspy::T("banner") << "\n"
      << llamaspy::T("help.usage") << " " << argv0
      << " [--pid N] [--metrics-url URL] [--backend auto|http|dtrace|bpftrace|log]\n"
      << "         [--slots-url URL] [--api-key KEY] [--log-file PATH]\n"
      << "         [--dtrace-script PATH] [--no-hud] [--hook-file PATH|-] [--gg-file PATH|-]\n"
      << "         [--list-tools] [--call-tool NAME [json-args]] [--from-url URL]\n"
      << "         [--draft-out PATH] [--draft-force] [--from-url-allow-http]\n"
      << "         [--from-url-allow-private] [--serve [127.0.0.1:9100]]\n"
      << "         [--listen-api-key KEY] [--listen-api-key-file PATH] [--api-key-file PATH]\n"
      << "         [--lang xx]\n"
      << "\n"
      << "  " << llamaspy::T("help.primary") << "\n"
      << "  " << llamaspy::T("help.fallback") << "\n"
      << "  " << llamaspy::T("help.auto") << "\n"
      << "  " << llamaspy::T("help.lang") << "\n"
      << "  --slots-url / --api-key: enrich HTTP path; slots fills busy/idle when\n"
      << "    Prometheus lacks requests_* (see docs/METRICS_MAP.md)\n"
      << "  --backend log --log-file PATH: cooperative timing stub (no FD hijack)\n"
      << "  auto: also accepts --log-file when metrics/dtrace unavailable\n"
      << "  " << llamaspy::T("help.hud") << "\n"
      << "  " << llamaspy::T("help.hook") << "\n"
      << "  " << llamaspy::T("help.gg") << "\n"
      << "  " << llamaspy::T("help.list_tools") << "\n"
      << "  " << llamaspy::T("help.call_tool") << "\n"
      << "  " << llamaspy::T("help.from_url") << "\n"
      << "  --draft-out PATH: where --from-url writes the draft (default llamaspy-hook.draft.json)\n"
      << "\n"
      << "  " << llamaspy::T("help.serve") << "\n"
      << "  --api-key / --api-key-file: Bearer for outbound llama-server HTTP only.\n"
      << "    Prefer --api-key-file (mode 0600, not a symlink). --api-key is visible in ps.\n"
      << "  --listen-api-key-file PATH: required for --serve (mode 0600, not a symlink).\n"
      << "    --listen-api-key is visible in ps. Neither is sent outbound.\n"
      << "  --from-url is https and public hosts only, unless --from-url-allow-http\n"
      << "    or --from-url-allow-private. --draft-force overwrites an existing draft.\n"
      << "  collector never binds the net; see docs/PRIVSEP.md.\n";
}

void PrintFrameLine(const llamaspy::SnoopV1Frame& f) {
  double avg_lat_us = 0.0;
  if (f.decode_latency_n > 0) {
    avg_lat_us = (static_cast<double>(f.decode_latency_ns_sum) /
                  static_cast<double>(f.decode_latency_n)) /
                 1000.0;
  }
  std::cout << "[SnoopV1]"
            << " pid=" << f.pid
            << " pred_tok/s=" << f.predicted_tok_s
            << " prompt_tok/s=" << f.prompt_tok_s
            << " req_proc=" << f.requests_processing
            << " req_def=" << f.requests_deferred
            << " decode_n=" << f.decode_count
            << " avg_decode_us=" << avg_lat_us
            << "\n";
}

bool LoadGgFile(const std::string& path, llamaspy::GgCodebook* out) {
  if (path == "-") {
    std::ostringstream ss;
    ss << std::cin.rdbuf();
    *out = llamaspy::ParseGameGenie(ss.str(), "<stdin>");
  } else {
    *out = llamaspy::LoadGameGenieFile(path);
  }
  std::cout << llamaspy::FormatCodebook(*out);
  if (!out->ok && out->bindings.empty()) {
    return false;
  }
  return true;
}

// Resolve DTrace script: --dtrace-script > $LLAMASPY_DTRACE_SCRIPT >
// ./scripts/llama_decode.d > <exe dir>/llama_decode.d, <exe dir>/scripts/... ,
// <exe dir>/../share/llamaspy/llama_decode.d > LLAMASPY_SHARE_DIR (install prefix).
std::string ResolveDtraceScript(const std::string& cli, const char* argv0) {
  namespace fs = std::filesystem;
  if (!cli.empty()) return cli;
  if (const char* e = std::getenv("LLAMASPY_DTRACE_SCRIPT"); e && *e) return e;
  std::error_code ec;
  std::vector<fs::path> c{fs::path("scripts/llama_decode.d")};
  fs::path exe;
#if defined(__linux__)
  exe = fs::read_symlink("/proc/self/exe", ec);
#elif defined(LLAMASPY_FREEBSD) || defined(__FreeBSD__)
  exe = fs::read_symlink("/proc/curproc/file", ec);
#endif
  if (exe.empty() && argv0 && std::string(argv0).find('/') != std::string::npos)
    exe = fs::absolute(argv0, ec);
  if (!exe.empty()) {
    fs::path d = exe.parent_path();
    c.push_back(d / "llama_decode.d");
    c.push_back(d / "scripts/llama_decode.d");
    c.push_back(d / "../scripts/llama_decode.d");
    c.push_back(d / "../share/llamaspy/llama_decode.d");
  }
#ifdef LLAMASPY_SHARE_DIR
  c.push_back(fs::path(LLAMASPY_SHARE_DIR) / "llama_decode.d");
#endif
  for (auto& p : c) if (fs::is_regular_file(p, ec)) return p.lexically_normal().string();
  return "scripts/llama_decode.d";  // nothing found; dtrace will report error
}

std::unique_ptr<llamaspy::TelemetryProvider> MakeSelected(const std::string& backend,
                                                         const llamaspy::AttachOptions& opts,
                                                         std::string* err) {
  using llamaspy::MakeBpftraceLinuxProvider;
  using llamaspy::MakeDtraceFreeBsdProvider;
  using llamaspy::MakeHttpMetricsProvider;
  using llamaspy::MakeLogTimingsProvider;
  if (backend == "dtrace") return MakeDtraceFreeBsdProvider();
  if (backend == "bpftrace" || backend == "uprobe") return MakeBpftraceLinuxProvider();
  if (backend == "http") return MakeHttpMetricsProvider();
  if (backend == "log") return MakeLogTimingsProvider();
  if (backend == "auto") {
#if defined(LLAMASPY_FREEBSD) || defined(__FreeBSD__)
    if (opts.pid != 0) return MakeDtraceFreeBsdProvider();
#else
    if (opts.pid != 0) {
#  if defined(__linux__)
      return MakeBpftraceLinuxProvider();
#  else
      if (err) *err = "auto: no live-attach backend on this OS; use --metrics-url";
      return nullptr;
#  endif
    }
#endif
    if (!opts.metrics_url.empty()) return MakeHttpMetricsProvider();
    if (!opts.log_file.empty()) return MakeLogTimingsProvider();
    if (err) {
#if defined(LLAMASPY_FREEBSD) || defined(__FreeBSD__)
      *err = "auto: need --pid (dtrace), --metrics-url, or --log-file";
#else
      *err = "auto: need --pid (bpftrace), --metrics-url, or --log-file";
#endif
    }
    return nullptr;
  }
  if (err) *err = "unknown backend: " + backend;
  return nullptr;
}

llamaspy::AttachStatus AttachWithFallback(std::unique_ptr<llamaspy::TelemetryProvider>& provider,
                                          const std::string& backend,
                                          const llamaspy::AttachOptions& opts) {
  auto st = provider->Attach(opts);
  if (st == llamaspy::AttachStatus::Ok) return st;
  if (backend == "auto" && !opts.metrics_url.empty()) {
    std::cerr << "live attach via " << provider->name()
              << " failed; falling back to HTTP /metrics\n";
    provider = llamaspy::MakeHttpMetricsProvider();
    return provider->Attach(opts);
  }
  return st;
}
} // namespace

int main(int argc, char** argv) {
  llamaspy::I18nInit();  // I18N: LLAMASPY_LANG / LANG
  uint32_t pid = 0;
  std::string metrics_url;
  std::string slots_url;   // optional; default derived from metrics_url
  std::string api_key;     // optional Bearer for /metrics + /slots
  std::string log_file;    // --log-file cooperative timing stub
  std::string backend = "auto";
  std::string dtrace_script;  // resolved by ResolveDtraceScript()
  std::string gg_file;
  std::string hook_file;
  std::string from_url;
  std::string draft_out;
  std::string api_key_file;
  std::string listen_api_key;
  std::string listen_api_key_file;
  std::string serve_spec;
  bool want_serve = false;
  bool draft_force = false;
  bool from_url_allow_http = false;
  bool from_url_allow_private = false;
  bool list_tools = false;
  std::string call_tool;
  std::string call_tool_args = "{}";
  bool use_hud = true;
  bool want_metrics = false;

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto need = [&](const char* flag) -> std::string {
      if (i + 1 >= argc) {
        std::cerr << "missing value for " << flag << "\n";
        std::exit(2);
      }
      return argv[++i];
    };
    if (a == "--pid") {
      pid = static_cast<uint32_t>(std::strtoul(need("--pid").c_str(), nullptr, 10));
      want_metrics = true;
    } else if (a == "--metrics-url") {
      metrics_url = need("--metrics-url");
      want_metrics = true;
    } else if (a == "--slots-url") {
      slots_url = need("--slots-url");
      want_metrics = true;
    } else if (a == "--api-key") {
      api_key = need("--api-key");
    } else if (a == "--api-key-file") {
      api_key_file = need("--api-key-file");
    } else if (a == "--listen-api-key") {
      listen_api_key = need("--listen-api-key");
    } else if (a == "--listen-api-key-file") {
      listen_api_key_file = need("--listen-api-key-file");
    } else if (a == "--log-file") {
      log_file = need("--log-file");
      want_metrics = true;
    } else if (a == "--backend") {
      backend = need("--backend");
      want_metrics = true;
    } else if (a == "--dtrace-script") {
      dtrace_script = need("--dtrace-script");
    } else if (a == "--gg-file") {
      gg_file = need("--gg-file");
    } else if (a == "--hook-file") {
      hook_file = need("--hook-file");
    } else if (a == "--list-tools") {
      list_tools = true;
    } else if (a == "--call-tool" || a == "--invoke") {
      call_tool = need(a.c_str());
      // Optional JSON args: next argv if it looks like JSON object/array/string/number
      if (i + 1 < argc) {
        std::string peek = argv[i + 1];
        if (!peek.empty() && (peek.front() == '{' || peek.front() == '[' ||
                              peek.front() == '"' || peek == "null" ||
                              peek == "true" || peek == "false" ||
                              (peek.front() >= '0' && peek.front() <= '9') ||
                              peek.front() == '-')) {
          call_tool_args = argv[++i];
        }
      }
    } else if (a == "--from-url") {
      from_url = need("--from-url");
    } else if (a == "--draft-out") {
      draft_out = need("--draft-out");
    } else if (a == "--draft-force") {
      draft_force = true;
    } else if (a == "--from-url-allow-http") {
      from_url_allow_http = true;
    } else if (a == "--from-url-allow-private") {
      from_url_allow_private = true;
    } else if (a == "--lang") {
      llamaspy::I18nSetLang(need("--lang"));
    } else if (a == "--no-hud") {
      use_hud = false;
    } else if (a == "--serve") {
      want_serve = true;
      want_metrics = true;
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        serve_spec = argv[++i];
      }
    } else if (a == "-h" || a == "--help") {
      Usage(argv[0]);
      return 0;
    } else {
      std::cerr << llamaspy::T("err.unknown_arg") << " " << a << "\n";
      Usage(argv[0]);
      return 2;
    }
  }

  auto load_key_file = [](const std::string& path, std::string* dest) {
    std::string kerr;
    std::string key = llamaspy::ReadApiKeyFile(path, &kerr);
    if (key.empty()) {
      std::cerr << "llama.SPY: " << kerr << "\n";
      std::exit(2);
    }
    *dest = std::move(key);
  };
  if (!api_key_file.empty()) {
    if (!api_key.empty()) {
      std::cerr << "llama.SPY: --api-key is set; ignoring --api-key-file\n";
    } else {
      load_key_file(api_key_file, &api_key);
    }
  }
  if (!listen_api_key_file.empty()) {
    if (!listen_api_key.empty()) {
      std::cerr << "llama.SPY: --listen-api-key is set; ignoring --listen-api-key-file\n";
    } else {
      load_key_file(listen_api_key_file, &listen_api_key);
    }
  }

  // Fetch and write a draft. Never load it and never execute remote code.
  if (!from_url.empty()) {
    llamaspy::UrlFetchOptions fopt;
    fopt.allow_http = from_url_allow_http;
    fopt.allow_private = from_url_allow_private;
    auto drafted = llamaspy::WriteHookDraftFromUrl(from_url, draft_out, draft_force, fopt);
    if (!drafted.ok) {
      std::cerr << "llama.SPY: --from-url failed: " << drafted.error << "\n"
                << "Remote content was not executed.\n";
      return 1;
    }
    std::cout << "Wrote HookScript draft (not loaded, not executed): " << drafted.path << "\n"
              << "Review it, then load locally with --hook-file. js_body is empty.\n";
    return 0;
  }

  llamaspy::SetMemTargetPid(pid);

  llamaspy::HookScript hook;
  bool have_hook = false;
  if (!hook_file.empty()) {
    hook = llamaspy::LoadHookScriptFile(hook_file);
    std::cout << llamaspy::FormatHookScript(hook);
    if (!hook.ok && hook.tools.empty() && hook.codebook.bindings.empty() &&
        hook.js_body.empty()) {
      std::cerr << "HookScript load failed\n";
      return 1;
    }
    llamaspy::SetMemCodebook(&hook.codebook);
    std::size_t n = llamaspy::ApplyHookTools(hook);
    std::cerr << "[" << llamaspy::T("hook.loaded") << "] registered " << n
              << " tool(s) from manifest\n";
    if (!hook.js_body.empty()) {
      std::string jerr;
      if (!llamaspy::JsEngine::Instance().EvalHook(hook, &jerr)) {
        std::cerr << "js_body: " << jerr << "\n";
        return 1;
      }
      std::cerr << "[js] js_body evaluated (" << hook.js_body.size() << " bytes)\n";
    }
    have_hook = true;
  }

  if (!call_tool.empty()) {
    if (!have_hook && hook_file.empty()) {
      std::cerr << "--call-tool needs --hook-file (load tools first)\n";
      return 2;
    }
    std::string result;
    std::string cerr_msg;
    if (!llamaspy::CallTool(call_tool, call_tool_args, &result, &cerr_msg)) {
      std::cerr << "call-tool failed: " << cerr_msg << "\n";
      return 1;
    }
    std::cout << result << "\n";
    return 0;
  }

  if (have_hook && !want_metrics && metrics_url.empty() && pid == 0 &&
      gg_file.empty()) {
    // Dump-only when no metrics attach requested (same as --gg-file alone).
    std::cout << llamaspy::FormatToolList(llamaspy::ToolRegistry::Instance().List());
    return 0;
  }

  llamaspy::GgCodebook gg;
  bool have_gg = false;
  if (!gg_file.empty()) {
    if (!LoadGgFile(gg_file, &gg)) {
      std::cerr << "Game Genie load failed" << std::endl;
      return 1;
    }
    have_gg = true;
    llamaspy::SetMemCodebook(&gg);
    // Dump-only mode: --gg-file without metrics attach flags.
    if (!want_metrics && metrics_url.empty() && pid == 0) {
      // Soft parse errors still exit 0 if at least one binding loaded; hard empty fail already returned 1.
      if (!gg.ok && !gg.bindings.empty()) {
        std::cerr << "warning: parsed with errors; dumping partial codebook\n";
      }
      if (list_tools) {
        std::cout << llamaspy::FormatToolList(llamaspy::ToolRegistry::Instance().List());
      }
      return 0;
    }
    std::string detail;
    auto st = llamaspy::ApplyReadOnly(pid, gg, &detail);
    std::cerr << "[gg] ApplyReadOnly status=" << static_cast<int>(st) << "\n"
              << detail;
  }

  if (list_tools) {
    std::cout << llamaspy::FormatToolList(llamaspy::ToolRegistry::Instance().List());
    if (!want_metrics && metrics_url.empty() && pid == 0) return 0;
  }

  if (!want_metrics && metrics_url.empty() && pid == 0) {
    if (have_gg || have_hook) return 0;
    Usage(argv[0]);
    return 2;
  }

  llamaspy::AttachOptions opts;
  opts.pid = pid;
  opts.metrics_url = metrics_url;
  opts.slots_url = slots_url;
  opts.api_key = api_key;
  opts.log_file = log_file;
  opts.dtrace_script_path = ResolveDtraceScript(dtrace_script, argv[0]);

  std::string sel_err;
  auto provider = MakeSelected(backend, opts, &sel_err);
  if (!provider) {
    std::cerr << sel_err << "\n";
    return 2;
  }

  if (want_serve) {
    if (pid == 0 && metrics_url.empty() && log_file.empty()) {
      std::cerr << "--serve needs --pid, --metrics-url, or --log-file\n";
      return 2;
    }
    llamaspy::ServeConfig cfg;
    cfg.listen = llamaspy::ParseListenSpec(serve_spec);
    cfg.api_key = listen_api_key;
    // Collector attaches first, then drops bind/listen/accept. Strict mode
    // (no new connect/open, Capsicum when available) is only for live tracers.
    return llamaspy::RunPrivsepServe(cfg, [&](int ipc) -> int {
      InstallStopSignals();
      int fl = ::fcntl(ipc, F_GETFL, 0);
      if (fl >= 0) ::fcntl(ipc, F_SETFL, fl | O_NONBLOCK);
      auto st = AttachWithFallback(provider, backend, opts);
      if (st != llamaspy::AttachStatus::Ok) {
        std::cerr << "Attach failed via " << provider->name()
                  << " status=" << static_cast<int>(st) << "\n";
        return 1;
      }
      const std::string pname = provider->name();
      const bool live = pname == "dtrace-freebsd" || pname == "bpftrace-linux";
      llamaspy::SandboxCollector(ipc, live);
      std::cerr << "Attached via " << provider->name() << "\n";
      while (g_run.load()) {
        bool cont = provider->StreamMetrics([&](const llamaspy::SnoopV1Frame& f) {
          llamaspy::SnoopV1Frame wire = llamaspy::snoop_hton(f);
          ssize_t n = ::send(ipc, &wire, sizeof(wire), MSG_NOSIGNAL);
          if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
          if (n != static_cast<ssize_t>(sizeof(wire))) g_run = false;
        });
        if (!cont) break;
      }
      provider->Detach();
      return 0;
    });
  }

  InstallStopSignals();

  auto st = AttachWithFallback(provider, backend, opts);
  if (st != llamaspy::AttachStatus::Ok) {
    std::cerr << "Attach failed via " << provider->name()
              << " status=" << static_cast<int>(st) << "\n";
    return 1;
  }
  std::cerr << "Attached via " << provider->name() << "\n";

  llamaspy::HudState hud;
  hud.mode = llamaspy::BadgeFromBackendName(provider->name(), backend.c_str());
  if (use_hud) {
    llamaspy::BeginHud(hud);
  }

  while (g_run.load()) {
    bool cont = provider->StreamMetrics([&](const llamaspy::SnoopV1Frame& f) {
      if (use_hud) {
        llamaspy::RenderHud(hud, f);
      } else {
        PrintFrameLine(f);
      }
    });
    if (!cont) break;
  }

  if (use_hud) {
    llamaspy::EndHud(hud);
  }
  provider->Detach();
  return 0;
}
