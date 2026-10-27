#include <filesystem>
#include <vector>
#include <cstdlib>
#include "llamaspy/game_genie.hpp"
#include "llamaspy/hook_script.hpp"
#include "llamaspy/js_engine.hpp"
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

namespace {
std::atomic<bool> g_run{true};
void OnSignal(int) { g_run = false; }

void Usage(const char* argv0) {
  std::cerr
      << llamaspy::T("banner") << "\n"
      << llamaspy::T("help.usage") << " " << argv0
      << " [--pid N] [--metrics-url URL] [--backend auto|http|dtrace|log]\n"
      << "         [--slots-url URL] [--api-key KEY] [--log-file PATH]\n"
      << "         [--dtrace-script PATH] [--no-hud] [--hook-file PATH|-] [--gg-file PATH|-]\n         [--list-tools] [--call-tool NAME [json-args]] [--from-url URL] [--lang xx]\n"
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
      << "\n"
      << "  " << llamaspy::T("help.serve") << "\n"
      << "  collector never binds the net — see docs/PRIVSEP.md.\n";
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
      // auth alone does not imply attach; pairs with --metrics-url
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
    } else if (a == "--lang") {
      llamaspy::I18nSetLang(need("--lang"));
    } else if (a == "--no-hud") {
      use_hud = false;
    } else if (a == "--serve") {
      // MVP stub only — real Capsicum/socketpair microservice is docs/PRIVSEP.md.
      std::cerr << "llama.SPY: --serve not implemented yet "
                   "(privilege-separated microservice; see docs/PRIVSEP.md)\n";
      return 2;
    } else if (a == "-h" || a == "--help") {
      Usage(argv[0]);
      return 0;
    } else {
      std::cerr << llamaspy::T("err.unknown_arg") << " " << a << "\n";
      Usage(argv[0]);
      return 2;
    }
  }

  // --from-url stub: never fetches or executes remotely.
  if (!from_url.empty()) {
    std::cerr << "llama.SPY: --from-url " << from_url << "\n"
              << llamaspy::T("from_url.stub") << "\n"
              << "  (review-before-load; no blind remote execute)\n";
    return 2;
  }

  bool have_hook = false;
  if (!hook_file.empty()) {
    auto hook = llamaspy::LoadHookScriptFile(hook_file);
    std::cout << llamaspy::FormatHookScript(hook);
    if (!hook.ok && hook.tools.empty() && hook.codebook.bindings.empty() &&
        hook.js_body.empty()) {
      std::cerr << "HookScript load failed\n";
      return 1;
    }
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
    // Combined mode: note that mem apply is stubbed.
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

  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);

  std::unique_ptr<llamaspy::TelemetryProvider> provider;
  if (backend == "dtrace") {
    provider = llamaspy::MakeDtraceFreeBsdProvider();
  } else if (backend == "http") {
    provider = llamaspy::MakeHttpMetricsProvider();
  } else if (backend == "log") {
    // Hook: --backend log --log-file PATH (src/log_timings.cpp); no FD hijack yet.
    provider = llamaspy::MakeLogTimingsProvider();
  } else if (backend == "auto") {
    // DTrace path resolution / LLAMASPY_FREEBSD ifdef owned by another worker — keep guard.
#if defined(LLAMASPY_FREEBSD) || defined(__FreeBSD__)
    if (pid != 0) {
      provider = llamaspy::MakeDtraceFreeBsdProvider();
    } else if (!metrics_url.empty()) {
      provider = llamaspy::MakeHttpMetricsProvider();
    } else if (!log_file.empty()) {
      provider = llamaspy::MakeLogTimingsProvider();
    } else {
      std::cerr << "auto: need --pid (dtrace), --metrics-url, or --log-file\n";
      return 2;
    }
#else
    if (!metrics_url.empty()) {
      provider = llamaspy::MakeHttpMetricsProvider();
    } else if (!log_file.empty()) {
      provider = llamaspy::MakeLogTimingsProvider();
    } else {
      std::cerr << "auto on non-FreeBSD: need --metrics-url or --log-file "
                   "(dtrace is FreeBSD primary; stub here)\n";
      return 2;
    }
#endif
  } else {
    std::cerr << "unknown backend: " << backend << "\n";
    return 2;
  }

  llamaspy::AttachOptions opts;
  opts.pid = pid;
  opts.metrics_url = metrics_url;
  opts.slots_url = slots_url;
  opts.api_key = api_key;
  opts.log_file = log_file;
  opts.dtrace_script_path = ResolveDtraceScript(dtrace_script, argv[0]);

  auto st = provider->Attach(opts);
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
