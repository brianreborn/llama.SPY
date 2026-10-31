#include "llamaspy/i18n.hpp"

#include <cstdlib>
#include <cctype>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace llamaspy {
namespace {

using Table = std::unordered_map<std::string, std::string>;

const Table& EnTable() {
  static const Table t = {
      {"app.name", "llama.SPY"},
      {"app.tagline", "FreeBSD-first realtime llama.cpp observability"},
      {"banner", "llama.SPY — FreeBSD-first realtime llama.cpp observability"},
      {"help.usage", "Usage"},
      {"help.primary", "Primary (FreeBSD): --backend dtrace --pid <llama_pid>"},
      {"help.portable", "Portable fallback: --backend http --metrics-url http://127.0.0.1:8080/metrics"},
      {"help.fallback", "Portable fallback: --backend http --metrics-url http://127.0.0.1:8080/metrics"},
      {"help.lang", "--lang xx: force UI language (also LLAMASPY_LANG / LANG)"},
      {"help.auto", "auto: --pid uses dtrace (FreeBSD) or bpftrace (Linux), else http if URL given"},
      {"help.hud", "Default: one-pane ANSI HUD each poll; --no-hud prints [SnoopV1] lines"},
      {"help.hook", "--hook-file PATH: load HookScript (JSON) or LLMS1 codes; registers tools"},
      {"help.gg", "--gg-file PATH: LLMS1 paste-in codes only (simple dialect)"},
      {"help.list_tools", "--list-tools: list tools in the in-memory ToolRegistry"},
      {"help.call_tool", "--call-tool NAME [json]: invoke a registered tool; print JSON result"},
      {"help.from_url", "--from-url URL: stub — will draft HookScripts from project README (no remote exec)"},
      {"help.serve", "Optional --serve (future): privilege-separated metrics microservice"},
      {"hud.mode", "mode"},
      {"hud.gen", "gen"},
      {"hud.ingest", "ingest"},
      {"hud.busy", "busy"},
      {"hud.decode", "decode"},
      {"hud.rate", "rate"},
      {"hud.title", "llama.SPY"},
      {"hud.deferred", "deferred"},
      {"hud.avg_decode", "avg decode"},
      {"err.unknown_arg", "unknown arg"},
      {"err.missing_value", "missing value for"},
      {"from_url.stub", "not implemented: will draft HookScripts from project README"},
      {"hook.loaded", "HookScript loaded"},
      {"tools.empty", "(empty — load a HookScript with --hook-file)"},
  };
  return t;
}

const Table& JaTable() {
  static const Table t = {
      {"app.name", "llama.SPY"},
      {"app.tagline", "FreeBSD優先・稼働中llama.cppのリアルタイム観測"},
      {"banner", "llama.SPY — FreeBSD優先・稼働中llama.cppのリアルタイム観測"},
      {"help.usage", "使い方"},
      {"help.primary", "推奨 (FreeBSD): --backend dtrace --pid <llama_pid>"},
      {"help.portable", "移植フォールバック: --backend http --metrics-url http://127.0.0.1:8080/metrics"},
      {"help.fallback", "移植フォールバック: --backend http --metrics-url http://127.0.0.1:8080/metrics"},
      {"help.lang", "--lang xx: UI言語を指定（LLAMASPY_LANG / LANG も可）"},
      {"help.auto", "auto: --pid時はdtrace(FreeBSD)/bpftrace(Linux)、それ以外はURLがあればhttp"},
      {"help.hud", "既定: 1ペインANSI HUD。--no-hud で [SnoopV1] 行出力"},
      {"help.hook", "--hook-file PATH: HookScript (JSON) または LLMS1 を読込しツール登録"},
      {"help.gg", "--gg-file PATH: LLMS1 オフセットコードのみ（簡易方言）"},
      {"help.list_tools", "--list-tools: メモリ上の ToolRegistry を一覧"},
      {"help.call_tool", "--call-tool NAME [json]: 登録ツールを呼び出し JSON 結果を表示"},
      {"help.from_url", "--from-url URL: スタブ — READMEからHookScript下書き（遠隔実行なし）"},
      {"help.serve", "将来の --serve: 権限分離メトリクス・マイクロサービス"},
      {"hud.mode", "モード"},
      {"hud.gen", "生成"},
      {"hud.ingest", "取込"},
      {"hud.busy", "ビジー"},
      {"hud.decode", "デコード"},
      {"hud.rate", "レート"},
      {"hud.title", "llama.SPY"},
      {"hud.deferred", "待機"},
      {"hud.avg_decode", "平均デコード"},
      {"err.unknown_arg", "不明な引数"},
      {"err.missing_value", "値が必要です"},
      {"from_url.stub", "未実装: プロジェクトREADMEからHookScriptを下書きします"},
      {"hook.loaded", "HookScriptを読み込みました"},
      {"tools.empty", "（空 — --hook-file で HookScript を読み込んでください）"},
  };
  return t;
}

std::string g_lang = "en";
const Table* g_table = &EnTable();

std::string NormalizeLang(std::string_view raw) {
  std::string s;
  for (char c : raw) {
    if (c == '.' || c == '_') break;  // en_US.UTF-8 → en
    if (c == '-') break;
    s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  if (s.size() >= 2) s = s.substr(0, 2);  // ja_JP → ja
  return s.empty() ? "en" : s;
}

const Table* TableFor(std::string_view lang) {
  if (lang == "ja") return &JaTable();
  return &EnTable();
}

}  // namespace

void I18nSetLang(std::string_view lang) {
  g_lang = NormalizeLang(lang);
  g_table = TableFor(g_lang);
  // Unknown codes fall back to en table but keep requested code visible.
  if (g_lang != "en" && g_lang != "ja") {
    g_table = &EnTable();
  }
}

void I18nInit() {
  if (const char* e = std::getenv("LLAMASPY_LANG"); e && *e) {
    I18nSetLang(e);
    return;
  }
  if (const char* e = std::getenv("LC_MESSAGES"); e && *e && std::strcmp(e, "C") != 0) {
    I18nSetLang(e);
    return;
  }
  if (const char* e = std::getenv("LANG"); e && *e && std::strcmp(e, "C") != 0) {
    I18nSetLang(e);
    return;
  }
  I18nSetLang("en");
}

std::string_view I18nLang() { return g_lang; }

std::string_view T(std::string_view key) {
  auto it = g_table->find(std::string(key));
  if (it != g_table->end()) return it->second;
  // fallback to English
  if (g_table != &EnTable()) {
    auto it2 = EnTable().find(std::string(key));
    if (it2 != EnTable().end()) return it2->second;
  }
  return key;
}

}  // namespace llamaspy
