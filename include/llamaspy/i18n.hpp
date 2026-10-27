#pragma once
// Trivial i18n for llama.SPY — no gettext.
// Auto-pick: LLAMASPY_LANG → LANG / LC_MESSAGES (prefix: en, ja, …); fallback en.
// Add a language: copy locales/en.json → locales/xx.json (and/or extend kTables).
// See README "i18n".

#include <string>
#include <string_view>

namespace llamaspy {

// Call once at startup (main). Safe to call again.
void I18nInit();
void I18nSetLang(std::string_view lang);  // "en", "ja", …
std::string_view I18nLang();

// Lookup key; returns key itself if missing.
std::string_view T(std::string_view key);
inline std::string_view tr(std::string_view key) { return T(key); }

}  // namespace llamaspy
