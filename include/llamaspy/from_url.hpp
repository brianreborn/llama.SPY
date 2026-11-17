#pragma once
// --from-url: fetch a project README (or a HookScript JSON document) and
// write a local draft. The draft is never loaded and remote code is never
// executed. js_body is always emptied.

#include <string>
#include <string_view>

namespace llamaspy {

// Build a HookScript JSON document from a fetched body.
// js_body is always "". readonly is always true.
std::string DraftHookScriptFromText(std::string_view body, std::string_view source_url);

struct DraftWriteResult {
  bool ok = false;
  std::string path;
  std::string error;
};

// Fetch url (http, or https via curl/fetch) and write a draft JSON file.
// out_path "-" writes the document to stdout and sets path to "-".
// Empty out_path uses "llamaspy-hook.draft.json" in the current directory.
DraftWriteResult WriteHookDraftFromUrl(const std::string& url, const std::string& out_path);

}  // namespace llamaspy
