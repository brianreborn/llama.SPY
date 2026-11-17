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

// https and public hosts by default. Tests and explicit CLI flags opt in.
struct UrlFetchOptions {
  bool allow_http = false;
  bool allow_private = false;
};

// Fetch url and write a draft JSON file. Remote code is never executed.
// out_path "-" writes the document to stdout and sets path to "-".
// Empty out_path uses "llamaspy-hook.draft.json". Existing files are kept
// unless overwrite is true. The temporary file is created with mkstemp.
DraftWriteResult WriteHookDraftFromUrl(const std::string& url, const std::string& out_path,
                                       bool overwrite = false, UrlFetchOptions opt = {});

}  // namespace llamaspy
