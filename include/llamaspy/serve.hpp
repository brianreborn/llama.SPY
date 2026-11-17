#pragma once
// Privilege-separated --serve. Collector never binds. Serve listens.
// docs/PRIVSEP.md LS1-LS4, plus an API key on every listener.
// Default bind is 127.0.0.1:9100. 0.0.0.0 and other non-loopback
// addresses are refused even when a key is present.

#include <functional>
#include <string>
#include <string_view>

namespace llamaspy {

struct ListenSpec {
  std::string host = "127.0.0.1";
  int port = 9100;
  bool ipv6 = false;
  bool ok = false;
  std::string error;
};

// Empty text -> 127.0.0.1:9100. Accepts "host:port", "[::1]:port", and "port".
ListenSpec ParseListenSpec(std::string_view text);

// Empty when the listener may start. Key must be non-empty for every listener.
// Non-loopback (0.0.0.0, *, ::, LAN, ...) is refused with or without a key.
std::string ListenerPolicyError(const ListenSpec& spec, const std::string& api_key);

// First line of path, trimmed. Refuses a symlink, a non-regular file,
// and any mode with group or other permission bits.
// Empty string and *err set on failure.
std::string ReadApiKeyFile(const std::string& path, std::string* err);

struct ServeConfig {
  ListenSpec listen;
  std::string api_key;
};

// Parent creates a socketpair, forks a collector child and a serve child,
// then reaps. If either child exits, the other is killed (LS4).
// collector runs only in the collector child; it must write host-order
// SnoopV1 frames by sending snoop_hton images of exactly 64 bytes on ipc_fd.
// Returns the child's exit code (0 on a clean signal stop).
int RunPrivsepServe(const ServeConfig& cfg, const std::function<int(int ipc_fd)>& collector);

// After the collector has attached. Denies bind/listen/accept.
// strict: also deny connect/open and enter Capsicum when the OS supports it.
// http/log collectors pass strict=false because they reopen files / sockets.
void SandboxCollector(int ipc_fd, bool strict);

}  // namespace llamaspy
