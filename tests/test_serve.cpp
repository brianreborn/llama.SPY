#include "llamaspy/serve.hpp"

#include <iostream>
#include <string>

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

int main() {
  auto def = llamaspy::ParseListenSpec("");
  CHECK(def.ok);
  CHECK(def.host == "127.0.0.1");
  CHECK(def.port == 9100);
  CHECK(llamaspy::ListenerPolicyError(def, "secret").empty());
  CHECK(!llamaspy::ListenerPolicyError(def, "").empty());

  auto loop = llamaspy::ParseListenSpec("127.0.0.1:19191");
  CHECK(loop.ok && loop.port == 19191);
  CHECK(llamaspy::ListenerPolicyError(loop, "k").empty());

  auto local = llamaspy::ParseListenSpec("localhost:9");
  CHECK(local.ok);
  CHECK(llamaspy::ListenerPolicyError(local, "k").empty());

  auto v6 = llamaspy::ParseListenSpec("[::1]:9100");
  CHECK(v6.ok && v6.ipv6);
  CHECK(llamaspy::ListenerPolicyError(v6, "k").empty());

  auto bare = llamaspy::ParseListenSpec("9100");
  CHECK(bare.ok && bare.host == "127.0.0.1" && bare.port == 9100);

  auto bad_port = llamaspy::ParseListenSpec("127.0.0.1:abc");
  CHECK(!bad_port.ok);

  auto eph = llamaspy::ParseListenSpec("127.0.0.1:0");
  CHECK(eph.ok && eph.port == 0);
  CHECK(llamaspy::ListenerPolicyError(eph, "k").empty());

  auto wild = llamaspy::ParseListenSpec("0.0.0.0:9100");
  CHECK(wild.ok);
  std::string wild_err = llamaspy::ListenerPolicyError(wild, "secret-key");
  CHECK(!wild_err.empty());
  CHECK(Has(wild_err, "0.0.0.0"));
  CHECK(Has(wild_err, "loopback") || Has(wild_err, "non-loopback"));
  std::string wild_nokey = llamaspy::ListenerPolicyError(wild, "");
  CHECK(Has(wild_nokey, "0.0.0.0"));
  CHECK(Has(wild_nokey, "API key"));

  auto star = llamaspy::ParseListenSpec("*:9100");
  CHECK(!llamaspy::ListenerPolicyError(star, "k").empty());

  auto lan = llamaspy::ParseListenSpec("192.168.1.10:9100");
  CHECK(!llamaspy::ListenerPolicyError(lan, "k").empty());

  auto all6 = llamaspy::ParseListenSpec("[::]:9100");
  CHECK(!llamaspy::ListenerPolicyError(all6, "k").empty());

  auto empty_host = llamaspy::ParseListenSpec(":9100");
  CHECK(!empty_host.ok);
  CHECK(!llamaspy::ListenerPolicyError(empty_host, "k").empty());

  auto no_key = llamaspy::ListenerPolicyError(loop, "   ");
  CHECK(Has(no_key, "API key"));

  if (g_fail) {
    std::cerr << g_fail << " failure(s)\n";
    return 1;
  }
  std::cout << "serve policy ok\n";
  return 0;
}
