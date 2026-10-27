#include "llamaspy/js_engine.hpp"
#include "llamaspy/tool_registry.hpp"

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

#if defined(LLAMASPY_JS) && LLAMASPY_JS
#include "duktape.h"
#endif

namespace llamaspy {
namespace {

#if defined(LLAMASPY_JS) && LLAMASPY_JS

constexpr const char* kHandlersProp = "__llamaspy_handlers";
constexpr const char* kHookNameProp = "__llamaspy_hook_name";
constexpr const char* kEnginePtrProp = "__llamaspy_engine";
constexpr const char* kBindingsProp = "__llamaspy_bindings";

duk_ret_t NativeLog(duk_context* ctx) {
  duk_idx_t n = duk_get_top(ctx);
  std::ostringstream o;
  o << "[js] ";
  for (duk_idx_t i = 0; i < n; ++i) {
    if (i) o << ' ';
    if (duk_is_object(ctx, i) && !duk_is_null(ctx, i)) {
      duk_dup(ctx, i);
      duk_json_encode(ctx, -1);
      o << duk_safe_to_string(ctx, -1);
      duk_pop(ctx);
    } else {
      o << duk_safe_to_string(ctx, i);
    }
  }
  std::cerr << o.str() << "\n";
  return 0;
}

duk_ret_t NativeReadBinding(duk_context* ctx) {
  const char* sym = duk_require_string(ctx, 0);

  duk_push_global_stash(ctx);
  duk_get_prop_string(ctx, -1, kBindingsProp);
  const GgCodebook* codebook =
      static_cast<const GgCodebook*>(duk_get_pointer(ctx, -1));
  duk_pop_2(ctx);

  if (codebook) {
    for (const auto& b : codebook->bindings) {
      if (b.symbol == sym) {
        duk_push_object(ctx);
        duk_push_string(ctx, b.symbol.c_str());
        duk_put_prop_string(ctx, -2, "sym");
        duk_push_number(ctx, static_cast<double>(b.offset));
        duk_put_prop_string(ctx, -2, "offset");
        duk_push_int(ctx, static_cast<duk_int_t>(b.width));
        duk_put_prop_string(ctx, -2, "width");
        duk_push_string(ctx, GgValueTypeName(b.type));
        duk_put_prop_string(ctx, -2, "type");
        duk_push_true(ctx);
        duk_put_prop_string(ctx, -2, "declared");
        duk_push_null(ctx);
        duk_put_prop_string(ctx, -2, "value");
        duk_push_string(ctx, "mem backend not implemented");
        duk_put_prop_string(ctx, -2, "error");
        return 1;
      }
    }
  }
  duk_push_null(ctx);
  return 1;
}

duk_ret_t NativeRegisterTool(duk_context* ctx) {
  duk_require_object(ctx, 0);

  duk_get_prop_string(ctx, 0, "name");
  if (!duk_is_string(ctx, -1)) {
    return duk_type_error(ctx, "registerTool: name must be a string");
  }
  std::string name = duk_get_string(ctx, -1);
  duk_pop(ctx);

  std::string description;
  duk_get_prop_string(ctx, 0, "description");
  if (duk_is_string(ctx, -1)) description = duk_get_string(ctx, -1);
  duk_pop(ctx);

  std::string schema = "{}";
  duk_get_prop_string(ctx, 0, "schema");
  if (duk_is_string(ctx, -1)) {
    schema = duk_get_string(ctx, -1);
  } else if (duk_is_object(ctx, -1) && !duk_is_null(ctx, -1)) {
    duk_dup(ctx, -1);
    duk_json_encode(ctx, -1);
    schema = duk_safe_to_string(ctx, -1);
    duk_pop(ctx);
  }
  duk_pop(ctx);

  duk_get_prop_string(ctx, 0, "handler");
  if (!duk_is_function(ctx, -1)) {
    return duk_type_error(ctx, "registerTool: handler must be a function");
  }

  // stash.handlers[name] = fn  (fn currently at stack top)
  duk_push_global_stash(ctx);                 // fn, stash
  duk_get_prop_string(ctx, -1, kHandlersProp);  // fn, stash, handlers?
  if (!duk_is_object(ctx, -1)) {
    duk_pop(ctx);
    duk_push_object(ctx);
    duk_dup(ctx, -1);
    duk_put_prop_string(ctx, -3, kHandlersProp);  // stash.handlers = {}
  }
  duk_dup(ctx, -3);  // fn, stash, handlers, fn
  duk_put_prop_string(ctx, -2, name.c_str());
  duk_pop_2(ctx);  // pop handlers, stash — leave original fn
  duk_pop(ctx);    // pop fn

  std::string hook_name;
  duk_push_global_stash(ctx);
  duk_get_prop_string(ctx, -1, kHookNameProp);
  if (duk_is_string(ctx, -1)) hook_name = duk_get_string(ctx, -1);
  duk_pop_2(ctx);

  ToolDesc td;
  td.name = name;
  td.description = std::move(description);
  td.json_schema = std::move(schema);
  td.handler = "js:" + name;
  td.hook_name = std::move(hook_name);
  if (!ToolRegistry::Instance().Register(std::move(td))) {
    return duk_error(ctx, DUK_ERR_ERROR,
                     "registerTool: tool already registered: %s", name.c_str());
  }
  std::cerr << "[js] registered tool " << name << "\n";
  return 0;
}

void InjectHostApi(duk_context* ctx, JsEngine* eng) {
  duk_push_global_object(ctx);
  duk_push_c_function(ctx, NativeLog, DUK_VARARGS);
  duk_put_prop_string(ctx, -2, "log");
  duk_push_c_function(ctx, NativeRegisterTool, 1);
  duk_put_prop_string(ctx, -2, "registerTool");
  duk_push_c_function(ctx, NativeReadBinding, 1);
  duk_put_prop_string(ctx, -2, "readBinding");
  duk_pop(ctx);

  duk_push_global_stash(ctx);
  duk_push_pointer(ctx, static_cast<void*>(eng));
  duk_put_prop_string(ctx, -2, kEnginePtrProp);
  duk_push_object(ctx);
  duk_put_prop_string(ctx, -2, kHandlersProp);
  duk_pop(ctx);
}

duk_ret_t DecodeJsonSafe(duk_context* ctx, void* /*udata*/) {
  duk_json_decode(ctx, -1);
  return 1;
}

#endif  // LLAMASPY_JS

}  // namespace

JsEngine& JsEngine::Instance() {
  static JsEngine g;
  return g;
}

bool JsEngine::available() const {
#if defined(LLAMASPY_JS) && LLAMASPY_JS
  return init_ok_;
#else
  return false;
#endif
}

bool JsEngine::EnsureInit(std::string* err) {
#if !(defined(LLAMASPY_JS) && LLAMASPY_JS)
  if (err) *err = "JS engine disabled at build (LLAMASPY_JS=OFF)";
  return false;
#else
  if (init_ok_) return true;
  if (init_attempted_) {
    if (err) *err = "JS engine init previously failed";
    return false;
  }
  init_attempted_ = true;
  duk_context* ctx = duk_create_heap_default();
  if (!ctx) {
    if (err) *err = "duk_create_heap_default failed";
    return false;
  }
  InjectHostApi(ctx, this);
  ctx_ = ctx;
  init_ok_ = true;
  return true;
#endif
}

void JsEngine::Shutdown() {
#if defined(LLAMASPY_JS) && LLAMASPY_JS
  if (ctx_) {
    duk_destroy_heap(static_cast<duk_context*>(ctx_));
    ctx_ = nullptr;
  }
  init_ok_ = false;
  init_attempted_ = false;
  bindings_ = nullptr;
#endif
}

void JsEngine::SetBindings(const GgCodebook* book) {
  bindings_ = book;
#if defined(LLAMASPY_JS) && LLAMASPY_JS
  if (!ctx_) return;
  duk_context* ctx = static_cast<duk_context*>(ctx_);
  duk_push_global_stash(ctx);
  duk_push_pointer(ctx, const_cast<void*>(static_cast<const void*>(book)));
  duk_put_prop_string(ctx, -2, kBindingsProp);
  duk_pop(ctx);
#else
  (void)book;
#endif
}

bool JsEngine::EvalHook(const HookScript& hook, std::string* err) {
#if !(defined(LLAMASPY_JS) && LLAMASPY_JS)
  if (err) *err = "JS engine disabled at build";
  return false;
#else
  if (hook.js_body.empty()) return true;
  if (!EnsureInit(err)) return false;
  duk_context* ctx = static_cast<duk_context*>(ctx_);

  duk_push_global_stash(ctx);
  duk_push_string(ctx, hook.name.c_str());
  duk_put_prop_string(ctx, -2, kHookNameProp);
  duk_pop(ctx);

  SetBindings(&hook.codebook);

  if (duk_peval_string(ctx, hook.js_body.c_str()) != 0) {
    std::string msg = duk_safe_to_string(ctx, -1);
    duk_pop(ctx);
    if (err) *err = "js_body error: " + msg;
    return false;
  }
  duk_pop(ctx);
  return true;
#endif
}

bool JsEngine::CallJsTool(std::string_view tool_name, std::string_view json_args,
                         std::string* result_json, std::string* err) {
#if !(defined(LLAMASPY_JS) && LLAMASPY_JS)
  if (err) *err = "JS engine disabled at build";
  return false;
#else
  if (!EnsureInit(err)) return false;
  duk_context* ctx = static_cast<duk_context*>(ctx_);

  duk_push_global_stash(ctx);
  duk_get_prop_string(ctx, -1, kHandlersProp);
  if (!duk_is_object(ctx, -1)) {
    duk_pop_2(ctx);
    if (err) *err = "no JS handlers registered";
    return false;
  }
  std::string name(tool_name);
  duk_get_prop_string(ctx, -1, name.c_str());
  if (!duk_is_function(ctx, -1)) {
    duk_pop_3(ctx);
    if (err) *err = "JS handler not found for tool: " + name;
    return false;
  }
  // stack: stash, handlers, fn — keep only fn
  duk_insert(ctx, -3);  // fn, stash, handlers
  duk_pop_2(ctx);       // fn

  std::string args = json_args.empty() ? "{}" : std::string(json_args);
  duk_push_string(ctx, args.c_str());
  if (duk_safe_call(ctx, DecodeJsonSafe, nullptr, 1 /*nargs*/, 1 /*nrets*/) !=
      DUK_EXEC_SUCCESS) {
    std::string msg = duk_safe_to_string(ctx, -1);
    duk_pop(ctx);  // error
    duk_pop(ctx);  // fn
    if (err) *err = "invalid JSON args: " + msg;
    return false;
  }
  // stack: fn, args_obj
  if (duk_pcall(ctx, 1) != DUK_EXEC_SUCCESS) {
    std::string msg = duk_safe_to_string(ctx, -1);
    duk_pop(ctx);
    if (err) *err = "tool threw: " + msg;
    return false;
  }

  if (duk_is_undefined(ctx, -1)) {
    if (result_json) *result_json = "null";
    duk_pop(ctx);
    return true;
  }
  duk_json_encode(ctx, -1);
  if (result_json) *result_json = duk_safe_to_string(ctx, -1);
  duk_pop(ctx);
  return true;
#endif
}

bool CallTool(std::string_view name, std::string_view json_args,
              std::string* result_json, std::string* err) {
  auto found = ToolRegistry::Instance().Find(name);
  if (!found) {
    if (err) *err = "tool not found: " + std::string(name);
    return false;
  }
  const std::string& h = found->handler;

  if (h.rfind("js:", 0) == 0) {
    std::string js_name = h.substr(3);
    if (js_name.empty()) js_name = std::string(name);
    return JsEngine::Instance().CallJsTool(js_name, json_args, result_json, err);
  }

  if (h.rfind("read_binding:", 0) == 0) {
    std::string sym = h.substr(std::strlen("read_binding:"));
    std::ostringstream o;
    o << "{\"ok\":false,\"handler\":\"read_binding\",\"sym\":\"" << sym
      << "\",\"error\":\"mem backend not implemented\"}";
    if (result_json) *result_json = o.str();
    return true;
  }

  std::ostringstream o;
  o << "{\"ok\":false,\"error\":\"no dispatcher for handler\",\"handler\":\""
    << h << "\"}";
  if (result_json) *result_json = o.str();
  return true;
}

}  // namespace llamaspy
