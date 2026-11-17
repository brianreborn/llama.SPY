cmake_minimum_required(VERSION 3.16)
# Official product name: llama.SPY (filesystem-safe target/binary: llamaspy)
project(llama_SPY VERSION 0.2.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  message(STATUS "FreeBSD detected: DTrace provider is PRIMARY backend for llama.SPY")
else()
  message(STATUS "Non-FreeBSD host: DTrace stub; Linux live attach uses bpftrace uprobes (--backend bpftrace)")
endif()

# Vendored Duktape for HookScript js_body (default ON — no network at build time).
option(LLAMASPY_JS "Embed Duktape JS engine for HookScript js_body" ON)
set(LLAMASPY_DUKTAPE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/duktape")
set(LLAMASPY_HAVE_DUKTAPE FALSE)
if(LLAMASPY_JS)
  if(EXISTS "${LLAMASPY_DUKTAPE_DIR}/duktape.c" AND EXISTS "${LLAMASPY_DUKTAPE_DIR}/duktape.h")
    set(LLAMASPY_HAVE_DUKTAPE TRUE)
    message(STATUS "JS engine: Duktape (vendored third_party/duktape)")
  else()
    message(WARNING "LLAMASPY_JS=ON but third_party/duktape missing — building without JS")
    set(LLAMASPY_JS OFF CACHE BOOL "Embed Duktape JS engine for HookScript js_body" FORCE)
  endif()
endif()
if(NOT LLAMASPY_JS)
  message(STATUS "JS engine: OFF (js_body will not execute; stub message at runtime)")
endif()

set(LLAMASPY_SOURCES
  src/main.cpp
  src/metrics_http.cpp
  src/provider_dtrace_freebsd.cpp
  src/provider_bpftrace_linux.cpp
  src/tui_stub.cpp
  src/game_genie.cpp
  src/log_timings.cpp
  src/i18n.cpp
  src/tool_registry.cpp
  src/hook_script.cpp
  src/js_engine.cpp
  src/mem_read.cpp
  src/serve.cpp
  src/from_url.cpp
  src/trace_parse.cpp
)

add_executable(llamaspy ${LLAMASPY_SOURCES})

if(LLAMASPY_HAVE_DUKTAPE)
  target_sources(llamaspy PRIVATE ${LLAMASPY_DUKTAPE_DIR}/duktape.c)
  target_include_directories(llamaspy PRIVATE ${LLAMASPY_DUKTAPE_DIR})
  # Silence noisy unused warnings from the amalgamation under -Wall.
  set_source_files_properties(${LLAMASPY_DUKTAPE_DIR}/duktape.c PROPERTIES
    COMPILE_FLAGS "-Wno-unused-parameter -Wno-unused-function")
  target_compile_definitions(llamaspy PRIVATE LLAMASPY_JS=1)
else()
  target_compile_definitions(llamaspy PRIVATE LLAMASPY_JS=0)
endif()

target_include_directories(llamaspy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Install-prefix fallback for the DTrace script (CMAKE_INSTALL_PREFIX/share/llamaspy)
target_compile_definitions(llamaspy PRIVATE
  LLAMASPY_SHARE_DIR="${CMAKE_INSTALL_FULL_DATADIR}/llamaspy")

if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  target_compile_definitions(llamaspy PRIVATE LLAMASPY_FREEBSD=1)
endif()

# Link libm for Duktape on some platforms
if(LLAMASPY_HAVE_DUKTAPE)
  find_library(M_LIB m)
  if(M_LIB)
    target_link_libraries(llamaspy PRIVATE ${M_LIB})
  endif()
endif()

install(TARGETS llamaspy RUNTIME DESTINATION bin)
install(FILES scripts/llama_decode.d scripts/llama_decode.bt DESTINATION share/llamaspy)
file(GLOB LLAMASPY_LOCALES ${CMAKE_CURRENT_SOURCE_DIR}/locales/*.json)
install(FILES ${LLAMASPY_LOCALES} DESTINATION share/llamaspy/locales)
install(FILES docs/DESIGN.md docs/PRIOR_ART.md docs/PRIVSEP.md docs/GAME_GENIE.md docs/METRICS_MAP.md README.md DESTINATION share/doc/llamaspy)
install(FILES examples/codes.sample.gg examples/hook.sample.json DESTINATION share/llamaspy/examples)

message(STATUS "llama.SPY ${PROJECT_VERSION} - FreeBSD-first (binary: llamaspy)")

enable_testing()
find_package(Threads REQUIRED)

add_executable(test_mem_read tests/test_mem_read.cpp src/mem_read.cpp src/game_genie.cpp)
target_include_directories(test_mem_read PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(test_mem_read PRIVATE LLAMASPY_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  target_compile_definitions(test_mem_read PRIVATE LLAMASPY_FREEBSD=1)
endif()

add_executable(test_serve tests/test_serve.cpp src/serve.cpp)
target_include_directories(test_serve PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
if(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  target_compile_definitions(test_serve PRIVATE LLAMASPY_FREEBSD=1)
endif()

add_executable(test_from_url tests/test_from_url.cpp src/from_url.cpp src/hook_script.cpp
               src/game_genie.cpp src/tool_registry.cpp src/js_engine.cpp src/mem_read.cpp)
target_include_directories(test_from_url PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(test_from_url PRIVATE Threads::Threads)
if(M_LIB)
  target_link_libraries(test_from_url PRIVATE ${M_LIB})
endif()
if(LLAMASPY_HAVE_DUKTAPE)
  target_sources(test_from_url PRIVATE ${LLAMASPY_DUKTAPE_DIR}/duktape.c)
  target_include_directories(test_from_url PRIVATE ${LLAMASPY_DUKTAPE_DIR})
  target_compile_definitions(test_from_url PRIVATE LLAMASPY_JS=1)
  set_source_files_properties(${LLAMASPY_DUKTAPE_DIR}/duktape.c PROPERTIES
    COMPILE_FLAGS "-Wno-unused-parameter -Wno-unused-function")
else()
  target_compile_definitions(test_from_url PRIVATE LLAMASPY_JS=0)
endif()

add_executable(test_trace_parse tests/test_trace_parse.cpp src/trace_parse.cpp)
target_include_directories(test_trace_parse PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_definitions(test_trace_parse PRIVATE LLAMASPY_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

add_test(NAME mem_read COMMAND test_mem_read)
add_test(NAME serve_policy COMMAND test_serve)
add_test(NAME from_url COMMAND test_from_url)
add_test(NAME trace_parse COMMAND test_trace_parse)
add_test(NAME cli_serve COMMAND sh ${CMAKE_SOURCE_DIR}/tests/cli_serve_test.sh $<TARGET_FILE:llamaspy>)
add_test(NAME serve_longevity COMMAND sh ${CMAKE_SOURCE_DIR}/tests/serve_longevity_test.sh $<TARGET_FILE:llamaspy>)
add_test(NAME no_target_writes COMMAND sh ${CMAKE_SOURCE_DIR}/tests/no_target_writes.sh ${CMAKE_SOURCE_DIR})
add_test(NAME hook_smoke COMMAND sh ${CMAKE_SOURCE_DIR}/bin/run-hook-smoke.sh)
add_test(NAME tracer_cleanup COMMAND sh ${CMAKE_SOURCE_DIR}/tests/tracer_cleanup_test.sh
         $<TARGET_FILE:llamaspy> ${CMAKE_SOURCE_DIR})
add_test(NAME gen_gg_offsets COMMAND sh ${CMAKE_SOURCE_DIR}/tests/gen_gg_offsets_test.sh
         $<TARGET_FILE:test_mem_read> ${CMAKE_SOURCE_DIR}/scripts/gen-gg-offsets.sh)
set_tests_properties(mem_read serve_policy from_url trace_parse cli_serve no_target_writes hook_smoke gen_gg_offsets tracer_cleanup serve_longevity
                     PROPERTIES TIMEOUT 60)
