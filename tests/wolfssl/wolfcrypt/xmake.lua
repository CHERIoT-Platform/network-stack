-- Copyright The Good Penguin Ltd
-- SPDX-License-Identifier: MIT
-- Combined wolfCrypt test and benchmark for CHERIoT.
-- Use --run_test=y (default) and/or --run_bench=y to control what runs.
-- If both are enabled, the test suite runs first, then the benchmark.
-- Default board is sonata; use --board=sail for the CHERIoT simulator.

sdkdir = path.absolute("/workspaces/cheriot-rtos/sdk")
set_project("wolfcrypt")

includes(sdkdir)
set_toolchains("cheriot-clang")
includes(path.join(sdkdir, "lib"))

option("board")
  set_default("sonata-1.3")
  set_showmenu(true)

option("heartbeat")
  set_default(false)
  set_showmenu(true)
  set_description("Enable heartbeat thread that prints elapsed time every 5 seconds")

option("run_test")
  set_default(true)
  set_showmenu(true)
  set_description("Run the wolfCrypt test suite (wolfcrypt_test)")

option("run_bench")
  set_default(true)
  set_showmenu(true)
  set_description("Run the wolfCrypt benchmark suite (benchmark_test)")

debugOption("wolfcrypt")

library("time_helpers_stub")
  add_includedirs("../../../include")
  add_files("time_stub.cc")

compartment("wolfcrypt")
  add_rules("cheriot.component-debug")
  add_deps("freestanding", "string", "stdio", "cxxrt", "debug", "atomiccap", "time_helpers_stub")

  add_defines("WOLFSSL_USER_SETTINGS")
  -- Suppress warnings from wolfSSL third-party source that are not actionable:
  --   -Wignored-attributes: wolfSSL's fallback thread platform sets
  --     WOLFSSL_THREAD to __stdcall, which is silently ignored on RISC-V.
  --   -Watomic-alignment: wolfSSL uses volatile int (not _Atomic) for its
  --     atomic ref-counts; clang warns the 4-byte operations may not be
  --     lock-free on this target.
  add_cxflags("-Wno-ignored-attributes", "-Wno-atomic-alignment", "-Wno-parentheses-equality", "-Wno-tautological-compare", {force = true})
  add_defines("CHERIOT_NO_AMBIENT_MALLOC", "CHERIOT_NO_NEW_DELETE")
  add_defines("max_align_t=maxalign_t")
  add_defines("WOLFSSL_SMALL_STACK")
  -- CHERIoT does not support printing floats
  add_defines("WOLFSSL_NO_FLOAT_FMT")

  add_includedirs(
    "../../../lib/wolfssl",
    "../../../include",
    "../../../third_party/wolfssl")

  add_files("wolfcrypt.cc")
  add_files(
    "../../../lib/wolfssl/wolfssl_glue.cc",
    "../../../lib/wolfssl/wolfssl_time.c")

  if get_config("run_test") then
    add_defines("RUN_TEST")
    add_files("../../../third_party/wolfssl/wolfcrypt/test/test.c")
  end

  if get_config("run_bench") then
    add_defines("RUN_BENCH")
    -- benchmark.c uses current_time() which we provide; needs softfloat for double return
    add_defines("WOLFSSL_USER_CURRTIME")
    add_deps("softfloat64")
    add_files("../../../third_party/wolfssl/wolfcrypt/benchmark/benchmark.c")
  end

  -- wolfcrypt/src (shared by both test and bench)
  add_files(
    "../../../third_party/wolfssl/wolfcrypt/src/aes.c",
    "../../../third_party/wolfssl/wolfcrypt/src/sha.c",
    "../../../third_party/wolfssl/wolfcrypt/src/sha256.c",
    "../../../third_party/wolfssl/wolfcrypt/src/sha512.c",
    "../../../third_party/wolfssl/wolfcrypt/src/hmac.c",
    "../../../third_party/wolfssl/wolfcrypt/src/hash.c",
    "../../../third_party/wolfssl/wolfcrypt/src/kdf.c",
    "../../../third_party/wolfssl/wolfcrypt/src/random.c",
    "../../../third_party/wolfssl/wolfcrypt/src/md5.c")
  add_files(
    "../../../third_party/wolfssl/wolfcrypt/src/asn.c",
    "../../../third_party/wolfssl/wolfcrypt/src/coding.c",
    "../../../third_party/wolfssl/wolfcrypt/src/logging.c",
    "../../../third_party/wolfssl/wolfcrypt/src/memory.c",
    "../../../third_party/wolfssl/wolfcrypt/src/misc.c",
    "../../../third_party/wolfssl/wolfcrypt/src/error.c",
    "../../../third_party/wolfssl/wolfcrypt/src/wc_port.c",
    "../../../third_party/wolfssl/wolfcrypt/src/wc_encrypt.c",
    "../../../third_party/wolfssl/wolfcrypt/src/signature.c",
    "../../../third_party/wolfssl/wolfcrypt/src/cryptocb.c")
  add_files(
    "../../../third_party/wolfssl/wolfcrypt/src/ecc.c",
    "../../../third_party/wolfssl/wolfcrypt/src/rsa.c",
    "../../../third_party/wolfssl/wolfcrypt/src/dh.c",
    "../../../third_party/wolfssl/wolfcrypt/src/sp_int.c",
    "../../../third_party/wolfssl/wolfcrypt/src/sp_c32.c",
    "../../../third_party/wolfssl/wolfcrypt/src/sp_c64.c",
    "../../../third_party/wolfssl/wolfcrypt/src/wolfmath.c")
  add_files(
    "../../../third_party/wolfssl/wolfcrypt/src/chacha.c",
    "../../../third_party/wolfssl/wolfcrypt/src/poly1305.c",
    "../../../third_party/wolfssl/wolfcrypt/src/chacha20_poly1305.c",
    "../../../third_party/wolfssl/wolfcrypt/src/curve25519.c",
    "../../../third_party/wolfssl/wolfcrypt/src/ed25519.c",
    "../../../third_party/wolfssl/wolfcrypt/src/fe_operations.c",
    "../../../third_party/wolfssl/wolfcrypt/src/ge_operations.c",
    "../../../third_party/wolfssl/wolfcrypt/src/cmac.c")

firmware("wolfcrypt-cheriot")
  add_deps("wolfcrypt")
  on_load(function(target)
    target:values_set("board", "$(board)")
    local threads = {
      {
        compartment        = "wolfcrypt",
        priority           = 1,
        entry_point        = "combined_main",
        stack_size         = 0xa000,
        trusted_stack_frames = 8
      }
    }
    if get_config("heartbeat") then
      table.insert(threads, {
        compartment        = "wolfcrypt",
        priority           = 2,
        entry_point        = "heartbeat_main",
        stack_size         = 0x400,
        trusted_stack_frames = 4
      })
    end
    target:values_set("threads", threads, {expand = false})
  end)
