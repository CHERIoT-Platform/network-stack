debugOption("WolfSSLTLS")

option("wolfssl-small-stack")
    set_default(false)
    set_description("Enable WOLFSSL_SMALL_STACK: allocate per-function crypto buffers on the heap instead of the stack. Requires wolfssl_set_fallback_heap() to be called for code paths that pass a NULL heap hint.")
    set_showmenu(true)
    add_defines("WOLFSSL_SMALL_STACK")

option("wolfssl-single-threaded")
    set_default(true)
    set_description("Enable SINGLE_THREADED: disable wolfSSL's internal mutex locking. Use only when the WolfSSLTLS compartment is guaranteed to be called from a single thread at a time.")
    set_showmenu(true)
    add_defines("SINGLE_THREADED")

compartment("WolfSSLTLS")
  add_rules("cheriot.component-debug")
  add_deps("freestanding")
  add_deps("cxxrt", "string", "debug")
  add_options("wolfssl-small-stack", "wolfssl-single-threaded")
  set_default(false)

  -- Pull in user_settings.h from this directory before any wolfSSL header.
  add_defines("WOLFSSL_USER_SETTINGS")
  -- CHERIoT SDK defines maxalign_t; standard C11 uses max_align_t.
  add_defines("max_align_t=maxalign_t")
  -- Suppress warnings from wolfSSL third-party source that are not actionable:
  --   -Wignored-attributes: wolfSSL's fallback thread platform sets
  --     WOLFSSL_THREAD to __stdcall, which is silently ignored on RISC-V.
  --   -Watomic-alignment: wolfSSL uses volatile int (not _Atomic) for its
  --     atomic ref-counts; clang warns the 4-byte operations may not be
  --     lock-free on this target.
  add_cxflags("-Wno-ignored-attributes", "-Wno-atomic-alignment", "-Wno-parentheses-equality", "-Wno-tautological-compare", {force = true})
  add_defines("CHERIOT_NO_AMBIENT_MALLOC", "CHERIOT_NO_NEW_DELETE")
  
  -- Include paths:
  --   "."                                 → user_settings.h (this dir)
  --   "../../include"                     → NetAPI.h etc (network-stack public headers)
  --   "../../third_party/wolfssl"         → <wolfssl/ssl.h>, <wolfssl/wolfcrypt/...>
  add_includedirs(
    ".",
    "../../include",
    "../../third_party/wolfssl")

  add_deps("NetAPI", "SNTP", "time_helpers", "atomiccap")
  add_files("wolfssl_glue.cc", "wolfssl_time.c", "tls_wolfssl.cc")

  -- wolfssl/src - TLS Bit
  add_files(
    "../../third_party/wolfssl/src/ssl.c",
    "../../third_party/wolfssl/src/ssl_api_cert.c",
    "../../third_party/wolfssl/src/ssl_api_crl_ocsp.c",
    "../../third_party/wolfssl/src/ssl_api_pk.c",
    "../../third_party/wolfssl/src/ssl_asn1.c",
    "../../third_party/wolfssl/src/ssl_bn.c",
    "../../third_party/wolfssl/src/ssl_certman.c",
    "../../third_party/wolfssl/src/ssl_crypto.c",
    "../../third_party/wolfssl/src/ssl_load.c",
    "../../third_party/wolfssl/src/ssl_misc.c",
    "../../third_party/wolfssl/src/ssl_sess.c",
    "../../third_party/wolfssl/src/ssl_sk.c")
  add_files(
    "../../third_party/wolfssl/src/bio.c",
    "../../third_party/wolfssl/src/internal.c",
    "../../third_party/wolfssl/src/keys.c",
    "../../third_party/wolfssl/src/tls.c",
    "../../third_party/wolfssl/src/tls13.c",
    "../../third_party/wolfssl/src/wolfio.c",
    "../../third_party/wolfssl/src/x509.c",
    "../../third_party/wolfssl/src/x509_str.c",
    "../../third_party/wolfssl/src/pk.c",
    "../../third_party/wolfssl/src/pk_ec.c",
    "../../third_party/wolfssl/src/pk_rsa.c",
    "../../third_party/wolfssl/src/ocsp.c",
    "../../third_party/wolfssl/src/crl.c")

  -- wolfcrypt/src - crypto primitives
  add_files(
    "../../third_party/wolfssl/wolfcrypt/src/aes.c",
    "../../third_party/wolfssl/wolfcrypt/src/sha.c",
    "../../third_party/wolfssl/wolfcrypt/src/sha256.c",
    "../../third_party/wolfssl/wolfcrypt/src/sha512.c",
    "../../third_party/wolfssl/wolfcrypt/src/hmac.c",
    "../../third_party/wolfssl/wolfcrypt/src/hash.c",
    "../../third_party/wolfssl/wolfcrypt/src/kdf.c",
    "../../third_party/wolfssl/wolfcrypt/src/random.c",
    "../../third_party/wolfssl/wolfcrypt/src/md5.c")
  add_files(
    "../../third_party/wolfssl/wolfcrypt/src/asn.c",
    "../../third_party/wolfssl/wolfcrypt/src/coding.c",
    "../../third_party/wolfssl/wolfcrypt/src/logging.c",
    "../../third_party/wolfssl/wolfcrypt/src/memory.c",
    "../../third_party/wolfssl/wolfcrypt/src/misc.c",
    "../../third_party/wolfssl/wolfcrypt/src/error.c",
    "../../third_party/wolfssl/wolfcrypt/src/wc_port.c",
    "../../third_party/wolfssl/wolfcrypt/src/wc_encrypt.c",
    "../../third_party/wolfssl/wolfcrypt/src/signature.c",
    "../../third_party/wolfssl/wolfcrypt/src/cryptocb.c")
  add_files(
    "../../third_party/wolfssl/wolfcrypt/src/ecc.c",
    "../../third_party/wolfssl/wolfcrypt/src/rsa.c",
    "../../third_party/wolfssl/wolfcrypt/src/dh.c",
    "../../third_party/wolfssl/wolfcrypt/src/sp_int.c",
    "../../third_party/wolfssl/wolfcrypt/src/sp_c32.c",
    "../../third_party/wolfssl/wolfcrypt/src/sp_c64.c",
    "../../third_party/wolfssl/wolfcrypt/src/wolfmath.c")
  add_files(
    "../../third_party/wolfssl/wolfcrypt/src/chacha.c",
    "../../third_party/wolfssl/wolfcrypt/src/poly1305.c",
    "../../third_party/wolfssl/wolfcrypt/src/chacha20_poly1305.c",
    "../../third_party/wolfssl/wolfcrypt/src/curve25519.c",
    "../../third_party/wolfssl/wolfcrypt/src/ed25519.c",
    "../../third_party/wolfssl/wolfcrypt/src/fe_operations.c",
    "../../third_party/wolfssl/wolfcrypt/src/ge_operations.c",
    "../../third_party/wolfssl/wolfcrypt/src/cmac.c")
