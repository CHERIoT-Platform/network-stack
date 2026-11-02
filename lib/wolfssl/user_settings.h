// Copyright The Good Penguin Ltd
// SPDX-License-Identifier: MIT
//
// Based on wolfSSL examples/configs/user_settings_template.h
//
// Algorithm/feature selections follow the template defaults
// CHERIoT platform-porting changes are applied

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CHERIoT is always an embedded target */
#define TARGET_EMBEDDED

/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_GENERAL_ALIGNMENT 8  /* CHERIoT capabilities are 8-byte aligned */
#define SIZEOF_LONG_LONG 8
/* Otherwise wc_ptr_t becomes size_t and causes issues with round-trip casts*/
#define HAVE_UINTPTR_T 
#if 0 /* Disable 64-bit types */
    #define NO_64BIT
#endif

#ifdef TARGET_EMBEDDED
    /* Controlled via xmake option "wolfssl-single-threaded" (default off).
     * When off: WOLFSSL_USER_MUTEX suppresses the pthreads fallback in wc_port.h.
     *           wolfssl_glue.cc provides the wc_*Mutex implementations.
     * When on:  wolfSSL compiles its own no-op mutex stubs. Safe only when the
     *           WolfSSLTLS compartment is called from a single thread at a time. */
    #ifndef SINGLE_THREADED
        #define WOLFSSL_USER_MUTEX
        typedef struct { uint32_t lockWord; } wolfSSL_Mutex;
    #endif

    /* Controlled via xmake option "wolfssl-small-stack" (default off).
     * When on:  Per-function crypto buffers are allocated on the heap via XMALLOC.
     *           wolfssl_glue provides a fallback heap for the NULL heap hints this generates;
     *           wolfssl_set_fallback_heap() must be called before use.
     * When off: all XMALLOC callers must pass a valid heap pointer; NULL heap
     *           is an error and returns NULL immediately. */
     //#define WOLFSSL_SMALL_STACK

    /* Force ASN template setters (GetASN_Int8Bit, GetASN_Buffer, etc.) to
       allocate onto the stack. Otherwise, these store stack derived 
       pointers on the heap which will cause a tag violation on CHERIoT. 
       Only comes into play if WOLFSSL_SMALL_STACK is defined.
    */
    #define WOLFSSL_ASN_TEMPLATE_STACK_ALLOC

    /* Disable the built-in socket support and use the IO callbacks.
     * Set IO callbacks with wolfSSL_CTX_SetIORecv/wolfSSL_CTX_SetIOSend
     */
    #define WOLFSSL_USER_IO

    /* No BSD socket glue on CHERIoT */
    #define WOLFSSL_NO_SOCK
#endif

/* ------------------------------------------------------------------------- */
/* Math Configuration */
/* ------------------------------------------------------------------------- */
/* Wolf Single Precision Math */
#if 1 /* SP Math (recommended) */
    #define WOLFSSL_HAVE_SP_RSA
    #define WOLFSSL_HAVE_SP_DH
    #define WOLFSSL_HAVE_SP_ECC
    //#define WOLFSSL_SP_4096 /* Enable RSA/RH 4096-bit support */
    #define WOLFSSL_SP_384  /* Enable ECC 384-bit SECP384R1 support */

    //#define WOLFSSL_SP_MATH     /* only SP math - disables integer.c/tfm.c */
    #define WOLFSSL_SP_MATH_ALL /* use SP math for all key sizes and curves */

    //#define WOLFSSL_SP_NO_MALLOC
    //#define WOLFSSL_SP_DIV_32 /* do not use 64-bit divides */

    #ifdef TARGET_EMBEDDED
        /* use smaller version of code */
        #define WOLFSSL_SP_SMALL
    #endif

    /* CHERIoT target is RISC-V 32-bit */
    //#define SP_WORD_SIZE 32

    /* SP Assembly Speedups - specific to chip type */
    //#define WOLFSSL_SP_ASM
    //#define WOLFSSL_SP_X86_64
    //#define WOLFSSL_SP_X86
    //#define WOLFSSL_SP_ARM32_ASM
    //#define WOLFSSL_SP_ARM64_ASM
    //#define WOLFSSL_SP_ARM_THUMB_ASM
    //#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#elif 1
    /* Fast Math (tfm.c) (stack based and timing resistant) */
    #define USE_FAST_MATH
    #define TFM_TIMING_RESISTANT
#else
    /* Normal (integer.c) (heap based, not timing resistant) - not recommended */
    #define USE_INTEGER_HEAP_MATH
#endif


/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* RSA */
#undef NO_RSA
#if 1 /* RSA */
    #ifdef USE_FAST_MATH
        /* Maximum math bits (Max RSA key bits * 2) */
        #define FP_MAX_BITS 4096
    #endif

    /* half as much memory but twice as slow */
    //#define RSA_LOW_MEM

    /* Enables blinding mode, to prevent timing attacks */
    #define WC_RSA_BLINDING

    /* RSA PSS Support */
    #define WC_RSA_PSS
#else
    #define NO_RSA
#endif

/* DH */
#undef  NO_DH
#if 1 /* DH */
    /* Use table for DH instead of -lm (math) lib */
    #if 1 /* FFDHE parameters */
        #define WOLFSSL_DH_CONST
        #define HAVE_FFDHE_2048
        //#define HAVE_FFDHE_4096
        //#define HAVE_FFDHE_6144
        //#define HAVE_FFDHE_8192
    #endif
#else
    #define NO_DH
#endif

/* ECC */
#undef HAVE_ECC
#if 1 /* ECC */
    #define HAVE_ECC

    /* Manually define enabled curves */
    #define ECC_USER_CURVES

    #ifdef ECC_USER_CURVES
        /* Manual Curve Selection */
        //#define HAVE_ECC192
        //#define HAVE_ECC224
        #undef NO_ECC256
        #define HAVE_ECC384
        //#define HAVE_ECC521
    #endif

    /* Fixed point cache (speeds repeated operations against same private key) */
    //#define FP_ECC
    #ifdef FP_ECC
        /* Bits / Entries */
        #define FP_ENTRIES  2
        #define FP_LUT      4
    #endif

    /* Optional ECC calculation method */
    /* Note: doubles heap usage, but slightly faster */
    #define ECC_SHAMIR

    /* Reduces heap usage, but slower */
    #define ECC_TIMING_RESISTANT

    /* Compressed ECC Key Support */
    //#define HAVE_COMP_KEY

    /* Use alternate ECC size for ECC math */
    #ifdef USE_FAST_MATH
        /* MAX ECC BITS = ROUND8(MAX ECC) * 2 */
        #if defined(NO_RSA) && defined(NO_DH)
            /* Custom fastmath size if not using RSA/DH */
            #define FP_MAX_BITS     (256 * 2)
        #else
            /* use heap allocation for ECC points */
            #define ALT_ECC_SIZE

            /* wolfSSL will compute the FP_MAX_BITS_ECC, but it can be overridden */
            //#define FP_MAX_BITS_ECC (256 * 2)
        #endif

        /* Speedups specific to curve */
        #ifndef NO_ECC256
            #define TFM_ECC256
        #endif
    #endif
#endif


/* AES */
#undef NO_AES
#if 1 /* AES */
    #define HAVE_AES_CBC

    /* GCM Method: GCM_TABLE_4BIT, GCM_SMALL, GCM_WORD32 or GCM_TABLE */
    #define HAVE_AESGCM
    #ifdef TARGET_EMBEDDED
        #define GCM_SMALL
    #else
        #define GCM_TABLE_4BIT
    #endif

    //#define WOLFSSL_AES_DIRECT
    //#define HAVE_AES_ECB
    //#define WOLFSSL_AES_COUNTER
    //#define HAVE_AESCCM
#else
    #define NO_AES
#endif


/* DES3 */
#undef NO_DES3
#if 0 /* DES3 (legacy, not recommended) */
#else
    #define NO_DES3
#endif

/* ChaCha20 / Poly1305 */
#undef HAVE_CHACHA
#undef HAVE_POLY1305
#if 1 /* ChaCha20 / Poly1305 */
    #define HAVE_CHACHA
    #define HAVE_POLY1305

    /* Needed for Poly1305 */
    #define HAVE_ONE_TIME_AUTH
#endif

/* Ed25519 / Curve25519 */
#undef HAVE_CURVE25519
#undef HAVE_ED25519
#if 0 /* Ed25519 / Curve25519 */
    #define HAVE_CURVE25519
    #define HAVE_ED25519 /* ED25519 Requires SHA512 */

    /* Optionally use small math (less flash, slower) */
    #if 1 /* Small Curve25519 */
        #define CURVED25519_SMALL
    #endif
#endif


/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */
/* Sha */
#undef NO_SHA
#if 1 /* SHA-1 */
    /* 1k smaller, but 25% slower */
    //#define USE_SLOW_SHA
#else
    #define NO_SHA
#endif

/* Sha256 */
#undef NO_SHA256
#if 1 /* SHA-256 */
    /* not unrolled - ~2k smaller and ~25% slower */
    //#define USE_SLOW_SHA256

    /* SHA-224 (requires SHA-256) */
    #if 0 /* SHA-224 */
        #define WOLFSSL_SHA224
    #endif
#else
    #define NO_SHA256
#endif

/* Sha512 */
#undef WOLFSSL_SHA512
#if 1
    #define WOLFSSL_SHA512

    /* SHA-384 (requires SHA-512) */
    #undef  WOLFSSL_SHA384
    #if 1 /* SHA-384 */
        #define WOLFSSL_SHA384
    #endif

    /* over twice as small, but 50% slower */
    //#define USE_SLOW_SHA512
#endif

/* Sha3 */
#undef WOLFSSL_SHA3
#if 0 /* SHA-3 */
    #define WOLFSSL_SHA3
#endif

/* MD5 */
#undef  NO_MD5
#if 0 /* MD5 (legacy, not recommended) */
    /* MD5 enabled */
#else
    #define NO_MD5
#endif

/* HKDF */
#undef HAVE_HKDF
#if 1 /* HKDF (TLS 1.3 requires this) */
    #define HAVE_HKDF
#endif

/* CMAC */
#undef WOLFSSL_CMAC
#if 0 /* CMAC */
    #define WOLFSSL_CMAC
#endif


/* ------------------------------------------------------------------------- */
/* Benchmark / Test */
/* ------------------------------------------------------------------------- */
#ifdef TARGET_EMBEDDED
    /* Use reduced benchmark / test sizes */
    #define BENCH_EMBEDDED
#endif

/* Use test buffers from array (not filesystem) */
#ifndef NO_FILESYSTEM
#define USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_2048
#endif

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */

#undef DEBUG_WOLFSSL
#undef NO_ERROR_STRINGS
#if 0 /* Enable debug logging */
    #define DEBUG_WOLFSSL
#else
    #if 0 /* Disable error strings to save flash */
        #define NO_ERROR_STRINGS
    #endif
#endif


/* ------------------------------------------------------------------------- */
/* Memory */
/* ------------------------------------------------------------------------- */

/* CHERIoT custom allocators - XMALLOC/XFREE/XREALLOC in wolfssl_glue.cc
 * use the void* heap hint (caller's AllocatorCapability cast to void*) to
 * call heap_allocate/heap_free. */
#define XMALLOC_USER

#if 0 /* Static memory (no heap) */
    #define WOLFSSL_STATIC_MEMORY

    /* Disable fallback malloc/free */
    #define WOLFSSL_NO_MALLOC
    #if 1 /* Trap malloc failure */
        #define WOLFSSL_MALLOC_CHECK /* trap malloc failure */
    #endif
#endif

/* Memory callbacks */
#if 0 /* wolfSSL memory callbacks */
    #undef  USE_WOLFSSL_MEMORY
    #define USE_WOLFSSL_MEMORY

    /* Use this to measure / print heap usage */
    #if 0 /* Memory tracking / debug */
        #define WOLFSSL_TRACK_MEMORY
        #define WOLFSSL_DEBUG_MEMORY
    #endif
#else
    #ifndef WOLFSSL_STATIC_MEMORY
        #define NO_WOLFSSL_MEMORY
        /* Otherwise we will use stdlib malloc, free and realloc */
    #endif
#endif


/* ------------------------------------------------------------------------- */
/* Port */
/* ------------------------------------------------------------------------- */

/* CHERIoT custom time function */
#define USER_TIME
#define XTIME(t)      cheriot_wolfssl_time(t)
#define XGMTIME(c, t) gmtime(c)


/* ------------------------------------------------------------------------- */
/* RNG */
/* ------------------------------------------------------------------------- */

/* P-RNG with hash DRBG seeded by CHERIoT entropy source */
extern int cheriot_wolfssl_seed(unsigned char *output, unsigned int sz);
#undef  CUSTOM_RAND_GENERATE_SEED
#define CUSTOM_RAND_GENERATE_SEED cheriot_wolfssl_seed

#undef  HAVE_HASHDRBG
#define HAVE_HASHDRBG


/* ------------------------------------------------------------------------- */
/* Custom Standard Lib */
/* ------------------------------------------------------------------------- */
/* STRING_USER: take ownership of ALL wolfSSL string/memory macros.
 * types.h defines XSTRNCAT unconditionally (no #ifndef guard) inside the
 * #ifndef STRING_USER block, overriding any earlier definition. The only
 * correct way to prevent that is STRING_USER. */
#define STRING_USER

#include <string.h>

/* Memory, all available in CHERIoT freestanding string.h */
#define XMEMCPY(d,s,l)    memcpy((d),(s),(l))
#define XMEMSET(b,c,l)    memset((b),(c),(l))
#define XMEMCMP(s1,s2,n)  memcmp((s1),(s2),(n))
#define XMEMMOVE(d,s,l)   memmove((d),(s),(l))

/* String basics, all available in CHERIoT freestanding string.h */
#define XSTRLEN(s1)       strlen((s1))
#define XSTRNCPY(s1,s2,n) strncpy((s1),(s2),(n))
#define XSTRSTR(s1,s2)    strstr((s1),(s2))
#define XSTRNSTR(s1,s2,n) strnstr((s1),(s2),(n))
#define XSTRNCMP(s1,s2,n) strncmp((s1),(s2),(n))
#define XSTRCMP(s1,s2)    strcmp((s1),(s2))

/* strncat absent from CHERIoT freestanding libc - provided in wolfssl_glue.cc */
extern char *cheriot_wolfssl_strncat(char *dst, const char *src, unsigned int n);
#define XSTRNCAT(s1,s2,n) cheriot_wolfssl_strncat((s1),(s2),(n))

/* strsep/strtok use wolfSSL's own implementations */
#define USE_WOLF_STRSEP
#define USE_WOLF_STRTOK
#define XSTRSEP(s1,d)         wc_strsep((s1),(d))
#define XSTRTOK(s1,d,ptr)     wc_strtok((s1),(d),(ptr))

/* strcasecmp / strncasecmp absent from CHERIoT freestanding libc - wolfssl_glue.cc */
extern int cheriot_wolfssl_strcasecmp(const char *s1, const char *s2);
#define XSTRCASECMP(s1,s2)    cheriot_wolfssl_strcasecmp((s1),(s2))
extern int cheriot_wolfssl_strncasecmp(const char *s1, const char *s2, unsigned int n);
#define XSTRNCASECMP(s1,s2,n) cheriot_wolfssl_strncasecmp((s1),(s2),(n))

/* atoi absent from CHERIoT freestanding libc - provided in wolfssl_glue.cc */
extern int cheriot_wolfssl_atoi(const char *s);
#define XATOI(s) cheriot_wolfssl_atoi((s))

#define XSNPRINTF snprintf

/* No <stdatomic.h> in CHERIoT environment sp block the stdatomic include path */
#define NO_STDATOMIC_H

/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */

#define WOLFSSL_TLS13
#define WOLFSSL_OLD_PRIME_CHECK /* Use faster DH prime checking */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SNI
#define HAVE_SUPPORTED_CURVES
#define WOLFSSL_BASE64_ENCODE

//#define WOLFSSL_KEY_GEN /* For RSA Key gen only */
//#define KEEP_PEER_CERT
//#define HAVE_COMP_KEY

/* TLS Session Cache */
#if 0 /* Small session cache */
    #define SMALL_SESSION_CACHE
#else
    #define NO_SESSION_CACHE
#endif

/* Store cipher-suite names as char[] arrays rather than const char* pointers.
 * The CHERIoT LLVM backend cannot initialise a global array of capability
 * pointers at link time; this avoids the resulting crash on cipher lookup. */
#define WOLFSSL_NAMES_STATIC

/* Keep SHA-256 message schedule on the stack to avoid XMALLOC round-trips. */
#define SHA256_MANY_REGISTERS


/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
//#define NO_WOLFSSL_SERVER
//#define NO_WOLFSSL_CLIENT
//#define NO_CRYPT_TEST
//#define NO_CRYPT_BENCHMARK
//#define WOLFCRYPT_ONLY

/* do not warn when file is included to be built and not required to be */
#define WOLFSSL_IGNORE_FILE_WARN

/* In-lining of misc.c functions */
/* If defined, must include wolfcrypt/src/misc.c in build */
/* Slower, but about 1k smaller */
//#define NO_INLINE

#ifdef TARGET_EMBEDDED
    #define NO_FILESYSTEM
    #define NO_WRITEV
    #define NO_MAIN_DRIVER
    #define NO_DEV_RANDOM
#endif

/* CHERIoT has no stdio filesystem */
#define NO_STDIO_FILESYSTEM

#define NO_OLD_TLS
#define NO_PSK

#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_PWDBASED
//#define NO_CODING
//#define NO_ASN_TIME
//#define NO_CERTS
//#define NO_SIG_WRAPPER

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
