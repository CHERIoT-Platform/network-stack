// Copyright The Good Penguin Ltd
// SPDX-License-Identifier: MIT

// CHERIoT headers first - prevents the logging.h extern-"C" +
// cheri-builtins.h template collision when wolfSSL headers follow.
#include <allocator.h>
#include <debug.hh>
#include <platform-entropy.hh>

#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#ifndef SINGLE_THREADED
#include <locks.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#endif

#include "wolfssl_glue.h"

constexpr bool DebugWolfGlue =
#ifdef DEBUG_WOLFSSLTLS
  DEBUG_WOLFSSLTLS
#else
  false
#endif
  ;

using GlueDebug = ConditionalDebug<DebugWolfGlue, "WolfGlue">;
using namespace CHERI;

extern "C"
{

// This CHERIoT EntropySource is why this is a .cc
uint64_t cheriot_wolfssl_get_entropy()
{
    static EntropySource source;
    return source();
}

// Seed callback - called by wolfSSL DRBG via CUSTOM_RAND_GENERATE_SEED.
int cheriot_wolfssl_seed(unsigned char *output, unsigned int sz)
{
    unsigned int i = 0;
    while (i < sz)
    {
        uint64_t     e     = cheriot_wolfssl_get_entropy();
        unsigned int chunk = sz - i < 8 ? sz - i : 8;
        memcpy(output + i, &e, chunk);
        i += chunk;
    }
    return 0;
}

// When WOLFSSL_SMALL_STACK is enabled wolfSSL generates many XMALLOC calls 
// with a NULL heap hint. A fallback heap bridges those call sites.
// When disabled every caller must supply a valid heap pointer.
#if defined(WOLFSSL_SMALL_STACK)
static AllocatorCapability fallbackHeap;

void wolfssl_set_fallback_heap(void *heap)
{
    fallbackHeap = (AllocatorCapability)heap;
}
#endif

void *XMALLOC(size_t n, void *heap, int type)
{
    (void)type;
    if (n == 0)
        return NULL;
    if (heap == NULL)
    {
#if defined(WOLFSSL_SMALL_STACK)
        GlueDebug::log(
            "XMALLOC: NULL heap n={} type={} using fallback", 
            n, 
            type);
        heap = fallbackHeap;
#else
        GlueDebug::log(
            "XMALLOC: NULL heap n={} type={} - caller must provide heap", 
            n, 
            type);
        return NULL;
#endif
    }
    AllocatorCapability cap = (AllocatorCapability)heap;
    if (!Capability{cap}.is_valid())
    {
        GlueDebug::log("XMALLOC: untagged heap cap n={} heap=0x{:x}",
                       n, (uintptr_t)heap);
        return NULL;
    }
    Timeout t   = {0, 0};
    void   *ptr = heap_allocate(
        &t, 
        cap, 
        n, 
        AllocateWaitNone);
    if (!Capability{ptr}.is_valid())
        GlueDebug::log("XMALLOC: allocation failed n={}", n);
    return Capability{ptr}.is_valid() ? ptr : NULL;
}

void XFREE(void *p, void *heap, int type)
{
    (void)type;
    if (p == NULL)
        return;
    if (heap == NULL)
    {
#if defined(WOLFSSL_SMALL_STACK)
        GlueDebug::log("XFREE: NULL heap p={} using fallback", p);
        heap = fallbackHeap;
#else
        GlueDebug::log(
            "XFREE: NULL heap p={} - caller must provide heap", 
            p);
        return;
#endif
    }
    AllocatorCapability cap = (AllocatorCapability)heap;
    if (!Capability{cap}.is_valid())
    {
        GlueDebug::log("XFREE: untagged heap cap p={}", p);
        return;
    }
    heap_free(cap, p);
}

void *XREALLOC(void *p, size_t n, void *heap, int type)
{
    (void)type;
    if (n == 0)
        return NULL;
    if (heap == NULL)
    {
#if defined(WOLFSSL_SMALL_STACK)
        GlueDebug::log("XREALLOC: NULL heap p={} n={} using fallback", p, n);
        heap = fallbackHeap;
#else
        GlueDebug::log(
            "XREALLOC: NULL heap p={} n={} - caller must provide heap", 
            p, 
            n);
        return NULL;
#endif
    }
    AllocatorCapability cap = (AllocatorCapability)heap;
    if (!Capability{cap}.is_valid())
    {
        GlueDebug::log("XREALLOC: untagged cap p={} n={}", p, n);
        return NULL;
    }
    Timeout t      = {0, 0};
    void   *newptr = heap_allocate(
        &t, 
        cap, 
        n, 
        AllocateWaitNone);
    if (!Capability{newptr}.is_valid())
        return NULL;
    if (p != NULL)
    {
        size_t oldSize = Capability{p}.length();
        memcpy(newptr, p, oldSize < n ? oldSize : n);
        heap_free(cap, p);
    }
    return newptr;
}

int cheriot_wolfssl_strcasecmp(const char *s1, const char *s2) {
    unsigned char a, b;
    do {
        a = (unsigned char)*s1++;
        b = (unsigned char)*s2++;
        if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
        if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
    } while (a && a == b);
    return (int)a - (int)b;
}

int cheriot_wolfssl_strncasecmp(const char *s1, const char *s2, unsigned int n) {
    while (n--) {
        unsigned char a = (unsigned char)*s1++;
        unsigned char b = (unsigned char)*s2++;
        if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
        if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
        if (a != b) return (int)a - (int)b;
        if (!a) break;
    }
    return 0;
}

char *cheriot_wolfssl_strncat(char *dst, const char *src, unsigned int n) {
    char *d = dst;
    while (*d) d++;
    while (n-- && *src) *d++ = *src++;
    *d = '\0';
    return dst;
}

int cheriot_wolfssl_atoi(const char *s) {
    int result = 0, sign = 1;
    while (*s == ' ' || *s == '\t') s++;
    if (*s == '-') { sign = -1; s++; }
    else if (*s == '+') s++;
    while (*s >= '0' && *s <= '9')
        result = result * 10 + (*s++ - '0');
    return sign * result;
}

#ifndef SINGLE_THREADED
int wc_InitMutex(wolfSSL_Mutex *m)
{
    m->lockWord = 0;
    return 0;
}

int wc_FreeMutex(wolfSSL_Mutex *m)
{
    (void)m;
    return 0;
}

int wc_LockMutex(wolfSSL_Mutex *m)
{
    Timeout t{UnlimitedTimeout};
    auto *s = reinterpret_cast<FlagLockState *>(m);
    return flaglock_priority_inheriting_trylock(&t, s) == 0 ? 0 : BAD_MUTEX_E;
}

int wc_UnLockMutex(wolfSSL_Mutex *m)
{
    flaglock_unlock(reinterpret_cast<FlagLockState *>(m));
    return 0;
}
#endif // !SINGLE_THREADED

} // extern "C"
