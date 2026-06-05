// Copyright The Good Penguin Ltd
// SPDX-License-Identifier: MIT

#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Required to provide some random seed / entropy source to wolfssl
int cheriot_wolfssl_seed(unsigned char *output, unsigned int sz);

int cheriot_wolfssl_strcasecmp(const char *s1, const char *s2);

long cheriot_wolfssl_time(long *tloc);

#if defined(WOLFSSL_SMALL_STACK)
// Fallback heap for callers that pass a NULL heap hint.
// Required when WOLFSSL_SMALL_STACK is enabled (xmake option wolfssl-small-stack).
void wolfssl_set_fallback_heap(void *heap);
#else
// No-op when WOLFSSL_SMALL_STACK is disabled: all heap hints are explicit so there is nothing to fall back to.
static inline void wolfssl_set_fallback_heap(void *heap) { (void)heap; }
#endif


#ifdef __cplusplus
}
#endif
