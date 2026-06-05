// Copyright The Good Penguin Ltd
// SPDX-License-Identifier: MIT
// Keeps track of time using SNTP derived time
#include <sntp.h>

long cheriot_wolfssl_time(long *tloc)
{
    struct timeval tv;
    timeval_calculate(&tv);
    long t = (long)tv.tv_sec;
    if (tloc)
        *tloc = t;
    return t;
}
