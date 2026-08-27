// Copyright The Good Penguin Ltd
// SPDX-License-Identifier: MIT

// Stub timeval_calculate for firmware that doesn't include SNTP.
// Returns a monotonically increasing time derived from the cycle counter.

#include <riscvreg.h>
#include <sntp.h>
#include <tick_macros.h>

// 2026-01-01 00:00:00 UTC
static const time_t BASE_TIME = 1767225600;

int timeval_calculate(struct timeval *__restrict tp)
{
	uint64_t cycles = rdcycle64();
	tp->tv_sec      = BASE_TIME + (time_t)(cycles / CPU_TIMER_HZ);
	tp->tv_usec     = (suseconds_t)((cycles % CPU_TIMER_HZ) /
	                                (CPU_TIMER_HZ / 1000000));
	return 0;
}
