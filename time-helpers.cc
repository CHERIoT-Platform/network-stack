#include "cdefs.h"
#include "sntp.h"
#include <compartment-macros.h>
#include <cstdint>
#include <debug.hh>
#include <futex.h>
#include <riscvreg.h>

using Debug = ConditionalDebug<false, "Time helper">;

int timeval_calculate(struct timeval *__restrict tp,
                      struct SynchronisedTime **sntp_time_cache)
{
	struct SynchronisedTime *sntp_time = *sntp_time_cache;
	if (sntp_time == NULL)
	{
		sntp_time        = sntp_time_get();
		*sntp_time_cache = sntp_time;
		Debug::log("Got SNTP time {}", sntp_time);
	}
	if (sntp_time == NULL)
	{
		Debug::log("Failed to get SNTP time");
		return -ENODEV;
	}
	struct timeval time;
	uint64_t       cycles;
	uint32_t       epoch;
	do
	{
		epoch = atomic_load(&sntp_time->updatingEpoch);
		// If the low bit is set then the time is being updated.  Wait for the
		// update to finish.
		if (epoch & 0x1)
		{
			Debug::log("Waiting for SNTP update");
			// Wait for the update to finish
			futex_wait(reinterpret_cast<uint32_t *>(&sntp_time->updatingEpoch),
			           epoch);
			continue;
		}
		time   = sntp_time->time;
		cycles = sntp_time->cycles;
	} while (epoch != atomic_load(&sntp_time->updatingEpoch));
	Debug::log("Got raw time {}.{}", uint64_t(time.tv_sec), time.tv_usec);
	uint64_t now = rdcycle64();
	Debug::log(
	  "Elapsed cycles {} (now: {}, timestamp: {}", now - cycles, now, cycles);
	// Elapsed time in cycles
	uint64_t elapsed = now - cycles;
	// Convert to microseconds
	if (CPU_TIMER_HZ / 1000000 > 0)
	{
		elapsed /= CPU_TIMER_HZ / 1000000;
	}
	Debug::log("Adjusted elapsed microseconds {}", elapsed);
	uint64_t usec = time.tv_usec + elapsed;
	if (usec >= 1000000)
	{
		time.tv_sec += usec / 1000000;
		usec %= 1000000;
	}
	*tp = time;
	return 0;
}
