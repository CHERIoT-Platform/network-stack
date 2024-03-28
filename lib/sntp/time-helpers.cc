// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <compartment-macros.h>
#include <cstdint>
#include <debug.hh>
#include <futex.h>
#include <riscvreg.h>
#include <sntp.h>

using Debug = ConditionalDebug<false, "Time helper">;

int timeval_calculate(struct timeval *__restrict tp,
                      struct SynchronisedTime **sntpTimeCache)
{
	struct SynchronisedTime *sntpTime = *sntpTimeCache;
	if (sntpTime == nullptr)
	{
		sntpTime       = sntp_time_get();
		*sntpTimeCache = sntpTime;
		Debug::log("Got SNTP time {}", sntpTime);
	}
	if (sntpTime == nullptr)
	{
		Debug::log("Failed to get SNTP time");
		return -ENODEV;
	}
	struct timeval time;
	uint64_t       cycles;
	uint32_t       epoch;
	do
	{
		epoch = atomic_load(&sntpTime->updatingEpoch);
		// If the low bit is set then the time is being updated.  Wait for the
		// update to finish.
		if (epoch & 0x1)
		{
			Debug::log("Waiting for SNTP update");
			// Wait for the update to finish
			sntpTime->updatingEpoch.wait(epoch);
			continue;
		}
		time   = sntpTime->time;
		cycles = sntpTime->cycles;
	} while ((epoch & 0x1) || epoch != atomic_load(&sntpTime->updatingEpoch));
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
	time.tv_usec = usec;
	*tp          = time;
	return 0;
}
