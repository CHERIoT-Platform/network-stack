#pragma once
// Don't try to do clang-tidy on this file if it won't compile.
#if __has_include(<sys/time.h>)
#	include <platform/concepts/wall_clock_source.hh>
#	include <sys/time.h>
#	include <time.h>

/**
 * Fetch the time with SNTP and return the result in `outTime`.
 */
int __cheri_compartment("SNTP") sntp_update(TimeoutArgument timeout,
                                            clock_t        &outTime,
                                            clock_t        &outMonotonicTime);

struct SNTPWallClockSource
{
	/// SNTP fetches the time, it does not set it.
	static constexpr bool SupportsTimeSetting = false;
	/// SNTP requires network fetches, it is not cheap.
	static constexpr bool IsCheap = false;

	inline int get_time(TimeoutArgument timeout,
	                    clock_t        &outRealTime,
	                    clock_t        &outMonotonicTime,
	                    int            &outPriority)
	{
		outPriority = 1000;
		return sntp_update(timeout, outRealTime, outMonotonicTime);
	}
};

static_assert(IsWallClockSource<SNTPWallClockSource>,
              "The SNTP wall-clock source must implement the required concept");
#endif
