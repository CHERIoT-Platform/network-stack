#include <sntp.h>
#include <NetAPI.h>
#include <cstdlib>
#include <debug.hh>
#include <errno.h>
#include <fail-simulator-on-error.h>
#include <memory>
#include <string_view>
#include <thread.h>
#include <tick_macros.h>

using Debug            = ConditionalDebug<true, "Network test">;
constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

void __cheri_compartment("sntp_example") example()
{
	network_start();
	Timeout t{MS_TO_TICKS(5000)};
	while (sntp_update(&t) != 0)
	{
		Debug::log("Failed to update NTP time");
		Timeout oneSecond{MS_TO_TICKS(1000)};
	}
	Debug::log("Updating NTP took {} ticks", t.elapsed);
	t = UnlimitedTimeout;
	time_t lastTime = 0;
	while (true)
	{
		timeval tv;
		int     ret = gettimeofday(&tv, nullptr);
		if (ret != 0)
		{
			Debug::log("Failed to get time of day: {}", ret);
		}
		else if (lastTime != tv.tv_sec)
		{
			lastTime = tv.tv_sec;
			// Truncate the epoch time to 32 bits for printing.
			Debug::log("Current UNIX epoch time: {}", tv.tv_sec);
		}
		Timeout shortSleep{MS_TO_TICKS(50)};
		thread_sleep(&shortSleep);
	}

}
