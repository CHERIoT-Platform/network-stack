// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
/**
 * Internal helpers for use inside of the TCP/IP compartment.
 * These should be called only from the TCP/IP compartment.
 */

/**
 * Flags for the state of restart.
 */
enum [[clang::flag_enum]] RestartState{
  NotRestarting   = 0,
  Restarting      = 1,
  IpThreadKicked  = 2,
  DriverKicked    = 4,
};

extern std::atomic<uint32_t> restartState;
extern std::atomic<uint8_t> userThreadCount;

/**
 * Helper to run a function ensuring that the thread counters are
 * updated appropriately.
 */
auto with_restarting_checks(auto operation, auto errorValue)
{
	if (restartState.load() != 0)
	{
		yield();
		return errorValue;
	}

	userThreadCount++;
	auto ret = operation();
	userThreadCount--;
	return ret;
}

auto with_restarting_checks_driver(auto operation, auto errorValue)
{
	uint32_t state = restartState.load();
	if ((state != 0) && ((state & DriverKicked) == 0))
	{
		// We are restarting and the driver isn't yet supposed to send
		// packets.
		yield();
		return errorValue;
	}

	userThreadCount++;
	auto ret = operation();
	userThreadCount--;
	return ret;
}
