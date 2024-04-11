// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
/**
 * Internal helpers for use inside of the TCP/IP compartment.
 * These should be called only from the TCP/IP compartment.
 */

extern std::atomic<bool>    currentlyRestarting;
extern std::atomic<bool>    kickDriver;
extern std::atomic<uint8_t> userThreadCount;

/**
 * Helper to run a function ensuring that the thread counters are
 * updated appropriately.
 */
auto with_restarting_checks(auto operation, auto errorValue)
{
	if (currentlyRestarting.load() == true)
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
	if ((currentlyRestarting.load() == true) && (kickDriver.load() == false))
	{
		yield();
		return errorValue;
	}

	userThreadCount++;
	auto ret = operation();
	userThreadCount--;
	return ret;
}
