// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include <FreeRTOS_IP.h>
#include <ds/linked_list.h>
#include <locks.hh>
/**
 * Internal helpers for use inside of the TCP/IP compartment.
 * These should be called only from the TCP/IP compartment.
 */

/**
 * Flags for the state of restart.
 */
enum [[clang::flag_enum]] RestartState{
  NotRestarting  = 0,
  Restarting     = 1,
  IpThreadKicked = 2,
  DriverKicked   = 4,
};

using ChunkFreeLink = ds::linked_list::cell::PtrAddr;

/**
 * The sealed wrapper around a FreeRTOS socket.
 */
struct SealedSocket
{
	/**
	 * Socket epoch. This is used to check if the socket correponds
	 * to the current instance of the network stack.
	 */
	uint64_t socketEpoch;
	/**
	 * The lock protecting this socket.
	 */
	FlagLockPriorityInherited socketLock;
	/**
	 * The FreeRTOS socket.  It would be nice if this didn't require a
	 * separate allocation but FreeRTOS+TCP isn't designed to support that
	 * use case.
	 */
	FreeRTOS_Socket_t *socket;
	ChunkFreeLink      ring __attribute__((__cheri_no_subobject_bounds__)) = {};
	/**
	 * Container-of for the above field.
	 */
	__always_inline static struct SealedSocket *from_ring(ChunkFreeLink *c)
	{
		return reinterpret_cast<struct SealedSocket *>(
		  reinterpret_cast<uintptr_t>(c) - offsetof(struct SealedSocket, ring));
	}
};

extern ds::linked_list::Sentinel<ChunkFreeLink> sealedSockets;
extern std::atomic<uint32_t>                    restartState;
extern std::atomic<uint8_t>                     userThreadCount;

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
		return errorValue;
	}

	userThreadCount++;
	auto ret = operation();
	userThreadCount--;
	return ret;
}
