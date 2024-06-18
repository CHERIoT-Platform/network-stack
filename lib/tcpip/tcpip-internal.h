// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include <FreeRTOS_IP.h>
#include <ds/linked_list.h>
#include <locks.hh>
#include "../firewall/firewall.h"

/**
 * Internal helpers and data structures for use inside of the TCP/IP
 * compartment. These should be called or used only from/in the TCP/IP
 * compartment.
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

static_assert(RestartStateDriverKickedBit == DriverKicked);

using ChunkFreeLink = ds::linked_list::cell::Pointer;

/**
 * The sealed wrapper around a FreeRTOS socket.
 *
 * These sealed wrappers are part of a doubly linked list which is used by the
 * compartment reset code to reset locks and other per-socket structures.
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
	/**
	 * Link into the sealed sockets doubly-linked list.
	 */
	ChunkFreeLink      ring __attribute__((__cheri_no_subobject_bounds__)) = {};
	/**
	 * Container-of for the above field. This is used to retrieve the
	 * corresponding sealed socket from a list element.
	 */
	__always_inline static struct SealedSocket *from_ring(ChunkFreeLink *c)
	{
		return reinterpret_cast<struct SealedSocket *>(
		  reinterpret_cast<uintptr_t>(c) - offsetof(struct SealedSocket, ring));
	}
};

extern FlagLockPriorityInherited                sealedSocketsListLock;
extern ds::linked_list::Sentinel<ChunkFreeLink> sealedSockets;
extern std::atomic<uint32_t>                    restartState;
extern std::atomic<uint8_t>                     userThreadCount;

/**
 * Helper to run a function ensuring that the thread counters are updated
 * appropriately. Every entry point of the TCP/IP stack API (with the exception
 * of the driver thread, see below) should go through this unless it
 * manipulates `userThreadCount` manually.
 */
auto with_restarting_checks(auto operation, auto errorValue)
{
	if (restartState.load() != 0)
	{
		// yield to give a chance to the restart code to make some
		// progress, in case applications are aggressively trying to
		// re-open the socket.
		yield();
		return errorValue;
	}
	userThreadCount++;
	auto ret = operation();
	userThreadCount--;
	return ret;
}

/**
 * Similar to `with_restarting_checks`, but for the driver thread.
 *
 * The compartment API entry points exposed to the firewall can only be called
 * by the firewall, and we trust the firewall not to call us at inappropriate
 * times during a restart. The firewall has access to `restartState` and knows
 * when not to call - if it does call at an inapproriate time during reset,
 * this is a firewall bug. Thus, do not check `restartState` here.
 */
auto with_restarting_checks_driver(auto operation, auto errorValue)
{
	userThreadCount++;
	auto ret = operation();
	userThreadCount--;
	return ret;
}
