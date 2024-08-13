// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include "../firewall/firewall.hh"
#include <FreeRTOS_IP.h>
#include <ds/linked_list.h>
#include <locks.hh>

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

using SocketRingLink = ds::linked_list::cell::Pointer;

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
	SocketRingLink ring __attribute__((__cheri_no_subobject_bounds__)) = {};
	/**
	 * Container-of for the above field. This is used to retrieve the
	 * corresponding sealed socket from a list element.
	 */
	__always_inline static struct SealedSocket *from_ring(SocketRingLink *c)
	{
		return reinterpret_cast<struct SealedSocket *>(
		  reinterpret_cast<uintptr_t>(c) - offsetof(struct SealedSocket, ring));
	}
};

/**
 * Store pointers to the sealed sockets.
 *
 * This is used as part of the network stack reset to clean up sockets and
 * unblock threads waiting on message queues.
 *
 * This will be reset by the error handler, however it *is* reset-critical.
 */
extern ds::linked_list::Sentinel<SocketRingLink> sealedSockets;

/**
 * Synchronize accesses to the sealed sockets list above.
 */
extern FlagLockPriorityInherited sealedSocketsListLock;

/**
 * State machine of the restart process. Used for synchronization across the
 * TCP/IP stack and with the firewall.
 *
 * TODO This could be merged together in the upper bits of
 * `currentSocketEpoch`.
 */
extern std::atomic<uint8_t> restartState;

/**
 * Keep track of the total number of user threads live in the network stack.
 * This is used to ensure that all threads have been adequately terminated when
 * performing a network stack reset.
 *
 * This should not be reset by the error handler and is reset-critical.
 */
extern std::atomic<uint8_t> userThreadCount;

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
	// The decrement will happen in the error handler if the thread
	// crashes.
	//
	// FIXME The decrement will *not* happen when a thread runs out of call
	// stack in the TCP/IP compartment (because the error handler does not
	// execute in that case). This will be fixed when we enable the error
	// handler to run on stack overflow.
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
