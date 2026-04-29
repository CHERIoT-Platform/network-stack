#include "FreeRTOS.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "compartment.h"
#include "tcpip-internal.h"
#include <BufferManagement.hh>
#include <atomic>
#include <cheri.hh>
#include <debug.hh>
#include <locks.hh>
#include <priv/riscv.h>
#include <simulator.h>
#include <vector>

using DebugErrorHandler = ConditionalDebug<false, "TCP/IP Stack error handler">;
using CHERI::Capability;

/**
 * Global state to update as part of the reset. These are documented in
 * `network_wrapper.cc` and `tcpip-internal.h`.
 */
extern std::atomic<uint32_t> currentSocketEpoch;
extern std::atomic<uint8_t>  userThreadCount;

/**
 * Global lock acquired by the IP thread at startup time. See documentation in
 * `FreeRTOS_IP_wrapper.c`.
 */
extern struct FlagLockState ipThreadLockState;

/**
 * Other locks and futexes to release as part of the reset. These are
 * documented in `sdk/include/FreeRTOS-Compat/task.h` in the main tree
 * (`__CriticalSectionFlagLock` and `__SuspendFlagLock`),
 * `source/FreeRTOS_IP.c` in the FreeRTOS+TCP tree (`xNetworkEventQueue`), and
 * `network_wrapper.cc` in the TCP/IP wrapper.
 */
extern struct RecursiveMutexState __CriticalSectionFlagLock;
extern struct RecursiveMutexState __SuspendFlagLock;
extern QueueHandle_t              xNetworkEventQueue;
extern FlagLockPriorityInherited  sealedSocketsListLock;
extern uint32_t                   threadEntryGuard;

/**
 * Restart the network stack. See documentation in `startup.cc`
 */
extern void network_restart();

/**
 * Free the compartment's heap memory.
 *
 * Note that socket memory will not be freed because sockets are allocated with
 * user-passed capabilities which we do not store. API users are supposed to
 * close them, which will trigger a free.
 */
__always_inline static inline void free_compartment_memory()
{
	// Global heap capability.
	heap_free_all(MALLOC_CAPABILITY);
	// Buffer manager capability. If the buffer manager is using the global
	// heap capability, this will do nothing.
	free_buffer_manager_memory();
}

/**
 * Reset the network stack state.
 *
 * This is meant to be called by error handlers. `isIpThread` specifies
 * whether the thread running this function is the IP thread.
 *
 * We go through all locks used in the TCP/IP compartment and set them for
 * destruction. The list of synchronization primitives resetted here was
 * extracted through a manual study of the compartment's code-base: this may
 * therefore break if new releases of FreeRTOS+TCP introduce new locks. In the
 * future, we may want to come up with a more systematic approach.
 *
 * Some of it may be moved to a normal (non-error-handler context) at a later
 * point - mainly Phase 3, see comments in the body.
 *
 * This function is designed to be robust against most types of compartment
 * corruption, however we do assume that:
 * - 'reset-critical' data has not been corrupted
 * - the control-flow of threads in the compartment has not been altered
 * - spatial and temporal memory safety are not violated
 */
extern "C" void reset_network_stack_state(bool isIpThread)
{
	/// Phase 1: Do bookkeeping and determine if we are already in a reset:
	/// should we do anything at all?
	const bool IsUserThread = !isIpThread;

	// We could print this in the caller, but it is not certain that
	// debugging is enabled there and it is nice to print this with the
	// same output code as other reset operations.
	if (IsUserThread)
	{
		DebugErrorHandler::log(
		  "User thread TCP/IP stack error handler called!");
		userThreadCount--;
	}
	else
	{
		DebugErrorHandler::log(
		  "Network thread TCP/IP stack error handler called!");
	}

	// Manually unlock the sealed sockets lock list if it was held.
	if (sealedSocketsListLock.get_owner_thread_id() == thread_id_get())
	{
		// This situation may happen if we crash in
		// `network_socket_create_and_bind` because we hold the lock
		// for more than simply editing the list (to simplify error
		// handling).
		//
		// If that is not the case, and we are here because we crashed
		// while adding to the list, we may not be able to recover
		// later because the list is reset-critical.
		DebugErrorHandler::log("The sealed sockets lock was held by the "
		                       "crashing thread. Forcefully unlocking it.");
		sealedSocketsListLock.unlock();
	}

	// Set the currently restarting flag. This will do several things:
	// 1. ensure that only one call to this error handler triggers a reset
	// 2. ensure that no thread enters the compartment while we are
	//    restarting
	// 3. reset the network thread whenever it wakes up
	uint8_t expected = NotRestarting;
	if (!restartState.compare_exchange_strong(expected, Restarting))
	{
		// `expected` now contains a snapshot of `restartState`.
		if (isIpThread && ((expected & IpThreadKicked) != 0))
		{
			// Currently recovering from a crash that happens
			// during the reset process is not possible. It is not
			// clear if we ever really want to do that: we will
			// only crash during reset if 1) there is a bug in the
			// reset code, or 2) there is some global data that we
			// cannot reset and which is corrupted. In either case,
			// re-reseting the same way will not make the situation
			// better.
			DebugErrorHandler::log("The network thread crashed while "
			                       "restarting. This may be unrecoverable.");
		}
		else if (isIpThread)
		{
			// Reset the IP thread entry guard. We only want to do
			// this in the case of a user thread crash, and we will
			// only ever reach this line if a user thread crashed
			// first (causing the network thread to crash).
			//
			// This is guaranteed not to race with
			// `ip_thread_start` since that function will only get
			// called after we return.
			//
			// For more information, look at the other place where
			// we reset `threadEntryGuard` in
			// `FreeRTOS_IP_wrapper.c`.
			threadEntryGuard = 0;
		}

		// Another instance of the error handler is running, do not do
		// anything.
		return;
	}

	/// Phase 2: Unblock and evacuate all threads from the network stack
	/// (apart from the network thread).
	DebugErrorHandler::log("Resetting the network stack.");

	// We need to acquire the sealed sockets lock because we do not want
	// the sealed sockets list to be in an inconsistent state when we go
	// over it.
	//
	// Waiting to acquire the lock is fine, as we know that any thread
	// which holds the it will eventually release it, either 1) exiting the
	// critical section, or 2) crashing into it, in which case we (the
	// error handler) will manually unlock it (see manual unlock above).
	//
	// Note that the internal state of the lock should not be corrupted
	// unless spatial or temporal memory safety was somehow violated.
	DebugErrorHandler::log("Acquiring the sealed sockets lock.");
	sealedSocketsListLock.lock();

	DebugErrorHandler::log(
	  "Setting the sealed sockets list lock for destruction.");
	sealedSocketsListLock.upgrade_for_destruction();

	// Upgrade socket locks for destruction and destroy event groups to
	// ensure that threads waiting on them exit the compartment. We will
	// empty the list later.
	//
	// This is designed to be resilient to a corrupted socket list. If the
	// socket list somehow ended up corrupted, we would still manage to
	// reset, albeit slower. In the case of socket locks, we would need to
	// wait up to 500ms for waiters to wake up, check the network stack
	// state machine, and bail out.  For event groups, we would need to
	// wait 500ms too, until waiters try to re-acquire the lock and crash
	// because it was freed through the heap-free-all below.
	DebugErrorHandler::log(
	  "Setting socket locks for destruction and destroying event groups.");
	if (!sealedSockets.is_empty())
	{
		auto *cell = sealedSockets.first();
		while (cell != &sealedSockets.sentinel)
		{
			if (!Capability{cell}.is_valid())
			{
				DebugErrorHandler::log(
				  "Ignoring corrupted cell {} in the socket list.", cell);
				// We have to stop here because we cannot
				// retrieve the next cell from a corrupted
				// cell.
				break;
			}

			struct SealedSocket *socket = SealedSocket::from_ring(cell);

			if (Capability{socket}.is_valid())
			{
				FlagLockPriorityInherited *lock = &(socket->socketLock);
				if (Capability{lock}.is_valid())
				{
					DebugErrorHandler::log("Destroying socket lock {}.", lock);
					lock->upgrade_for_destruction();
				}
				else
				{
					DebugErrorHandler::log("Ignoring corrupted socket lock {}.",
					                       lock);
				}

				FreeRTOS_Socket_t *s = socket->socket;
				if (Capability{s}.is_valid() &&
				    Capability{s->xEventGroup}.is_valid())
				{
					DebugErrorHandler::log("Destroying event group {}.",
					                       s->xEventGroup);
					eventgroup_destroy_force(MALLOC_CAPABILITY, s->xEventGroup);
				}
				else
				{
					DebugErrorHandler::log("Ignoring corrupted socket {}.", s);
				}
			}
			else
			{
				DebugErrorHandler::log(
				  "Ignoring corrupted socket {} in the socket list.", socket);
			}

			cell = cell->cell_next();
		}
	}

	DebugErrorHandler::log("Resetting the sealed sockets list.");
	sealedSockets.reset();

	// Upgrade the two critical section locks for destruction
	DebugErrorHandler::log("Upgrading critical sections for destruction.");
	flaglock_upgrade_for_destruction(&__CriticalSectionFlagLock.lock);
	flaglock_upgrade_for_destruction(&__SuspendFlagLock.lock);

	// Upgrade the message queue lock for destruction
	DebugErrorHandler::log("Upgrading the message queue for destruction.");
	if (int err = queue_destroy(MALLOC_CAPABILITY, xNetworkEventQueue);
	    err != 0)
	{
		DebugErrorHandler::log(
		  "Failed to upgrade the message queue for destruction (error {}).",
		  err);
	}

	// Wait for all user threads to exit.
	DebugErrorHandler::log("Waiting for all threads to exit.");
	while (userThreadCount.load() != 0)
	{
		// Here, we may also want to experiment with
		// `switcher_interrupt_thread` to get threads to die faster.

		DebugErrorHandler::log("Waiting for {} user thread(s) to terminate.",
		                       userThreadCount.load());

		// Threads may also be waiting on the allocator in an
		// out-of-memory situation. Do a `heap_free_all` to unblock
		// them. We must do this in the loop body in case threads
		// re-enter OOM multiple times.
		//
		// We will do another free at the end of the reset to ensure
		// that everything is cleaned up in case threads allocate
		// memory again before terminating.
		free_compartment_memory();

		Timeout t{1};
		thread_sleep(&t);
	}

	// Wait for the IP thread to reset (unless this error handler is
	// running from the IP thread).
	if (IsUserThread)
	{
		DebugErrorHandler::log("Waiting for the IP thread to reset.");
		// We will only manage to lock this when the IP thread releases
		// the lock, which will happen when it re-enters its
		// initialization phase.
		flaglock_lock(&ipThreadLockState);
		// Release the lock as we want the IP thread to grab it again
		// when we unleash it.
		flaglock_unlock(&ipThreadLockState);
	}

	/// Phase 3: Now that only the network thread is present in the
	/// compartment, reset the network stack into a pristine state. With
	/// some more work, this may be moved to a non-error-handler context.

	// At this point all user threads have exited the TCP/IP stack
	// compartment and the network thread context has been reinstalled.
	DebugErrorHandler::Assert(userThreadCount.load() == 0,
	                          "All user threads should be terminated by now.");

	// Free heap memory.  We must do this *again*, because threads may have
	// allocated memory since the previous calls to `heap_free_all`.
	DebugErrorHandler::log("Freeing heap memory.");
	free_compartment_memory();

	// Update the socket epoch. We want to do this after all threads have
	// terminated in case some threads were allocating new sockets during
	// the restart.
	currentSocketEpoch++;

	// Re-initialize the locks we updated for destruction earlier.
	__CriticalSectionFlagLock.lock.lockWord = 0;
	__CriticalSectionFlagLock.depth         = 0;
	__SuspendFlagLock.lock.lockWord         = 0;
	__SuspendFlagLock.depth                 = 0;
	memset(&sealedSocketsListLock, 0, sizeof(FlagLockPriorityInherited));

	// Restart the network stack. This resets the startup state before
	// calling `network_start`.
	DebugErrorHandler::log("Restarting the network stack.");
	restartState |= IpThreadKicked;
	network_restart();

	// We do not reset `restartState` here, the network thread will take
	// care of it when the TCP/IP stack is done reseting.
}
