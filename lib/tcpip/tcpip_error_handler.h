#include "FreeRTOS.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "compartment.h"
#include <atomic>
#include <cheri.hh>
#include <debug.hh>
#include <locks.hh>
#include <priv/riscv.h>
#include <simulator.h>
#include <vector>

using DebugErrorHandler = ConditionalDebug<true, "TCP/IP Stack error handler">;

// Globals to update as part of the reset.
extern uint64_t                                 currentSocketEpoch;
extern std::vector<FlagLockPriorityInherited *> socketLocks;
extern std::vector<FreeRTOS_Socket_t *>         sockets;
extern struct FlagLockState                     ipThreadLockState;
extern void                                     free_buffer_manager_memory();
extern void                                     network_restart();
extern std::atomic<bool>                        kickDriver;
extern std::atomic<bool>                        currentlyRestarting;
extern std::atomic<bool>                        restartingIpThread;
extern std::atomic<uint8_t>                     userThreadCount;
extern struct RecursiveMutexState               __CriticalSectionFlagLock;
extern struct RecursiveMutexState               __SuspendFlagLock;
extern QueueHandle_t                            xNetworkEventQueue;

/// Thread ID of the network thread.
extern uint16_t networkThreadID;

extern "C" void reset_network_stack_state()
{
	const bool isUserThread = thread_id_get() != networkThreadID;
	const bool isIpThread   = !isUserThread;

	if (isUserThread)
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

	// Set the currently restarting flag. This will do several things:
	// 1. ensure that only one call to this error handler triggers a reset
	// 2. ensure that no thread enters the compartment while we are
	//    restarting
	// 3. reset the network thread whenever it wakes up
	bool expected = false;
	if (!currentlyRestarting.compare_exchange_strong(expected, true))
	{
		if (isIpThread && restartingIpThread.load())
		{
			// Currently recovering from a crash that happens
			// during the reset process isn't possible. It's not
			// clear if we ever really want to do that: we will
			// only crash during reset if 1) there is a bug in the
			// reset code, or 2) there is some global data that we
			// cannot reset and which is corrupted. In either case,
			// re-reseting the same way won't make the situation
			// better.
			DebugErrorHandler::log("The network thread crashed while "
			                       "restarting. This may be unrecoverable.");
		}

		// Another instance of the error handler is running, do not do
		// anything.
		return;
	}

	DebugErrorHandler::log("Reset-ing the network stack.");

	// Upgrade socket locks for destruction to ensure that threads waiting
	// on it exit the compartment. Do not remove the entries because we
	// will re-initialize the vectors anyways.
	DebugErrorHandler::log("Upgrading socket locks for destruction.");
	for (FlagLockPriorityInherited *&lock : socketLocks)
	{
		if (lock != nullptr)
		{
			lock->upgrade_for_destruction();
		}
	}

	DebugErrorHandler::log("Unblocking threads blocked on event groups.");
	for (FreeRTOS_Socket_t *&s : sockets)
	{
		if (s != nullptr)
		{
			eventgroup_destroy_force(MALLOC_CAPABILITY, s->xEventGroup);
		}
	}

	// Upgrade the two critical section locks for destruction
	// TODO document what this will do
	DebugErrorHandler::log("Upgrading critical sections for destruction.");
	flaglock_upgrade_for_destruction(&__CriticalSectionFlagLock.lock);
	flaglock_upgrade_for_destruction(&__SuspendFlagLock.lock);

	// Upgrade the message queue lock for destruction
	DebugErrorHandler::log("Upgrading the message queue for destruction.");
	// TODO document what this will do
	auto *queueHandle = &xNetworkEventQueue->handle;
	if (int err = queue_destroy(MALLOC_CAPABILITY, queueHandle); err != 0)
	{
		DebugErrorHandler::log(
		  "Failed to upgrade the message queue for destruction (error {}).",
		  err);
	}

	// Threads may also be waiting on the allocator in an out-of-memory
	// situation. Do a first `heap_free_all` to unblock them. We will do
	// another one later to ensure that everything is cleaned up if threads
	// allocate memory again before terminating.
	//
	// Note that socket memory will not be freed because sockets are
	// allocated with user-passed capabilities which we do not store.
	DebugErrorHandler::log("Unblocking threads waiting on the allocator.");
	// Global heap capability.
	heap_free_all(MALLOC_CAPABILITY);
	// Buffer manager capability. If the buffer manager is using the global
	// heap capability, this will do nothing.
	free_buffer_manager_memory();

	DebugErrorHandler::log("Waiting for all threads to exit.");

	// Wait for all user threads to exit.
	while (userThreadCount.load() != 0)
	{
		// TODO here, we can experiment with
		// `switcher_interrupt_thread` to get threads to die faster
		DebugErrorHandler::log("Waiting for {} user thread(s) to terminate.",
		                       userThreadCount.load());
		Timeout t{1};
		thread_sleep(&t);
	}

	// Wait for the IP thread to exit (unless this error handler is running
	// from the IP thread)
	if (isUserThread)
	{
		DebugErrorHandler::log("Waiting for the IP thread to terminate.");
		// We will only manage to lock this when the IP thread releases
		// the lock, which will happen when it re-enters its
		// initialization phase.
		flaglock_lock(&ipThreadLockState);
		// Release the lock as we want the IP thread to grab it again
		// when we unleash it.
		flaglock_unlock(&ipThreadLockState);
	}

	// At this point all user threads have exited the TCP/IP stack
	// compartment and the network thread context has been reinstalled.
	DebugErrorHandler::Assert(userThreadCount.load() == 0,
	                          "All user threads should be terminated.");

	// Free heap memory.  We must do this *again*, because threads may have
	// allocated memory since the previous calls to `heap_free_all`.
	DebugErrorHandler::log("Freeing heap memory.");
	heap_free_all(MALLOC_CAPABILITY);
	free_buffer_manager_memory();

	// Update the socket epoch.
	currentSocketEpoch++;

	// Initialize fresh vectors for locks and sockets
	socketLocks = std::vector<FlagLockPriorityInherited *>{};
	sockets = std::vector<FreeRTOS_Socket_t *>{};

	// Restart the network stack. This resets the startup state before
	// calling `network_start`.
	DebugErrorHandler::log("Restarting the network stack.");
	restartingIpThread.store(true);
	network_restart();

	// We do not reset `currentlyRestarting` to `false` here, the network
	// thread will take care of it when the network stack is done reseting.
}

extern void ip_thread_entry(void);

extern "C" ErrorRecoveryBehaviour
compartment_error_handler(ErrorState *frame, size_t mcause, size_t mtval)
{
	auto threadID = thread_id_get();
	if (mcause == priv::MCAUSE_CHERI)
	{
		auto [exceptionCode, registerNumber] =
		  CHERI::extract_cheri_mtval(mtval);
		// The thread entry point is called with a NULL return address so the
		// cret at the end of the entry point function will trap if it is
		// reached. We don't want to treat this as an error but thankfully we
		// detect it quite specifically by checking for all of:
		// 1) CHERI cause is tag violation
		// 2) faulting register is CRA
		// 3) value of CRA is NULL
		// 4) we've reached the top of the thread's stack
		CHERI::Capability stackCapability{
		  frame->get_register_value<CHERI::RegisterNumber::CSP>()};
		CHERI::Capability returnCapability{
		  frame->get_register_value<CHERI::RegisterNumber::CRA>()};
		if (registerNumber == CHERI::RegisterNumber::CRA &&
		    returnCapability.address() == 0 &&
		    exceptionCode == CHERI::CauseCode::TagViolation &&
		    stackCapability.top() == stackCapability.address())
		{
			// looks like thread exit -- just log it then ForceUnwind
			DebugErrorHandler::log(
			  "Thread exit CSP={}, PCC={}", stackCapability, frame->pcc);
		}
		else if (exceptionCode == CHERI::CauseCode::None)
		{
			// An unwind occurred from a called compartment, just resume.
			return ErrorRecoveryBehaviour::InstallContext;
		}
		else
		{
			// An unexpected error -- log it and restart the stack.
			// Note: handle CZR differently as `get_register_value`
			// will return a nullptr which we cannot dereference.
			DebugErrorHandler::log(
			  "{} error at {} (return address: {}), with capability register "
			  "{}: {} by thread {}",
			  exceptionCode,
			  frame->pcc,
			  frame->get_register_value<CHERI::RegisterNumber::CRA>(),
			  registerNumber,
			  registerNumber == CHERI::RegisterNumber::CZR
			    ? nullptr
			    : *frame->get_register_value(registerNumber),
			  threadID);

			// TODO before running the reset function we should go
			// to the top of the stack to ensure that we do not run
			// out of stack space while executing the error
			// handler.

			// Reset the network stack state.
			reset_network_stack_state();

			// Now we should either rewind if this is a user
			// thread, or reinstall the context if this is the
			// network thread.
			if (threadID == networkThreadID)
			{
				// Reset the stack pointer to the top of the stack.
				CHERI::Capability<void *> stack{
				  frame->get_register_value(CHERI::RegisterNumber::CSP)};
				DebugErrorHandler::log("Resetting the stack from {} -> {}.",
				                       stack.address(),
				                       stack.base());
				stack.address() = stack.base();
				DebugErrorHandler::log("Stack length is {}.", stack.length());

				// Reset the program counter.
				DebugErrorHandler::log(
				  "Reinstalling context to ip_thread_entry.");
				frame->pcc = (void *)&ip_thread_entry;

				// We will now run `ip_thread_entry`.
				return ErrorRecoveryBehaviour::InstallContext;
			}

			DebugErrorHandler::log("Rewinding crashed user thread {}.",
			                       threadID);
			return ErrorRecoveryBehaviour::ForceUnwind;
		}
	}
	else
	{
		// other error (e.g. __builtin_trap causes ReservedInstruciton)
		// log and end simulation with error.
		DebugErrorHandler::log("Unhandled error {} at {} by thread {}",
		                       mcause,
		                       frame->pcc,
		                       threadID);
		CHERI::Capability<void *> stack{
		  frame->get_register_value(CHERI::RegisterNumber::CSP)};
		DebugErrorHandler::log("Stack length is {}.", stack.length());
	}
	return ErrorRecoveryBehaviour::ForceUnwind;
}
