#include "FreeRTOS_IP.h"
#include "thread.h"
#undef xTaskCreate
#define xTaskCreate(...) (ip_thread_start(), pdPASS)
void ip_thread_start(void);

// These C files are included here so that we can edit their static globals.
// This is evil.
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_ARP.c"
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_DHCP.c"
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_IP.c"
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_IP_Timers.c"
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_IP.c"
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_WIN.c"

#include <futex.h>
#include <locks.h>
#include <stdatomic.h>
#include <unwind.h>

/**
 * Flag used to synchronize the network stack thread and user threads at
 * startup.
 */
uint32_t threadEntryGuard;

/**
 * Store the thread ID of the TCP/IP thread for use in the error handler.
 */
uint16_t networkThreadID;

/**
 * Global lock acquired by the IP thread at startup time. In normal running
 * conditions, this lock is never released and acquiring it after startup will
 * always fail. This lock can be used to force the IP thread to run for a short
 * amount of time, e.g., when the internal FreeRTOS message queue is full and
 * we want to let the IP thread empty it to close a socket. See such an example
 * in `close_socket_retry`.
 *
 * Corner case: during a network stack reset, the lock is shortly released to
 * notify other threads that the IP thread is restarting. See comment in
 * `ip_thread_entry` for more details.
 */
struct FlagLockState ipThreadLockState;

void ip_thread_start(void)
{
	FreeRTOS_printf(("ip_thread_start\n"));
	threadEntryGuard = 1;
	futex_wake(&threadEntryGuard, 1);
}

/**
 * Cleanup to perform when restarting the network stack, including resetting
 * global state.
 *
 * This must be here as most of this state is static (we can edit them here
 * through the evil "include C files" hack above).
 *
 * This global state was identified by going through all entries of the .bss
 * and .data sections of this compartment. This *will* break if new FreeRTOS
 * releases introduce new global state. Ideally we would later reset all this
 * state automatically by zero-ing the entire .bss and resetting .data with
 * snapshots taken at startup time. See note of `defaultUDPPacketHeaderCopy`.
 */
void ip_cleanup(void)
{
	/// Reset data from `.bss`

	xIPTaskInitialised = 0;

	// Timers to reset
	memset(&xARPTimer, 0, sizeof(xARPTimer));
	memset(&xARPResolutionTimer, 0, sizeof(xARPResolutionTimer));
	memset(&xTCPTimer, 0, sizeof(xTCPTimer));

	// These globals can store sockets for further access by the IP thread,
	// we need to update otherwise the IP thread may crash again.
	xSocketToClose  = NULL;
	xSocketToListen = NULL;
	memset(&xBoundTCPSocketsList, 0, sizeof(xBoundTCPSocketsList));
	memset(&xBoundUDPSocketsList, 0, sizeof(xBoundUDPSocketsList));
	memset(&xDHCPv4Socket, 0, sizeof(xDHCPv4Socket));

	// Other globals which we must reset.
	xNetworkEventQueue        = NULL;
	pxARPWaitingNetworkBuffer = NULL;
	memset(&xSegmentList, 0, sizeof(xSegmentList));
	xTCPSegments              = NULL;
	pxNetworkInterfaces       = NULL;
	pxARPWaitingNetworkBuffer = NULL;
	memset(&xARPCache, 0, sizeof(xARPCache));
	xNetworkDownEventPending = 0;
	xDHCPSocketUserCount     = 0;

	// Note: do not reset `ucDefaultPartUDPPacketHeader` and
	// `xDefaultPartARPPacketHeader` because these globals are `const`,
	// i.e., only accessible through a read-only capability, and thus not
	// modifiable by a potentially compromised compartment.
}

extern void reset_network_stack_state(bool isIpThread);

void __cheri_compartment("TCPIP") ip_thread_entry(void)
{
	FreeRTOS_printf(("ip_thread_entry\n"));

	networkThreadID = thread_id_get();

	while (1)
	{
		CHERIOT_DURING
		{
			while (threadEntryGuard == 0)
			{
				FreeRTOS_printf(
				  ("Sleeping until the IP task is supposed to start\n"));
				futex_wait(&threadEntryGuard, 0);
			}

			xIPTaskHandle = networkThreadID;
			FreeRTOS_printf(
			  ("ip_thread_entry starting, thread ID is %p\n", xIPTaskHandle));

			flaglock_priority_inheriting_lock(&ipThreadLockState);

			// FreeRTOS event loop. This will only return if a user
			// thread crashed.
			prvIPTask(NULL);

			// Reset the guard. We only want to do this in the case
			// of a user thread crash, and we will only ever reach
			// this line if a user thread crashes (otherwise we'd
			// end up in the error handler).
			//
			// This is guaranteed not to race with
			// `ip_thread_start` since that function will only get
			// called after we release the IP thread lock at the
			// bottom of this function.
			//
			// The reason why we only reset this in the case of a
			// user thread crash is that the synchronization is
			// trivial in the case of a network thread crash: we
			// know that we will only enter the next loop iteration
			// after the guard has been set to 1 by
			// `ip_thread_start`, since the error handler only
			// returns once `network_restart` has returned.
			threadEntryGuard = 0;
		}
		CHERIOT_HANDLER
		{
			// Call the network stack error handler for the network thread.
			reset_network_stack_state(true /* this is the IP thread */);
		}
		CHERIOT_END_HANDLER

		// Release the IP thread lock. We will re-acquire it in the
		// next loop iteration. This is necessary if a user thread
		// triggered a reset. In such a case, the user thread error
		// handler will wait for the IP thread to restart by acquiring
		// the `ipThreadLockState` with an infinite timeout (and
		// immediately releasing it thereafter).
		flaglock_unlock(&ipThreadLockState);
	}
}
