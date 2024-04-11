#include "FreeRTOS_IP.h"
#include "thread.h"
#undef xTaskCreate
#define xTaskCreate(...) (ip_thread_start(), pdPASS)
void ip_thread_start(void);

// These C files are included here so that we can edit their static globals.
// This is evil.
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_ARP.c"
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_DHCP.c"
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Cache.c"
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_IP.c"
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_IP_Timers.c"
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_IP.c"
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_WIN.c"

#include <futex.h>
#include <locks.h>
#include <stdatomic.h>

/**
 * Backup of the constant UDP packet header (`xDefaultPartUDPPacketHeader`).
 *
 * This should not be reset by the error handler.
 */
static UDPPacketHeader_t defaultUDPPacketHeaderCopy;

/**
 * Flag used to synchronize the network stack thread and user threads at
 * startup.
 *
 * This should not be reset by the error handler.
 */
static uint32_t threadEntryGuard;

/**
 * Flag used to distinguish a normal TCP/IP thread start from a restart due to
 * a reset of the TCP/IP thread.
 *
 * This should not be reset by the error handler.
 */
static uint8_t isRestart = 0;

/**
 * Store the thread ID of the TCP/IP thread for use in the error handler.
 *
 * TODO: is this necessary or do we store this somewhere else already? The
 * FreeRTOS `xIPTaskHandle` global is static unfortunately so we cannot access
 * it from the error handler.
 */
uint16_t networkThreadID;

/**
 * Global lock acquired by the IP thread at startup time. This lock is never
 * released and acquiring it after startup will always fail. This lock can be
 * used to force the IP thread to run for a short amount of time, e.g., when
 * the internal FreeRTOS message queue is full and we want to let the IP thread
 * empty it to close a socket.
 */
struct FlagLockState ipThreadLockState;

void ip_thread_start(void)
{
	FreeRTOS_printf(("ip_thread_start\n"));
	threadEntryGuard = 1;
	futex_wake(&threadEntryGuard, 1);
}

/**
 * Set some constants which will outlive resets of the network stack. This will
 * be run exactly once the first time the network stack starts.
 */
void ip_set_constants(void)
{
	// Make a backup of the default UDP header to reset it later.
	memcpy(&defaultUDPPacketHeaderCopy,
	       &xDefaultPartUDPPacketHeader,
	       sizeof(defaultUDPPacketHeaderCopy));
}

/**
 * Cleanup to perform when restarting the network stack, including reseting
 * some globals which cannot be reset in the error handler because they are
 * static.
 */
void ip_cleanup(void)
{
	flaglock_unlock(&ipThreadLockState);

	/// Reset data from `.bss`

	xIPTaskInitialised = 0;

	// Set to != 0 when a network down event is pending, needs reset.
	xNetworkDownEventPending = 0;

	// Not sure if we need to reset this.
	xProcessedTCPMessage = 0;

	// Count of users to the DHCP socket, we need to reset
	xDHCPSocketUserCount = 0;

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

	// Other buffer (pointers) stored in globals, which we must reset.
	xNetworkEventQueue        = NULL;
	pxARPWaitingNetworkBuffer = NULL;
	memset(&xSegmentList, 0, sizeof(xSegmentList));
	xTCPSegments              = NULL;
	pxNetworkInterfaces       = NULL;
	pxARPWaitingNetworkBuffer = NULL;
	memset(&xARPCache, 0, sizeof(xARPCache));
	memset(&xDNSCache, 0, sizeof(xDNSCache));

	/// Reset data from `.data`

	// Reset the default UDP header from the backup we made at startup.
	memcpy(&xDefaultPartUDPPacketHeader,
	       &defaultUDPPacketHeaderCopy,
	       sizeof(xDefaultPartUDPPacketHeader));

	xDNS_IP_Preference = xPreferenceIPv4;
}

void __cheri_compartment("TCPIP") ip_thread_entry(void)
{
	if (isRestart == 0)
	{
		ip_set_constants();
	}

	networkThreadID = thread_id_get();

	while (1)
	{
		// After the initial start, all further invokations of this
		// function or iterations of this loop are restarts.
		isRestart = 1;

		FreeRTOS_printf(("ip_thread_entry\n"));

		while (threadEntryGuard == 0)
		{
			FreeRTOS_printf(
			  ("Sleeping until the IP task is supposed to start\n"));
			futex_wait(&threadEntryGuard, 0);
		}

		// Reset the guard now: we will only ever re-enter this
		// function in the case of a network stack reset, in which case
		// we want to wait again for a call to `ip_thread_start`.
		//
		// Note that we cannot reset this in `ip_cleanup`, because that
		// would overwrite the 1 written by `ip_thread_start` if the
		// latter was called before we call `ip_cleanup`. This will
		// happen if the IP thread crashes, in which case we would
		// first call `ip_thread_start` in the error handler, and then
		// reset the context to `ip_thread_entry` (itself then calling
		// `ip_cleanup`).
		threadEntryGuard = 0;

		xIPTaskHandle = networkThreadID;
		FreeRTOS_printf(
		  ("ip_thread_entry starting, thread ID is %p\n", xIPTaskHandle));
		flaglock_priority_inheriting_lock(&ipThreadLockState);

		// FreeRTOS event loop. This will only return if a user thread
		// crashed.
		prvIPTask(NULL);
	}
}
