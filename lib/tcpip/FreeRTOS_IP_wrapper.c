#include "FreeRTOS_IP.h"
#include "thread.h"
#undef xTaskCreate
#define xTaskCreate(...) (ip_thread_start(), pdPASS)
void ip_thread_start(void);
#include "../../third_party/freertos-plus-tcp/source/FreeRTOS_IP.c"
#include <futex.h>
#include <locks.h>
#include <stdatomic.h>

uint32_t threadEntryGuard;

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

void __cheri_compartment("TCPIP") ip_thread_entry(void)
{
	FreeRTOS_printf(("ip_thread_entry\n"));
	while (threadEntryGuard == 0)
	{
		FreeRTOS_printf(("Sleeping until the IP task is supposed to start\n"));
		futex_wait(&threadEntryGuard, 0);
	}
	xIPTaskHandle = thread_id_get();
	FreeRTOS_printf(
	  ("ip_thread_entry starting, thread ID is %p\n", xIPTaskHandle));
	flaglock_priority_inheriting_lock(&ipThreadLockState);
	prvIPTask(NULL);
	FreeRTOS_printf(("ip_thread_entry exiting.  This should not happen\n"));
}
