#include "FreeRTOS.h"
#include "FreeRTOSIPConfig.h"
#include <stdlib.h>
#include <riscvreg.h>

// Give the network stack a big heap capability.
DEFINE_ALLOCATOR_CAPABILITY(__default_malloc_capability, 64*1024)

struct RecursiveMutexState __CriticalSectionFlagLock;
struct RecursiveMutexState __SuspendFlagLock;



BaseType_t xApplicationGetRandomNumber( uint32_t * pulNumber )
{
	// FIXME: This is not a good random number generator.  We could do better
	// feeding this through Fortuna, but without a good source of entropy, it
	// will be fairly predictable.
	*pulNumber = rdcycle64();
	return pdTRUE;
}

uint32_t ulApplicationGetNextSequenceNumber( uint32_t ulSourceAddress,
                                             uint16_t usSourcePort,
                                             uint32_t ulDestinationAddress,
                                             uint16_t usDestinationPort )
{
	// This is also bad.
	return rdcycle64();
}
