// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include "FreeRTOS.h"
#include "FreeRTOS_IP.h"
#include <NetworkBufferManagement.h>
#include <cstdlib>
#include <debug.hh>
#include <timeout.hh>

using Debug = ConditionalDebug<false, "Buffer management">;

// Use a separate allocator quota for the buffer manager (false by default).
// The buffer manager is responsible for allocating network buffers, which
// differs from the other types of allocations the TCP/IP stack performs. It
// may thus make sense to give it its own quota. We may want to expose this as
// a build system configuration option at some point.
#define USE_DEDICATED_BUFFERMANAGER_POOL false
// Size of the buffer manager allocator quota. Only relevant if
// USE_DEDICATED_BUFFERMANAGER_POOL is enabled.
#define BUFFER_MANAGER_QUOTA                                                   \
	(ipconfigNUM_NETWORK_BUFFER_DESCRIPTORS *                                  \
	 (ipconfigTCP_MSS + ipBUFFER_PADDING))

#if USE_DEDICATED_BUFFERMANAGER_POOL
DECLARE_AND_DEFINE_ALLOCATOR_CAPABILITY(BufferManagementMallocQuota,
                                        BUFFER_MANAGER_QUOTA);
#	define BM_MALLOC_QUOTA STATIC_SEALED_VALUE(BufferManagementMallocQuota)
#else
#	define BM_MALLOC_QUOTA MALLOC_CAPABILITY
#endif

constexpr size_t MinimumBufferSize =
#if ipconfigUSE_TCP == 1
  sizeof(TCPPacket_t)
#else
  sizeof(ARPPacket_t)
#endif
  ;

/**
 * Variable consumed in FreeRTOS_IP.c to determine whether buffers are fixed
 * sizes.
 */
const BaseType_t xBufferAllocFixedSize = pdFALSE;

/**
 * Initialise the network buffer management.  We don't need to do anything here
 * because this code just delegates to the heap allocator.
 */
BaseType_t xNetworkBuffersInitialise()
{
	return pdPASS;
}

/**
 * Allocate a buffer and its associated descriptor.
 */
NetworkBufferDescriptor_t *
pxGetNetworkBufferWithDescriptor(size_t     xRequestedSizeBytes,
                                 TickType_t xBlockTimeTicks)
{
	xRequestedSizeBytes = std::max(xRequestedSizeBytes, MinimumBufferSize);
	if ((xRequestedSizeBytes & (sizeof(void *) - 1U)) != 0U)
	{
		xRequestedSizeBytes =
		  (xRequestedSizeBytes | (sizeof(void *) - 1U)) + 1U;
	}

	Timeout t{xBlockTimeTicks};

	// TODO we likely want to pre-allocate (or re-use) the descriptors at
	// some point
	auto deleter = [=](void *ptr) { heap_free(BM_MALLOC_QUOTA, ptr); };
	std::unique_ptr<NetworkBufferDescriptor_t, decltype(deleter)> descriptor{
	  static_cast<NetworkBufferDescriptor_t *>(
	    heap_allocate(&t, BM_MALLOC_QUOTA, sizeof(NetworkBufferDescriptor_t))),
	  deleter};
	if (descriptor == nullptr)
	{
		Debug::log("Failed to allocate descriptor");
		return nullptr;
	}
	auto *buffer = static_cast<uint8_t *>(heap_allocate(
	  &t, BM_MALLOC_QUOTA, xRequestedSizeBytes + ipBUFFER_PADDING));
	if (buffer == nullptr)
	{
		Debug::log("Failed to allocate {} byte buffer", xRequestedSizeBytes);
		return nullptr;
	}
	Debug::log("Allocated {} byte buffer: {}, descriptor: {}",
	           xRequestedSizeBytes,
	           buffer,
	           descriptor.get());

	vListInitialiseItem(&descriptor->xBufferListItem);
	listSET_LIST_ITEM_OWNER(&descriptor->xBufferListItem, descriptor.get());

	*reinterpret_cast<NetworkBufferDescriptor_t **>(buffer) = descriptor.get();
	// Make sure that there is enough space in the padding for the pointer.
	static_assert(sizeof(NetworkBufferDescriptor_t *) <= ipBUFFER_PADDING);
	// Make sure that the result is correctly aligned so that the packet after
	// the Ethernet header is 4-byte aligned.
	static_assert(((ipBUFFER_PADDING % 8) + 14) % 4 == 0);
	descriptor->pucEthernetBuffer = buffer + ipBUFFER_PADDING;
	descriptor->xDataLength       = xRequestedSizeBytes;
	// Debug::log("Allocated buffer of size {}: {}", buffer,
	// xRequestedSizeBytes); Debug::log("Descriptor: {}", descriptor.get());
	return descriptor.release();
}

/**
 * Free a descriptor and its associated buffer.
 */
void vReleaseNetworkBufferAndDescriptor(
  NetworkBufferDescriptor_t *const networkBuffer)
{
	if (networkBuffer != nullptr)
	{
		uint8_t *bufferWithoutOffset =
		  networkBuffer->pucEthernetBuffer - ipBUFFER_PADDING;

		Debug::log("Freeing descriptor: {} and buffer {}",
		           networkBuffer,
		           bufferWithoutOffset);

		int ret = heap_free(MALLOC_CAPABILITY, bufferWithoutOffset);
		ret |= heap_free(MALLOC_CAPABILITY, networkBuffer);

		// Failure is not supposed to happen unless we have a bug here
		// or in FreeRTOS.
		Debug::Assert(ret == 0, "Failed to free network buffer or descriptor.");
	}
}

/**
 * Allocate a buffer from the heap.  We don't support running code in ISRs, so
 * this function is redundant.
 */
NetworkBufferDescriptor_t *pxNetworkBufferGetFromISR(size_t xRequestedSizeBytes)
{
	return pxGetNetworkBufferWithDescriptor(xRequestedSizeBytes, 0);
}

/**
 * Free a buffer from an ISR.  We don't support running code in ISRs, so this
 * function is redundant.
 */
BaseType_t
vNetworkBufferReleaseFromISR(NetworkBufferDescriptor_t *const networkBuffer)
{
	vReleaseNetworkBufferAndDescriptor(networkBuffer);
	return pdTRUE;
}

/**
 * Return the number of free network buffers.  This API makes no sense when
 * network buffers are dynamically allocated.
 */
UBaseType_t uxGetNumberOfFreeNetworkBuffers(void)
{
	// Not chosen by fair die roll in this case, chosen because a bunch of
	// things in the stack do >= 4 or >= 3 comparisons to determine whether to
	// proceed.
	return 4;
}

/**
 * Return the minimum number of free network buffers since the start.  This is
 * used only in logging and so returning an arbitrary number is fine.
 */
UBaseType_t uxGetMinimumFreeNetworkBuffers(void)
{
	return 4;
}
