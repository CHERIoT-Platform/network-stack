// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once

/**
 * Internal helpers and configuration settings for use in the TCP/IP buffer
 * manager. These should be called or used only from/in the TCP/IP compartment.
 */

#ifndef USE_DEDICATED_BUFFERMANAGER_POOL
// Use a separate allocator quota for the buffer manager (false by default).
// The buffer manager is responsible for allocating network buffers, which
// differs from the other types of allocations the TCP/IP stack performs. It
// may thus make sense to give it its own quota. We may want to expose this as
// a build system configuration option at some point.
#	define USE_DEDICATED_BUFFERMANAGER_POOL false
#endif

#if USE_DEDICATED_BUFFERMANAGER_POOL
extern void free_buffer_manager_memory();
#else
/**
 * Free the buffer manager's memory. Since the buffer manager does not have a
 * dedicated quota, this is a noop.
 */
static inline void free_buffer_manager_memory()
{
	return;
}
#endif
