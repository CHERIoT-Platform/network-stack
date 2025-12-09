// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include "cdefs.h"
#include <stdint.h>

uint16_t constexpr ntohs(uint16_t value)
{
	return
#ifdef __LITTLE_ENDIAN__
	  __builtin_bswap16(value)
#else
	  value
#endif
	    ;
}

uint16_t constexpr htons(uint16_t value)
{
	return
#ifdef __LITTLE_ENDIAN__
	  __builtin_bswap16(value)
#else
	  value
#endif
	    ;
}

template<class T>
__always_inline T read_unaligned(const void *p)
{
	T val;
	__builtin_memcpy(&val, p, sizeof(T));
	return val;
}
