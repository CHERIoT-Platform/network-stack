// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

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
