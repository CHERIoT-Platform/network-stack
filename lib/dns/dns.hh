// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include <compartment.h>

/**
 * Resolve a host name to an IPv4 or IPv6 address.  If `useIPv6` is true, then
 * this will first attempt to find a IPv6 address and fall back to IPv4 if none
 * is found.
 *
 * The result of the resolve is stored in `outAddress`.
 *
 * This returns zero for success, or a negative value on error.
 *
 * TODO which errors?
 */
__cheri_compartment("DNS") int network_host_resolve(const char     *hostname,
                                                    bool            useIPv6,
                                                    NetworkAddress *outAddress);
