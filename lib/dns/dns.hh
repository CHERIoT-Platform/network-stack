// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include <compartment.h>
#include <timeout.h>

/**
 * Resolve `hostname` to an IPv4 or IPv6 address. If `useIPv6` is true, then
 * this will first attempt to find a IPv6 address and fall back to IPv4 if none
 * is found. We assume that `hostname` is null-terminated, and contains a host
 * name compliant with RFC 952.
 *
 * The result of the resolve is stored in `outAddress`.
 *
 * This returns zero for success, or a negative value on error.
 *
 * The negative values will be errno values:
 *
 *  - `-EINVAL`: An argument is invalid, e.g., the `hostname` is too long.
 *  - `-ETIMEDOUT`: The timeout was reached before the lookup could be
 *                  completed.
 *  - `-EAGAIN`: The lookup could not be completed at this time, e.g., because
 *               the DNS server cannot find a record for `hostname`.
 */
__cheri_compartment("DNS") int network_host_resolve(Timeout        *timeout,
                                                    const char     *hostname,
                                                    bool            useIPv6,
                                                    NetworkAddress *outAddress);
