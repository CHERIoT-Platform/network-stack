#pragma once
/**
 * Internal APIs that the TCP/IP compartment exposes for the wrapper APIs to use.
 *
 * These should be called only from the NetAPI compartment.
 */

#include "NetAPI.h"

/**
 * Resolve a host name to an IPv4 or IPv6 address.  If `useIPv6` is true, then
 * this will first attempt to find a IPv6 address and fall back to IPv4 if none
 * is found.
 */
NetworkAddress __cheri_compartment("TCPIP")
  network_host_resolve(const char *hostname, bool useIPv6);

/**
 * Create a socket and connect it to the given address.  The socket will be
 * allocated with the malloc capability and connected to the address and port.
 *
 * This returns a sealed capability to a socket on success, or null on failure.
 */
SObj __cheri_compartment("TCPIP")
  network_socket_create_and_connect(Timeout       *timeout,
                                    SObj           mallocCapability,
                                    NetworkAddress address,
                                    ConnectionType            type,
                                    short          port);

