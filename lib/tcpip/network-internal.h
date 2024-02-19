#pragma once
/**
 * Internal APIs that the TCP/IP compartment exposes for the wrapper APIs to
 * use.
 *
 * These should be called only from the NetAPI compartment (validated by
 * checking the compartment linkage report).  These APIs trust the caller and
 * do *not* check arguments.
 */

#include <NetAPI.h>

/**
 * Resolve a host name to an IPv4 or IPv6 address.  If `useIPv6` is true, then
 * this will first attempt to find a IPv6 address and fall back to IPv4 if none
 * is found.
 */
NetworkAddress __cheri_compartment("TCPIP")
  network_host_resolve(const char *hostname, bool useIPv6);

/**
 * Create a socket and bind it to the given address.  The socket will be
 * allocated with the malloc capability.
 *
 * This returns a sealed capability to a socket on success, or null on failure.
 *
 * This should be called only from the NetAPI compartment.
 */
SObj __cheri_compartment("TCPIP")
  network_socket_create_and_bind(Timeout       *timeout,
                                 SObj           mallocCapability,
                                 bool           isIPv6,
                                 ConnectionType type,
                                 uint16_t       localPort = 0);

/**
 * Connect a TCP socket to the given address.
 */
int __cheri_compartment("TCPIP")
  network_socket_connect_tcp_internal(Timeout       *timeout,
                                      SObj           socket,
                                      NetworkAddress address,
                                      short          port);
/**
 * Information about a socket.
 */
struct SocketKind
{
	/**
	 * The protocol for this socket.
	 */
	enum
	{
		/// TCP over IPv4
		TCPIPv4,
		/// UDP over IPv4
		UDPIPv4,
		/// TCP over IPv6
		TCPIPv6,
		/// UDP over IPv6
		UDPIPv6,
		/// Invalid socket
		Invalid,
	} protocol;
	/**
	 * The local port for this socket.  This is in host byte order.
	 */
	uint16_t localPort;
};

/**
 * Returns information about the given socket.
 */
SocketKind __cheri_compartment("TCPIP") network_socket_kind(SObj socket);
