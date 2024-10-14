// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include "cdefs.h"
#include <compartment-macros.h>
#include <timeout.h>
#include <token.h>

/**
 * Structure wrapping a network address and a discriminator.
 */
struct NetworkAddress
{
	/**
	 * Network address in either IPv4 or IPv6 format.
	 */
	union
	{
		/// IPv4 addresses are 32 bits.  Stored in network byte order.
		uint32_t ipv4;
		/// IPv6 addresses are 16 bytes.  Stored in network byte order.
		uint8_t ipv6[16];
	};
	/// The kind of address that this holds.
	enum
	{
		/// No valid address.
		AddressKindInvalid,
		/// The ipv4 field contains an IPv4 address.
		AddressKindIPv4,
		/// The ipv6 field contains an IPv6 address.
		AddressKindIPv6
	} kind;
};

/**
 * Start the network.  This is a temporary API.  It will eventually be replaced
 * by a non-blocking version.
 */
void __cheri_compartment("TCPIP") network_start(void);

/**
 * Create a connected TCP socket.
 *
 * This function will block until the connection is established or the timeout
 * is reached.
 *
 * The `mallocCapability` argument is used to allocate memory for the socket
 * and must have sufficient quota remaining for the socket.
 *
 * The `hostCapability` argument is a capability authorising the connection to
 * a specific host.
 *
 * This returns a valid sealed capability to a socket on success, or a null on
 * failure.
 */
SObj __cheri_compartment("NetAPI")
  network_socket_connect_tcp(Timeout *timeout,
                             SObj     mallocCapability,
                             SObj     hostCapability);

/**
 * Create a listening TCP socket bound to a given port.
 *
 * The `mallocCapability` argument is used to allocate memory for the socket
 * and must have sufficient quota remaining for the socket.
 *
 * The `bindCapability` argument is a capability authorising the bind to a
 * specific server port.
 *
 * This returns a valid sealed capability to a socket on success, or a null on
 * failure.
 */
SObj __cheri_compartment("NetAPI")
  network_socket_listen_tcp(Timeout *timeout,
                            SObj     mallocCapability,
                            SObj     bindCapability);

/**
 * Accept a connection on a listening socket.
 *
 * This function will block until a connection is established or the timeout is
 * reached.
 *
 * The `address` and `port` arguments are used to return the address and port
 * of the connected client.  These can be null if the caller is not interested
 * in the client's address or port.
 *
 * This returns a valid sealed capability to a connected socket on success, or
 * a null on failure.
 */
SObj __cheri_compartment("TCPIP")
  network_socket_accept_tcp(Timeout        *timeout,
                            SObj            mallocCapability,
                            SObj            listeningSocket,
                            NetworkAddress *address,
                            uint16_t       *port);

/**
 * Create a bound UDP socket, allocated from the quota associated with
 * `mallocCapability`.  This will use IPv4 if `isIPv6` is false, or IPv6 if it
 * is true.
 *
 * Unlike the TCP variant, this does not require an authorising capability for
 * the host. UDP is connectionless and so there is no connection to authorise.
 * Instead, each remote host must be separately authorised with
 * `network_socket_udp_authorise_host`.
 *
 * Returns a valid sealed capability to a socket on success, or a null on
 * failure.
 */
SObj __cheri_compartment("TCPIP")
  network_socket_udp(Timeout *timeout, SObj mallocCapability, bool isIPv6);

/**
 * Authorise a UDP socket to send packets to a specific host.  This opens a
 * firewall hole allowing the socket to send and receive packets to the host.
 *
 * This also performs a DNS lookup and returns the result.  If the lookup fails
 * then the returned address will be invalid.
 *
 * Note: If we provided a full capability model for UDP then this would return
 * a capability that authorised sending and receiving packets to/from the host.
 * This would work well with `sendto`, simply taking the returned capability as
 * an argument.  It would require `recvfrom` to take a set of capabilities and
 * look up the correct one, which would be a lot more complex and hard to adapt
 * to existing code.  Instead, we treat the socket as a capability and this as
 * an operation that adds a permission to the capability.
 */
NetworkAddress __cheri_compartment("NetAPI")
  network_socket_udp_authorise_host(Timeout *timeout,
                                    SObj     socket,
                                    SObj     hostCapability);

/**
 * Close a socket.  This must be called with the same malloc capability that
 * was used to allocate the socket.
 *
 * Returns 0 on success, or a negative error code on failure:
 *
 *  - -EINVAL: Invalid argument (the socket is not valid, the malloc capability
 *             does not match the socket, or the timeout is invalid). When
 *             -EINVAL is returned, no resources were freed and the socket was
 *             not closed. The operation can be retried with correct arguments.
 *  - -ETIMEDOUT: The timeout was reached before the socket could be closed. No
 *             resources were freed and the socket was not closed. The operation
 *             can be retried.
 *  - -ENOTRECOVERABLE: An error occurred and the socket was partially freed or
 *             closed. The operation cannot be retried.
 */
int __cheri_compartment("TCPIP")
  network_socket_close(Timeout *t, SObj mallocCapability, SObj sealedSocket);

/**
 * The result of a receive call.
 */
struct NetworkReceiveResult
{
	/**
	 * The number of bytes received.  This may be negative if an error
	 * occurred.
	 */
	ssize_t bytesReceived;
	/**
	 * The buffer containing the received data.
	 */
	uint8_t *buffer;
};

/**
 * Receive data from a socket.  This will block until data are received or the
 * timeout expires.  If data are received, they will be stored in a buffer
 * allocated with the given malloc capability, the caller is responsible for
 * freeing this buffer.
 *
 * The `bytesReceived` field of the result will be negative if an error
 * occurred.  The `buffer` field will be null if no data were received.
 *
 * The negative values will be errno values:
 *
 *  - `-EINVAL`: The socket is not valid.
 *  - `-ETIMEDOUT`: The timeout was reached before data could be received.
 *  - `-ENOTCONN`: The socket is not connected.
 */
NetworkReceiveResult __cheri_compartment("TCPIP")
  network_socket_receive(Timeout *timeout, SObj mallocCapability, SObj socket);

/**
 * Receive data from a socket into a preallocated buffer.  This will block until
 * data are received or the timeout expires.  If data are received, they will be
 * stored in the provided buffer.
 *
 * NOTE: Callers should remove global and load permissions from `buffer` before
 * passing it to this function if they are worried about a potentially
 * compromised network stack.
 *
 * The return value is either the number of bytes received, or a negative error
 * code.
 *
 * The negative values will be errno values:
 *
 *  - `-EPERM`: `buffer` and/or `length` are invalid.
 *  - `-EINVAL`: The socket is not valid.
 *  - `-ETIMEDOUT`: The timeout was reached before data could be received.
 *  - `-ENOTCONN`: The socket is not connected.
 */
int __cheri_compartment("TCPIP")
  network_socket_receive_preallocated(Timeout *timeout,
                                      SObj     socket,
                                      void    *buffer,
                                      size_t   length);

/**
 * Receive data from a UDP socket.  This will block until data is received or
 * the timeout expires.  If data are received, they will be stored in a buffer
 * allocated with the given malloc capability, the caller is responsible for
 * freeing this buffer.
 *
 * The `address` and `port` arguments are used to return the address and port
 * of the sender.  These can be null if the caller is not interested in the
 * sender's address or port.
 *
 * The `bytesReceived` field of the result will be negative if an error
 * occurred.  The `buffer` field will be null if no data were received.
 *
 * Note that errors occuring in this function (particularly timeout and invalid
 * `address` or `port` pointers) may cause UDP packets to be dropped.
 *
 * The negative values will be errno values:
 *
 *  - `-ENOMEM`: The allocation quota is insufficient to hold the packet.
 *  - `-EPERM`: The `address` and/or `port` pointers are invalid.
 *  - `-EINVAL`: The socket is not valid.
 *  - `-ETIMEDOUT`: The timeout was reached before data could be received.
 *  - `-ENOTCONN`: The socket is not connected.
 */
NetworkReceiveResult __cheri_compartment("TCPIP")
  network_socket_receive_from(Timeout        *timeout,
                              SObj            mallocCapability,
                              SObj            socket,
                              NetworkAddress *address,
                              uint16_t       *port);

/**
 * Send data over a TCP socket.  This will block until the data have been sent
 * or the timeout expires.
 */
ssize_t __cheri_compartment("TCPIP") network_socket_send(Timeout *timeout,
                                                         SObj     socket,
                                                         void    *buffer,
                                                         size_t   length);

/**
 * Send data over a UDP socket to a specified host / port.  The address and
 * port must have been previously authorised with
 * `network_socket_udp_authorise_host` (the packets will be silently dropped if
 * not, there will be no error reported).
 *
 * This will block until the data have been sent or the timeout expires.  The
 * return value is the number of bytes sent or a negative error code.
 */
ssize_t __cheri_compartment("TCPIP")
  network_socket_send_to(Timeout              *timeout,
                         SObj                  socket,
                         const NetworkAddress *address,
                         uint16_t              port,
                         const void           *buffer,
                         size_t                length);

/**
 * Enumeration defining the connection type.
 */
enum ConnectionType : uint8_t
{
	/// TCP connection.
	ConnectionTypeTCP,
	/// UDP connection.
	ConnectionTypeUDP
};

/**
 * Returns the host name embedded in a host capability or null if this is not a
 * valid host capability.
 */
const char *__cheri_compartment("NetAPI") network_host_get(SObj hostCapability);

/**
 * Inject a memory-safety bug into the network stack.
 *
 * This is disabled unless compiled with the `network-inject-faults` option.
 */
void __cheri_compartment("TCPIP") network_inject_fault(void);

/**
 * Connection capability contents.  Instances of this sealed with the
 * NetworkConnectionKey sealing capability authorise access to a specific host
 * and port.
 *
 * This is probably too inflexible for the general case, but it's fine for the
 * prototype and can be extended once we have more feedback.  In particular,
 * UDP is not connection-oriented and so connecting to a single address with
 * UDP doesn't make sense in the general case (though it does in the specific
 * case of NTP and similar protocols).
 */
struct ConnectionCapability
{
	/**
	 * The type of connection (UDP or TCP) that this capability authorises.
	 */
	ConnectionType type;
	/**
	 * The remote port number that this capability authorises.  This is
	 * provided in host byte order.
	 */
	uint16_t port;
	/**
	 * The length of the hostname string (including the null terminator).
	 */
	size_t nameLength;
	/**
	 * The hostname that this capability authorises.  This is a null-terminated
	 * string.
	 */
	char hostname[];
};

/**
 * Bind capability contents. Instances of this sealed with the NetworkBindKey
 * sealing capability authorise binding to a specific server port.
 */
struct BindCapability
{
	/**
	 * Allow to bind on an IPv6 or IPv4 interface.
	 */
	bool isIPv6;
	/**
	 * The server port this bind capability allows to bind to. This is
	 * provided in host byte order.
	 */
	uint16_t port;
};

/**
 * Define a capability that authorises connecting to a specific host and port
 * with UDP or TCP.
 */
#define DECLARE_AND_DEFINE_CONNECTION_CAPABILITY(                              \
  name, authorisedHost, portNumber, connectionType)                            \
	DECLARE_AND_DEFINE_STATIC_SEALED_VALUE(                                    \
	  struct {                                                                 \
		  ConnectionType type;                                                 \
		  short          port;                                                 \
		  size_t         nameLength;                                           \
		  const char     hostname[sizeof(authorisedHost)];                     \
	  },                                                                       \
	  NetAPI,                                                                  \
	  NetworkConnectionKey,                                                    \
	  name,                                                                    \
	  connectionType,                                                          \
	  portNumber,                                                              \
	  sizeof(authorisedHost),                                                  \
	  authorisedHost)

/**
 * Define a capability that authorises binding to a specific server port with
 * TCP. Binding to a server port with UDP is not supported.
 */
#define DECLARE_AND_DEFINE_BIND_CAPABILITY(name, isIPv6Binding, portNumber)    \
	DECLARE_AND_DEFINE_STATIC_SEALED_VALUE(                                    \
	  struct {                                                                 \
		  bool     isIPv6;                                                     \
		  uint16_t port;                                                       \
	  },                                                                       \
	  NetAPI,                                                                  \
	  NetworkBindKey,                                                          \
	  name,                                                                    \
	  isIPv6Binding,                                                           \
	  portNumber)
