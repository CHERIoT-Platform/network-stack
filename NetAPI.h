#pragma once
#include <compartment-macros.h>
#include <timeout.h>
#include <token.h>

/**
 * Start the network.  This is a temporary API.  It will eventually be replaced
 * by a non-blocking version.
 */
void __cheri_compartment("TCPIP") network_start();

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
 * Close a socket.  This must be called with the same malloc capability that
 * was used to allocate the socket.
 *
 * Returns 0 on success, or a negative error code on failure:
 *
 *  - -EINVAL: The socket is not valid or the malloc capability does not match
 *    the socket.
 *  - -ETIMEDOUT: The timeout was reached before the socket could be closed.
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
 * Receive data from a socket.  This will block until data is received or the
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
 * Send data over the socket.  This will block until the data have been sent or
 * the timeout expires.
 */
ssize_t __cheri_compartment("TCPIP") network_socket_send(Timeout *timeout,
                                                         SObj     socket,
                                                         void    *buffer,
                                                         size_t   length);

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
	short port;
	/**
	 * The length of the hostname string (including the null terminator).
	 */
	size_t nameLength;
	/**
	 * The hostname that this capability authorises.  This is a null-terminated
	 * string.
	 */
	const char hostname[];
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
 * Structure wrapping a network address and a descriminator.
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
