#include "NetAPI.h"
#include "cdefs.h"
#include "third_party/BearSSL/inc//bearssl_x509.h"
#include <token.h>

/**
 * Creates a new TLS connection.  Returns null on failure or a sealed TLS
 * connection object on success.
 *
 * The state for the TLS connection will be allocated with `allocator`.  The
 * connection will be made to the host identified by the connection capability.
 * This must authorise a TCP connection.  Once the connection is made, the
 * certificates will be validated against the trust anchors provided via the
 * `trustAnchors` parameter, which contains a pointer to an array of
 * `trustAnchorsCount` trust anchors.
 *
 * This can fail if:
 *
 *  - The connection capability is not a valid TCP connection capability.
 *  - The allocator capability does not have enough quota to satisfy the allocations.
 *  - The remote host is not accessible.
 *  - The remote host's certificate is not trusted by the trust anchors.
 * 
 * Known problems with this API:
 *
 *  - The BearSSL types are leaked into the API.
 *  - The reason for the failure is not reported.
 */
SObj __cheri_compartment("TLS")
  tls_connection_create(Timeout                    *t,
                        SObj                        allocator,
                        SObj                        connectionCapability,
                        const br_x509_trust_anchor *trustAnchors,
                        size_t                      trustAnchorsCount);

/**
 * Flags that can control the behaviour of `tls_connection_send`.
 */
enum TLSSendFlags
{
	/**
	 * By default, each send call will force the TLS engine to flush data,
	 * preventing it from being locally buffered.  Set this flag if you are
	 * calling `tls_connection_send` repeatedly and want to minimise the
	 * number of packets sent, at the cost of increased latency.
	 */
	TLSSendNoFlush = 1,
};

/**
 * Sends `length` bytes from `buffer` to the remote host.  Returns the number
 * of bytes sent, or a negative error code.  The `sealedConnection` parameter
 * is a pointer to a TLS connection, returned by `tls_connection_create`.
 *
 * If `flags` is set to `TLSSendNoFlush`, the TLS engine may buffer the data
 * and not send until a later send call.  If this is not provided then the
 * timeout may be exceeded.
 */
ssize_t __cheri_compartment("TLS") tls_connection_send(Timeout *t,
                                                       SObj   sealedConnection,
                                                       void  *buffer,
                                                       size_t length,
                                                       int    flags);

/**
 * Receive data from the TLS connection.  This returns a newly allocated buffer
 * (allocated with the allocator provided to `tls_connection_create`)
 * containing the received data along with its length, or null and a negative
 * error code.  The caller is responsible for freeing this buffer.
 */
NetworkReceiveResult __cheri_compartment("TLS")
  tls_connection_receive(Timeout *t, SObj sealedConnection);

/**
 * Close a TLS connection.
 */
int __cheri_compartment("TLS") tls_connection_close(Timeout *t, SObj sealed);
