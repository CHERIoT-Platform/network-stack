// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include "../third_party/BearSSL/inc//bearssl_x509.h"
#include "NetAPI.h"
#include <token.h>

/// Opaque type for sealed TLS contexts.
struct TLSContext;

typedef CHERI_SEALED(struct TLSContext *) TLSConnection;

/**
 * Creates a new TLS connection. This will block until the connection is
 * established, an error happens, or the timeout expires. Returns an untagged
 * value on failure or a sealed TLS connection object on success.
 *
 * The state for the TLS connection will be allocated with `allocator`.  The
 * connection will be made to the host identified by the connection capability,
 * which must authorise a TCP connection.  Once the connection is made, the
 * certificates will be validated against the trust anchors provided via the
 * `trustAnchors` parameter, which contains a pointer to an array of
 * `trustAnchorsCount` trust anchors.
 *
 * This can fail if:
 *
 *  - The connection capability is not a valid TCP connection capability.
 *  - The allocator capability does not have enough quota to satisfy the
 * allocations.
 *  - The remote host is not accessible.
 *  - The remote host's certificate is not trusted by the trust anchors.
 *
 *  This function assumes that the trust anchors are valid and will not be
 *  freed during the call.  If this is not the case, then this function can
 *  abort *without* gracefully freeing the resources it has allocated. These
 *  are allocated with the callee's allocator and so the caller is able to
 *  mount a denial of service attack on itself via a concurrent free.
 *
 * Known problems with this API:
 *
 *  - The BearSSL types are leaked into the API.
 *  - The reason for the failure is not reported.
 */
TLSConnection __cheri_compartment("TLS")
  tls_connection_create(Timeout                    *t,
                        AllocatorCapability         allocator,
                        ConnectionCapability        connectionCapability,
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
 * Sends `length` bytes from `buffer` to the remote host. Returns the
 * number of bytes sent, or a negative error code.
 *
 * The `sealedConnection` parameter is a pointer to a TLS connection, returned
 * by `tls_connection_create`.
 *
 * If `flags` is set to `TLSSendNoFlush`, the TLS engine may buffer the data
 * and not send until a later send call.  If this is not provided then the
 * timeout may be exceeded. In the general case, this will block until the data
 * is sent, an error happens, or the timeout expires.
 */
ssize_t __cheri_compartment("TLS")
  tls_connection_send(Timeout      *t,
                      TLSConnection sealedConnection,
                      void         *buffer,
                      size_t        length,
                      int           flags);

/**
 * Receive data from the TLS connection.  This will block until data are
 * received, an error happens, or the timeout expires. If data are received,
 * they will be stored in a newly allocated buffer (allocated with the
 * allocator provided to `tls_connection_create`) and returned along with their
 * length.  The caller is responsible for freeing this buffer. On error, the
 * return value is an untagged value and a negative error code.
 *
 * The negative values will be errno values:
 *
 *  - `-EINVAL`: The socket is not valid.
 *  - `-ETIMEDOUT`: The timeout was reached before data could be received.
 *  - `-ENOMEM`: Memory was insufficient to allocate the receive buffer.
 */
NetworkReceiveResult __cheri_compartment("TLS")
  tls_connection_receive(Timeout *t, TLSConnection sealedConnection);

/**
 * Receive data from the TLS connection into a preallocated buffer. This will
 * block until data are received, an error happens, or the timeout expires. If
 * data are received, they will be stored in the provided buffer.
 *
 * The return value is either the number of bytes received, zero if the
 * connection is closed, or a negative error code.
 *
 * The negative values will be errno values:
 *
 *  - `-EINVAL`: The socket is not valid.
 *  - `-ETIMEDOUT`: The timeout was reached before data could be received.
 *  - `-EPERM`: The receive buffer provided does not feature write permissions.
 */
int __cheri_compartment("TLS")
  tls_connection_receive_preallocated(Timeout      *t,
                                      TLSConnection sealedConnection,
                                      void         *buffer,
                                      size_t        length);
/**
 * Close a TLS connection.
 */
int __cheri_compartment("TLS")
  tls_connection_close(Timeout *t, TLSConnection sealed);
