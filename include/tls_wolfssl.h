#pragma once
#include <NetAPI.h>
#include <cheri.h>
#include <timeout.h>

/* Create a sealed WolfSSLContext that is created & sealed in the WolfSSLTLS 
 * compartment.  It is returned to the calling compartment when 
 * wolftls_connection_create is called and handed back when calling the other 
 * API functions.
 */
typedef CHERI_SEALED(struct WolfSSLContext *) WolfSSLConnection;

/* Trust anchor is a certificate that you unconditionally trust (typically a 
 * root CA certificate) It is a DER-encoded X.509 certificate. wolfSSL parses 
  the raw bytes internally.
 */
typedef struct {
    const unsigned char *certDer;
    size_t               certDerLength;
} WolfSSLTrustAnchor;

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
 * `trustAnchorsCount` DER-encoded CA certificates.
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
 *  - The reason for the failure is not reported.
 */
__cheri_compartment("WolfSSLTLS")
WolfSSLConnection wolftls_connection_create(
    Timeout *t, 
    AllocatorCapability allocator,
    ConnectionCapability connectionCapability,
    const WolfSSLTrustAnchor *trustAnchors, 
    size_t trustAnchorsCount);

/**
 * Sends `length` bytes from `buffer` to the remote host. Returns the
 * number of bytes sent, or a negative error code.
 *
 * The `sealedConnection` parameter is a pointer to a TLS connection, returned
 * by `wolftls_connection_create`.

 *  - `-EINVAL`: Invalid timeout pointer or invalid/unsealed connection
 *  - `-ETIMEDOUT`: Lock acquisition timeout or timeout mid-write exits loop, 
 *                  returning bytes sent so far
 *  - `-EPERM`: Buffer lacks Load permission
 *  - `-EIO`: wolfSSL write error before any bytes were sent
 *
 */
__cheri_compartment("WolfSSLTLS")
ssize_t wolftls_connection_send(
    Timeout *t, 
    WolfSSLConnection sealedConnection, 
    void *buffer, 
    size_t length);

/**
 * Receive data from the TLS connection.  This will block until data are
 * received, an error happens, or the timeout expires. If data are received,
 * they will be stored in a newly allocated buffer (allocated with the
 * allocator provided to `wolftls_connection_create`) and returned along with their
 * length.  The caller is responsible for freeing this buffer. On error, the
 * return value is an untagged value and a negative error code.
 *
 * The negative values will be errno values:
 *
 *  - `-EINVAL`: The socket is not valid.
 *  - `-ETIMEDOUT`: The timeout was reached before data could be received.
 *  - `-ENOMEM`: Memory was insufficient to allocate the receive buffer.
 *  - `-ENOTCONN`: The TLS layer returned an unexpected error
 */
__cheri_compartment("WolfSSLTLS")
NetworkReceiveResult wolftls_connection_receive(
    Timeout *t, 
    WolfSSLConnection sealedConnection);

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
__cheri_compartment("WolfSSLTLS")
int wolftls_connection_receive_preallocated(
    Timeout *t, 
    WolfSSLConnection sealedConnection, 
    void *buffer, 
    size_t length);

/**
 * Close a TLS connection.
 */
__cheri_compartment("WolfSSLTLS")
int wolftls_connection_close(
    Timeout *t, 
    WolfSSLConnection sealed);
