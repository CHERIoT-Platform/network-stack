// Copyright The Good Penguin Ltd
// SPDX-License-Identifier: MIT

#include <NetAPI.h>
#include <allocator.h>
#include <cheri.hh>
#include <debug.hh>
#include <locks.hh>
#include <sealed_cleanup.hh>
#include <token.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>

#include <tls_wolfssl.h>
#include "wolfssl_glue.h"

using namespace CHERI;

constexpr bool DebugWolfTLS =
#ifdef DEBUG_WolfSSLTLS
  DEBUG_WolfSSLTLS
#else
  false
#endif
  ;

using Debug = ConditionalDebug<DebugWolfTLS, "WolfSSLTLS">;

struct WolfSSLContext
{
    WOLFSSL_CTX              *sslCtx;
    WOLFSSL                  *ssl;
    AllocatorCapability       allocator;
    Socket                    socket;
    FlagLockPriorityInherited lock;

    WolfSSLContext() : sslCtx(nullptr), ssl(nullptr) {}
    ~WolfSSLContext();
};

WolfSSLContext::~WolfSSLContext()
{
    if (ssl)
        wolfSSL_free(ssl);
    if (sslCtx)
        wolfSSL_CTX_free(sslCtx);
    Timeout t{UnlimitedTimeout};
    network_socket_close(&t, allocator, socket);
    wolfSSL_Cleanup();
}

namespace
{
    __always_inline auto wolf_key()
    {
        return STATIC_SEALING_TYPE(WolfSSLConnection);
    }

    // IO callbacks bridging wolfSSL record I/O to CHERIoT NetAPI sockets.
    extern "C" int wolfssl_io_recv(WOLFSSL *, char *buf, int sz, void *ctx)
    {
        auto   *c = static_cast<WolfSSLContext *>(ctx);
        // Use a local Timeout so check_timeout_pointer in the network
        // compartment receives a stack-derived capability.
        Timeout localT{0};
        if (heap_claim_ephemeral(&localT, buf) != 0)
            return WOLFSSL_CBIO_ERR_GENERAL;
        Capability rbuf{buf};
        rbuf.bounds().set_inexact_at_most(sz);
        sz = static_cast<int>(rbuf.length());
        rbuf.permissions() &= Permission::Store;
        Debug::log("Receiving {} bytes into {}", sz, rbuf);
        int r =
          network_socket_receive_preallocated(&localT, c->socket, rbuf, sz);
        Debug::log("Network stack returned {}", r);
        if (r > 0)
            return r;
        if (r == -ENOTCONN)
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        if (r == -ETIMEDOUT)
            return WOLFSSL_CBIO_ERR_WANT_READ;
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    extern "C" int wolfssl_io_send(WOLFSSL *, char *buf, int sz, void *ctx)
    {
        auto *c  = static_cast<WolfSSLContext *>(ctx);
        // Use a local Timeout so check_timeout_pointer in the network
        // compartment receives a stack-derived capability.
        Timeout localT{0};
        if (heap_claim_ephemeral(&localT, buf) != 0)
            return WOLFSSL_CBIO_ERR_GENERAL;
        Capability rbuf{buf};
        rbuf.bounds().set_inexact_at_most(sz);
        sz = static_cast<int>(rbuf.length());
        rbuf.permissions() &= Permission::Load;
        Debug::log("Sending {} bytes of records", sz);
        int r = network_socket_send(&localT,
                                    c->socket,
                                    rbuf,
                                    sz);
        Debug::log("Send returned {}", r);
        if (r > 0)
            return r;
        if (r == -ETIMEDOUT)
            return WOLFSSL_CBIO_ERR_WANT_WRITE;
        if (r == -ENOTCONN)
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    ssize_t with_sealed_context(Timeout          *t,
                                WolfSSLConnection conn,
                                auto              fn)
    {
        Sealed<WolfSSLContext> sealedCtx{conn};
        auto *ctx = token_unseal(wolf_key(), sealedCtx);
        if (!ctx)
        {
            Debug::log("Failed to unseal WolfSSL context");
            return -EINVAL;
        }
        Debug::log("unseal:ctx ptr=0x{:x}", (uintptr_t)ctx);
        if (LockGuard g{ctx->lock, t})
        {
            wolfssl_set_fallback_heap(ctx->allocator);
            return fn(ctx);
        }
        Debug::log("Timed out acquiring WolfSSL context lock");
        return -ETIMEDOUT;
    }

} // namespace

WolfSSLConnection wolftls_connection_create(Timeout                  *t,
                                            AllocatorCapability       allocator,
                                            ConnectionCapability      connectionCapability,
                                            const WolfSSLTrustAnchor *trustAnchors,
                                            size_t                    trustAnchorsCount)
{
    Debug::log("wolftls_connection_create: entered, t={}", t);
    if (!check_timeout_pointer(t))
    {
        Debug::log("wolftls_connection_create: check_timeout_pointer failed");
        return nullptr;
    }

    if (wolfSSL_Init() != WOLFSSL_SUCCESS)
    {
        Debug::log("wolfSSL_Init failed");
        return nullptr;
    }

    const char *hostname = network_host_get(connectionCapability);
    if (!hostname)
    {
        Debug::log("Failed to get hostname from connection capability");
        return nullptr;
    }

    auto socketDeleter = [&](Socket s) {
        Timeout unlimited{UnlimitedTimeout};
        network_socket_close(&unlimited, allocator, s);
        t->elapse(unlimited.elapsed);
    };
    SealedOwner<SealedSocket, decltype(socketDeleter)> socket{
      network_socket_connect_tcp(t, allocator, connectionCapability), socketDeleter};
    if (!socket)
    {
        Debug::log("TCP connect failed");
        return nullptr;
    }

    wolfssl_set_fallback_heap(allocator);

    WOLFSSL_CTX *sslCtx =
      wolfSSL_CTX_new_ex(wolfTLSv1_3_client_method_ex(allocator), allocator);
    if (!sslCtx)
    {
        Debug::log("wolfSSL_CTX_new_ex failed");
        return nullptr;
    }
    auto ctxDeleter = [](WOLFSSL_CTX *c) { wolfSSL_CTX_free(c); };
    std::unique_ptr<WOLFSSL_CTX, decltype(ctxDeleter)> sslCtxOwner{sslCtx,
                                                                    ctxDeleter};

    wolfSSL_CTX_SetIORecv(sslCtx, wolfssl_io_recv);
    wolfSSL_CTX_SetIOSend(sslCtx, wolfssl_io_send);
    wolfSSL_CTX_set_verify(sslCtx, WOLFSSL_VERIFY_PEER, nullptr);

    for (size_t i = 0; i < trustAnchorsCount; ++i)
    {
        int r = wolfSSL_CTX_load_verify_buffer(sslCtx,
                                               trustAnchors[i].certDer,
                                               (long)trustAnchors[i].certDerLength,
                                               WOLFSSL_FILETYPE_ASN1);
        if (r != WOLFSSL_SUCCESS)
        {
            Debug::log("Failed to load trust anchor {}: {}", i, r);
            return nullptr;
        }
    }

    WOLFSSL *ssl = wolfSSL_new(sslCtx);
    if (!ssl)
    {
        Debug::log("wolfSSL_new failed");
        return nullptr;
    }
    auto sslDeleter = [](WOLFSSL *s) { wolfSSL_free(s); };
    std::unique_ptr<WOLFSSL, decltype(sslDeleter)> sslOwner{ssl, sslDeleter};

    if (wolfSSL_check_domain_name(ssl, hostname) != WOLFSSL_SUCCESS)
    {
        Debug::log("wolfSSL_check_domain_name failed");
        return nullptr;
    }
    if (wolfSSL_UseSNI(ssl,
                       WOLFSSL_SNI_HOST_NAME,
                       hostname,
                       (word16)strlen(hostname)) != WOLFSSL_SUCCESS)
    {
        Debug::log("wolfSSL_UseSNI failed");
        return nullptr;
    }

    auto [unsealed, sealed] =
      token_allocate<WolfSSLContext>(t, allocator, wolf_key());
    auto rawSealed = sealed.get();
    if (rawSealed == nullptr)
    {
        Debug::log("Failed to allocate sealed WolfSSL context");
        return nullptr;
    }

    WolfSSLContext *ctx    = new (unsealed) WolfSSLContext{};
    ctx->sslCtx            = sslCtxOwner.release();
    ctx->ssl               = sslOwner.release();
    ctx->allocator         = allocator;
    ctx->socket            = socket.release();

    auto cleanup = [&](decltype(sealed)) {
        ctx->~WolfSSLContext();
        token_obj_destroy(allocator, wolf_key(), rawSealed);
    };
    SealedOwner<WolfSSLContext, decltype(cleanup)> sealedCtx{rawSealed,
                                                             cleanup};

    wolfSSL_SetIOReadCtx(ssl, ctx);
    wolfSSL_SetIOWriteCtx(ssl, ctx);
    wolfssl_set_fallback_heap(allocator);

    // Handshake loop, wolfSSL_connect drives the TLS 1.3 state machine,
    // calling wolfssl_io_recv/send as needed.
    while (true)
    {
        int ret = wolfSSL_connect(ssl);
        if (ret == WOLFSSL_SUCCESS)
            break;
        int err = wolfSSL_get_error(ssl, ret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
        {
            if (t->may_block())
            {
                Timeout shortSleep{1};
                thread_sleep(&shortSleep);
                t->elapse(shortSleep.elapsed);
                continue;
            }
            Debug::log("Handshake timed out");
            return nullptr;
        }
        Debug::log("Handshake failed, wolfSSL error {}", err);
        return nullptr;
    }

    Debug::log("TLS 1.3 handshake complete for {}", hostname);
    return sealedCtx.release();
}

ssize_t wolftls_connection_send(Timeout          *t,
                                WolfSSLConnection sealedConnection,
                                void             *buffer,
                                size_t            length)
{
    if (!check_timeout_pointer(t))
        return -EINVAL;

    return with_sealed_context(t, sealedConnection, [&](WolfSSLContext *ctx) -> ssize_t {
        int ret = heap_claim_ephemeral(t, buffer);
        if (ret != 0)
            return ret;
        if (!check_pointer<PermissionSet{Permission::Load}>(buffer, length))
            return -EPERM;

        size_t sent = 0;
        while (sent < length)
        {
            Debug::log("wolfSSL_write {} bytes", length - sent);
            int r = wolfSSL_write(
              ctx->ssl, static_cast<const char *>(buffer) + sent, length - sent);
            Debug::log("wolfSSL_write returned {}", r);
            if (r > 0)
            {
                sent += r;
                continue;
            }
            int err = wolfSSL_get_error(ctx->ssl, r);
            if (err == WOLFSSL_ERROR_WANT_WRITE || err == WOLFSSL_ERROR_WANT_READ)
            {
                if (t->may_block())
                {
                    Timeout shortSleep{1};
                    thread_sleep(&shortSleep);
                    t->elapse(shortSleep.elapsed);
                    continue;
                }
                break;
            }
            Debug::log("wolfSSL_write error {}", err);
            return sent > 0 ? static_cast<ssize_t>(sent) : -EIO;
        }
        return static_cast<ssize_t>(sent);
    });
}

int wolftls_connection_receive_preallocated(Timeout          *t,
                                            WolfSSLConnection sealedConnection,
                                            void             *buffer,
                                            size_t            length)
{
    if (!check_timeout_pointer(t))
        return -EINVAL;

    return with_sealed_context(t, sealedConnection, [&](WolfSSLContext *ctx) -> ssize_t {
        int ret = heap_claim_ephemeral(t, buffer);
        if (ret != 0)
            return ret;
        if (!check_pointer<PermissionSet{Permission::Store}>(buffer, length))
            return -EPERM;

        Debug::log("wolfSSL_read into {} byte buffer", length);
        while (true)
        {
            int r = wolfSSL_read(ctx->ssl, buffer, (int)length);
            Debug::log("wolfSSL_read returned {}", r);
            if (r > 0)
                return r;
            int err = wolfSSL_get_error(ctx->ssl, r);
            if (err == WOLFSSL_ERROR_WANT_READ)
            {
                if (t->may_block())
                {
                    Timeout shortSleep{1};
                    thread_sleep(&shortSleep);
                    t->elapse(shortSleep.elapsed);
                    continue;
                }
                return -ETIMEDOUT;
            }
            if (err == WOLFSSL_ERROR_ZERO_RETURN)
                return 0;
            Debug::log("wolfSSL_read error {}", err);
            return -ENOTCONN;
        }
    });
}

NetworkReceiveResult wolftls_connection_receive(Timeout          *t,
                                                WolfSSLConnection sealedConnection)
{
    uint8_t *buffer = nullptr;
    ssize_t  result =
      with_sealed_context(t, sealedConnection, [&](WolfSSLContext *ctx) -> ssize_t {
          // If the heap is near exhaustion don't block
          Timeout      zeroTimeout{0};
          int          available = 4096;
          while (true)
          {
              buffer = static_cast<uint8_t *>(
                heap_allocate(&zeroTimeout, ctx->allocator, available));
              t->elapse(zeroTimeout.elapsed);
              if (Capability{buffer}.is_valid())
                  break;
              if (available > 128)
              {
                  available = 128;
                  continue;
              }
              auto quota = heap_quota_remaining(ctx->allocator);
              if (quota > 16 && (size_t)available > quota - 16)
              {
                  available = quota - 16;
                  continue;
              }
              return t->may_block() ? -ENOMEM : -ETIMEDOUT;
          }

          Debug::log("wolfSSL_read into {} byte buffer", available);
          while (true)
          {
              int r = wolfSSL_read(ctx->ssl, buffer, available);
              Debug::log("wolfSSL_read returned {}", r);
              if (r > 0)
                  return r;
              int err = wolfSSL_get_error(ctx->ssl, r);
              if (err == WOLFSSL_ERROR_WANT_READ)
              {
                  if (t->may_block())
                  {
                      Timeout shortSleep{1};
                      thread_sleep(&shortSleep);
                      t->elapse(shortSleep.elapsed);
                      continue;
                  }
                  heap_free(ctx->allocator, buffer);
                  buffer = nullptr;
                  return -ETIMEDOUT;
              }
              if (err == WOLFSSL_ERROR_ZERO_RETURN)
              {
                  heap_free(ctx->allocator, buffer);
                  buffer = nullptr;
                  return 0;
              }
              Debug::log("wolfSSL_read error {}", err);
              heap_free(ctx->allocator, buffer);
              buffer = nullptr;
              return -ENOTCONN;
          }
      });
    return {result, buffer};
}

int wolftls_connection_close(Timeout *t, WolfSSLConnection sealed)
{
    if (!check_timeout_pointer(t))
        return -EINVAL;

    Sealed<WolfSSLContext> sealedCtx{sealed};
    auto                  *ctx = token_unseal(wolf_key(), sealedCtx);
    if (!ctx)
    {
        Debug::log("close: failed to unseal");
        return -EINVAL;
    }

    if (!ctx->lock.try_lock(t))
        return -ETIMEDOUT;

    wolfssl_set_fallback_heap(ctx->allocator);

    // wolfSSL_shutdown drives the close_notify exchange,
    // calling wolfssl_io_recv/send as needed, same pattern as the handshake.
    while (true)
    {
        int ret = wolfSSL_shutdown(ctx->ssl);
        if (ret == WOLFSSL_SUCCESS)
            break;
        if (ret == WOLFSSL_SHUTDOWN_NOT_DONE)
        {
            // Local close_notify sent; waiting for peer's reply.
            if (t->may_block())
            {
                Timeout shortSleep{1};
                thread_sleep(&shortSleep);
                t->elapse(shortSleep.elapsed);
                continue;
            }
            Debug::log("Timed out waiting for peer close_notify");
            break;
        }
        int err = wolfSSL_get_error(ctx->ssl, ret);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE)
        {
            if (t->may_block())
            {
                Timeout shortSleep{1};
                thread_sleep(&shortSleep);
                t->elapse(shortSleep.elapsed);
                continue;
            }
            Debug::log("Timed out during TLS shutdown");
            break;
        }
        // SOCKET_ERROR_E / SOCKET_PEER_CLOSED_E: TCP was already torn down
        // by the peer after it sent its close_notify
        if (err == SOCKET_ERROR_E || err == SOCKET_PEER_CLOSED_E)
            break;
        Debug::log("wolfSSL_shutdown error {}", err);
        break;
    }

    ctx->lock.upgrade_for_destruction();
    auto alloc = ctx->allocator;
    ctx->~WolfSSLContext();
    token_obj_destroy(alloc, wolf_key(), sealed);
    return 0;
}
