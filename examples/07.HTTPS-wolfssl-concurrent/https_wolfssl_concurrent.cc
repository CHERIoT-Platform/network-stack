// Copyright The Good Penguin Ltd
// SPDX-License-Identifier: MIT
//
// Concurrent wolfSSL TLS example opens two HTTPS connections simultaneously
// from separate threads to exercise the multi-threaded wolfSSL mutex support.
//
// We have to do the handshake stage sequentially because it takes long enough to 
// do both simultaneously that the server times out.
//
// We use example.com and example.org as they use the same Comodo AAA root cert
//
// Both threads log with a [A]/[B] tag so interleaving is visible on the UART.
//

#include <NetAPI.h>
#if __has_include(<allocator.h>)
#	include <allocator.h>
#endif
#include <cheri.hh>
#include <cstring>
#include <debug.hh>
#include <errno.h>
#include <fail-simulator-on-error.h>
#include <locks.hh>
#include <string_view>
#include <thread.h>
#include <tick_macros.h>
#include <sntp.h>
#include <tls_wolfssl.h>

// Bit dirty but just re-use the cert from example 06
#include "../06.HTTPS-wolfssl/Comodo_AAA_Services_root.h"

using Debug            = ConditionalDebug<true, "WolfTLS Concurrent">;
constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

DECLARE_AND_DEFINE_CONNECTION_CAPABILITY(ExampleComTLS,
                                         "example.com",
                                         443,
                                         ConnectionTypeTCP);

DECLARE_AND_DEFINE_CONNECTION_CAPABILITY(ExampleOrgTLS,
                                         "example.org",
                                         443,
                                         ConnectionTypeTCP);

// Separate allocators per connection to avoid allocator contention.
DECLARE_AND_DEFINE_ALLOCATOR_CAPABILITY(MallocA, 24 * 1024);
DECLARE_AND_DEFINE_ALLOCATOR_CAPABILITY(MallocB, 24 * 1024);
#define MALLOC_A STATIC_SEALED_VALUE(MallocA)
#define MALLOC_B STATIC_SEALED_VALUE(MallocB)

static FlagLockPriorityInherited handshakeLock;

static const WolfSSLTrustAnchor trustAnchors[] = {
    {COMODO_AAA_SERVICES_ROOT_DER, sizeof(COMODO_AAA_SERVICES_ROOT_DER)},
};

static void sync_network(const char *tag)
{
    Debug::log("[{}] Waiting for network...", tag);
    network_start();
    Timeout t{MS_TO_TICKS(5000)};
    while (sntp_update(&t) != 0)
    {
        Debug::log("[{}] Waiting for NTP...", tag);
        t = Timeout{MS_TO_TICKS(5000)};
    }
    Debug::log("[{}] Network and NTP ready", tag);
}

static bool run_connection(const char *tag,
                           AllocatorCapability        alloc,
                           ConnectionCapability       conn,
                           const char                *host,
                           const char                *request)
{
    Timeout unlimited{UnlimitedTimeout};

    WolfSSLConnection tlsConn = nullptr;
    {
        LockGuard g{handshakeLock, &unlimited};
        Debug::log("[{}] Creating TLS connection to {}...", tag, host);
        tlsConn = wolftls_connection_create(
            &unlimited, alloc, conn, trustAnchors, 1);
    }

    if (!CHERI::Capability{tlsConn}.is_valid())
    {
        Debug::log("[{}] Failed to create TLS connection", tag);
        return false;
    }
    Debug::log("[{}] TLS handshake complete", tag);

    size_t toSend = strlen(request);
    size_t sent   = 0;
    while (sent < toSend)
    {
        ssize_t r = wolftls_connection_send(
            &unlimited,
            tlsConn,
            // Cast away const: the API takes void* but does not mutate.
            const_cast<char *>(request) + sent,
            toSend - sent);
        if (r > 0)
            sent += r;
        else
        {
            Debug::log("[{}] Send failed: {}", tag, r);
            wolftls_connection_close(&unlimited, tlsConn);
            return false;
        }
    }
    Debug::log("[{}] Sent {} bytes, waiting for response", tag, sent);

    size_t totalReceived = 0;
    while (true)
    {
        auto [received, buffer] =
            wolftls_connection_receive(&unlimited, tlsConn);
        if (received > 0)
        {
            totalReceived += received;
            Debug::log("[{}] Received {} bytes:\n{}",
                       tag,
                       received,
                       std::string_view(reinterpret_cast<char *>(buffer), received));
            heap_free(alloc, buffer);
        }
        else if (received == 0 || received == -ENOTCONN)
        {
            Debug::log("[{}] Connection closed, total received: {} bytes",
                       tag, totalReceived);
            break;
        }
        else if (received == -ETIMEDOUT)
        {
            Debug::log("[{}] Receive timed out", tag);
        }
        else
        {
            Debug::log("[{}] Receive error: {}", tag, received);
            wolftls_connection_close(&unlimited, tlsConn);
            return false;
        }
    }

    wolftls_connection_close(&unlimited, tlsConn);
    Debug::log("[{}] Done. Free heap: {}", tag, heap_available());
    return totalReceived > 0;
}

void __cheri_compartment("https_wolfssl_concurrent") connection_a()
{
    sync_network("A");
    static const char request[] = "GET / HTTP/1.1\r\n"
                                  "Host: example.com\r\n"
                                  "User-Agent: cheriot-wolfssl-concurrent\r\n"
                                  "Connection: close\r\n"
                                  "Accept: */*\r\n"
                                  "\r\n";
    bool ok = run_connection("A",
                             MALLOC_A,
                             CONNECTION_CAPABILITY(ExampleComTLS),
                             "example.com",
                             request);
    Debug::log("[A] {}", ok ? "SUCCESS" : "FAILED");
}

void __cheri_compartment("https_wolfssl_concurrent") connection_b()
{
    sync_network("B");
    static const char request[] = "GET / HTTP/1.1\r\n"
                                  "Host: example.org\r\n"
                                  "User-Agent: cheriot-wolfssl-concurrent\r\n"
                                  "Connection: close\r\n"
                                  "Accept: */*\r\n"
                                  "\r\n";
    bool ok = run_connection("B",
                             MALLOC_B,
                             CONNECTION_CAPABILITY(ExampleOrgTLS),
                             "example.org",
                             request);
    Debug::log("[B] {}", ok ? "SUCCESS" : "FAILED");
}
