// Copyright The Good Penguin Ltd
// SPDX-License-Identifier: MIT
//
// wolfSSL HTTPS example, mirrors examples/03.HTTPS/https.cc but uses the WolfSSLTLS compartment instead of BearSSL TLS.
//

#include <NetAPI.h>
#if __has_include(<allocator.h>)
#	include <allocator.h>
#endif
#include <debug.hh>
#include <errno.h>
#include <fail-simulator-on-error.h>
#include <memory>
#include <string_view>
#include <thread.h>
#include <tick_macros.h>
#include <sntp.h>
#include <tls_wolfssl.h>

#include "Comodo_AAA_Services_root.h"

using Debug            = ConditionalDebug<true, "WolfTLS Example">;
constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

DECLARE_AND_DEFINE_CONNECTION_CAPABILITY(ExampleComTLS,
                                         "example.com",
                                         443,
                                         ConnectionTypeTCP);

DECLARE_AND_DEFINE_ALLOCATOR_CAPABILITY(TestMalloc, 32 * 1024);
#define TEST_MALLOC STATIC_SEALED_VALUE(TestMalloc)

void __cheri_compartment("https_wolfssl_example") example()
{
    Debug::log("Waiting for network...");
    network_start();

    // Cert date validation requires correct time.
    {
        Timeout t{MS_TO_TICKS(5000)};
        while (sntp_update(&t) != 0)
        {
            Debug::log("Waiting for NTP...");
            t = Timeout{MS_TO_TICKS(5000)};
        }
    }

    Debug::log("Attempting to connect to example.com:443 via wolfSSL TLS 1.3");

    static const WolfSSLTrustAnchor trustAnchors[] = {
      {COMODO_AAA_SERVICES_ROOT_DER, sizeof(COMODO_AAA_SERVICES_ROOT_DER)},
    };

    Timeout unlimited{UnlimitedTimeout};
    auto    tlsConn = wolftls_connection_create(
      &unlimited,
      TEST_MALLOC,
      CONNECTION_CAPABILITY(ExampleComTLS),
      trustAnchors,
      1);

    if (!__builtin_cheri_tag_get(tlsConn))
    {
        Debug::log("Failed to create TLS connection");
        return;
    }
    Debug::log("TLS handshake complete");

    static char request[] = "GET / HTTP/1.1\r\n"
                            "Host: example.com\r\n"
                            "User-Agent: cheriot-wolfssl\r\n"
                            "Connection: close\r\n"
                            "Accept: */*\r\n"
                            "\r\n";
    constexpr size_t toSend = sizeof(request) - 1;
    size_t           sent   = 0;
    while (sent < toSend)
    {
        ssize_t r = wolftls_connection_send(
          &unlimited, tlsConn, &request[sent], toSend - sent);
        if (r > 0)
            sent += r;
        else
        {
            Debug::log("Send failed: {}", r);
            break;
        }
    }
    Debug::log("Sent {} bytes, waiting for response", sent);

    while (true)
    {
        auto [received, buffer] =
          wolftls_connection_receive(&unlimited, tlsConn);
        if (received > 0)
        {
            Debug::log(
              "Received {} bytes:\n{}",
              received,
              std::string_view(reinterpret_cast<char *>(buffer), received));
            heap_free(TEST_MALLOC, buffer);
        }
        else if (received == 0 || received == -ENOTCONN)
        {
            Debug::log("Connection closed");
            break;
        }
        else if (received == -ETIMEDOUT)
        {
            Debug::log("Receive timed out");
        }
        else
        {
            Debug::log("Receive error: {}", received);
            break;
        }
    }

    wolftls_connection_close(&unlimited, tlsConn);
    Debug::log("Done. Free heap: {}", heap_available());
}
