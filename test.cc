#include "NetAPI.h"
#include "sntp.h"
#include "timeout.h"
#include <debug.hh>
#include <errno.h>
#include <thread.h>
#include <tick_macros.h>

using Debug            = ConditionalDebug<true, "Network test">;
constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;


DECLARE_AND_DEFINE_CONNECTION_CAPABILITY(ExampleCom,
                                         "example.com",
                                         80,
                                         ConnectionTypeTCP);

DECLARE_AND_DEFINE_ALLOCATOR_CAPABILITY(TestMalloc, 4 * 1024);

#define TEST_MALLOC STATIC_SEALED_VALUE(TestMalloc)

void __cheri_compartment("test") test_network()
{
	network_start();
	Timeout t{MS_TO_TICKS(5000)};
	while (sntp_update(&t) != 0)
	{
		Debug::log("Failed to update NTP time");
		Timeout oneSecond{MS_TO_TICKS(1000)};
	}
	Debug::log("Updating NTP took {} ticks", t.elapsed);
	t = UnlimitedTimeout;
	for (int i = 0; i < 100; i++)
	{
		timeval tv;
		int    ret = gettimeofday(&tv, nullptr);
		if (ret != 0)
		{
			Debug::log("Failed to get time of day: {}", ret);
		}
		else
		{
			// Truncate the epoch time to 32 bits for printing.
			Debug::log("Current UNIX epoch time: {}", (int32_t)tv.tv_sec);
		}
		Timeout oneSecond{MS_TO_TICKS(1000)};
		thread_sleep(&oneSecond);
	}

	auto    socket = network_socket_connect_tcp(
	     &t, TEST_MALLOC, STATIC_SEALED_VALUE(ExampleCom));

	static char      message[] = "GET / HTTP/1.1\r\n"
	                             "Host: example.com\r\n"
	                             "User-Agent: cheriot-demo\r\n"
	                             "Accept: */*\r\n"
	                             "\r\n";
	constexpr size_t toSend    = sizeof(message) - 1;
	size_t           sent      = 0;
	while (sent < toSend)
	{
		size_t remaining = toSend - sent;

		size_t sentThisCall =
		  network_socket_send(&t, socket, &(message[sent]), remaining);

		if (sentThisCall >= 0)
		{
			sent += sentThisCall;
		}
		else
		{
			Debug::log("Send failed: {}", sentThisCall);
			break;
		}
	}


	ssize_t contentLength = -1;

	while (true)
	{
		auto [received, buffer] =
		  network_socket_receive(&t, TEST_MALLOC, socket);
		if (received > 0)
		{
			if (contentLength < 0)
			{
				static const char Header[] = "Content-Length: ";
				auto *strBuffer = reinterpret_cast<char *>(buffer);
				if (char *headerStart = strnstr(strBuffer, Header, received) ; headerStart != nullptr)
				{
					char *length = headerStart + sizeof(Header) - 1;
					contentLength = 0;
					while (*length > '0' && *length < '9')
					{
						contentLength *= 10;
						contentLength += *length - '0';
						length++;
					}
					char *headerEnd = strnstr(headerStart, "\r\n\r\n", received - (headerStart - strBuffer));
					if (headerEnd != nullptr)
					{
						Debug::log("Content length: {}", contentLength);
					}
					// Skip the initial header
					headerEnd += 4;
					received -= headerEnd - strBuffer;
					buffer = reinterpret_cast<unsigned char *>(headerEnd);
				}
				else
				{
					Debug::log("No content length header found");
					break;
				}
			}
			Debug::log(
			  "Received:\n{}",
			  std::string_view(reinterpret_cast<char *>(buffer), received));
			contentLength -= received;
			int ret = heap_free(TEST_MALLOC, buffer);
			if (ret != 0)
			{
				Debug::log("Failed to free buffer: {}", ret);
				break;
			}
			if (contentLength <= 0)
			{
				Debug::log("Received all content");
				break;
			}
		}
		else if (received == 0 || received == -ENOTCONN)
		{
			Debug::log("Connection closed, shutting down");
			break;
		}
		else if (received == -ETIMEDOUT)
		{
			Debug::log("Receive timed out, trying again");
		}
		else
		{
			Debug::log("Receive failed: {}", received);
			break;
		}
	}
	network_socket_close(&t, TEST_MALLOC, socket);
}
