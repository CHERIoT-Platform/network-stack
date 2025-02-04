#include "timeout.h"
#include <NetAPI.h>
#include <debug.hh>
#include <errno.h>
#include <fail-simulator-on-error.h>
#include <memory>
#include <string_view>
#include <thread.h>
#include <tick_macros.h>

using Debug            = ConditionalDebug<true, "Network test">;
constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

DECLARE_AND_DEFINE_CONNECTION_CAPABILITY(ExampleCom,
                                         "www.example.com",
                                         80,
                                         ConnectionTypeTCP);

DECLARE_AND_DEFINE_ALLOCATOR_CAPABILITY(TestMalloc, 32 * 1024);

#define TEST_MALLOC STATIC_SEALED_VALUE(TestMalloc)

void __cheri_compartment("http_example") example()
{
	network_start();
	Debug::log("Creating connection");
	Timeout unlimited{UnlimitedTimeout};
	auto    socket = network_socket_connect_tcp(
	     &unlimited, TEST_MALLOC, CONNECTION_CAPABILITY(ExampleCom));

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

		ssize_t sentThisCall =
		  network_socket_send(&unlimited, socket, &(message[sent]), remaining);
		Debug::log("Sent {} bytes", sentThisCall);

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
	Debug::log("Sent {} bytes of HTTP request, waiting for response", sent);

	ssize_t contentLength = -1;

	while (true)
	{
		auto [received, buffer] =
		  network_socket_receive(&unlimited, TEST_MALLOC, socket);
		if (received > 0)
		{
			// WARNING: This assumes that the Content-Length header is in the
			// first read.  This happens to be true for this server, but it's
			// absolutely *not* something that is true in the general case.
			if (contentLength < 0)
			{
				Debug::log(
				  "Looking for Content-Length in:\n{}",
				  std::string_view(reinterpret_cast<char *>(buffer), received));
				static const char Header[]  = "Content-Length: ";
				auto             *strBuffer = reinterpret_cast<char *>(buffer);
				if (char *headerStart = strnstr(strBuffer, Header, received);
				    headerStart != nullptr)
				{
					char *length  = headerStart + sizeof(Header) - 1;
					contentLength = 0;
					while (*length > '0' && *length < '9')
					{
						contentLength *= 10;
						contentLength += *length - '0';
						length++;
					}
					Debug::log("Content length: {}", contentLength);
					char *headerEnd =
					  strnstr(headerStart,
					          "\r\n\r\n",
					          received - (headerStart - strBuffer));
					if (headerEnd != nullptr)
					{
						// Skip the initial header
						headerEnd += 4;
						received -= headerEnd - strBuffer;
						buffer = reinterpret_cast<unsigned char *>(headerEnd);
					}
					else
					{
						Debug::log("No end of header found");
						break;
					}
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
	Debug::log("Free heap space: {}", heap_available());
	network_socket_close(&unlimited, TEST_MALLOC, socket);
	Debug::log("Free heap space: {}", heap_available());
}
