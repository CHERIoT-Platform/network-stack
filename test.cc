#include "NetAPI.h"
#include <debug.hh>
#include <errno.h>

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
	Timeout t{UnlimitedTimeout};
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
	while (true)
	{
		auto [received, buffer] =
		  network_socket_receive(&t, TEST_MALLOC, socket);
		if (received > 0)
		{
			Debug::log("Received {} bytes in: {}", received, buffer);
			Debug::log(
			  "Received:\n{}",
			  std::string_view(reinterpret_cast<char *>(buffer), received));
			int ret = heap_free(TEST_MALLOC, buffer);
			if (ret != 0)
			{
				Debug::log("Failed to free buffer: {}", ret);
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
