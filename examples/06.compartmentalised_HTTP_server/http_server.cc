#include "http_server.h"
#include "timeout.h"
#include <NetAPI.h>
#if __has_include(<allocator.h>)
#	include <allocator.h>
#endif
#include <debug.hh>
#include <fail-simulator-on-error.h>
#include <thread.h>
#include <tick_macros.h>

using CHERI::Capability;

using Debug            = ConditionalDebug<true, "HTTP server example test">;
constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

/**
 * Bind capability for the server port 80. Use IPv6 if enabled in the
 * configuration, and allow at most two simultaneous connections to the server.
 */
#define LISTEN_PORT 80
DECLARE_AND_DEFINE_BIND_CAPABILITY(HTTPPort, UseIPv6, LISTEN_PORT, 10);

DECLARE_AND_DEFINE_ALLOCATOR_CAPABILITY(TestMalloc, 32 * 1024);
#define TEST_MALLOC STATIC_SEALED_VALUE(TestMalloc)

/**
 * Maximum number of clients the server will server before shutting down. This
 * is useful to check that the server can handle multiple clients before
 * terminating.
 */
static const uint16_t MaxClients = 10;

/**
 * This example server is written to showcase the network stack server API, but
 * also the network stack restart. If one of the network stack APIs fails in a
 * way likely caused by a crash, the server will wait this small delay before
 * retrying to give time to the network stack to reset.
 */
static const uint16_t RestartDelay = 100; // in ticks

/**
 * Helper to call after a presumed network stack crash to wait a little bit
 * until it completed a reset.
 */
inline void sleep_after_crash()
{
	Timeout sleep{RestartDelay};
	thread_sleep(&sleep);
};

/**
 * Helper to close a socket with support for network stack crashes.
 *
 * The close() API returns immediately with -EAGAIN if the network stack is
 * currently resetting, hence the need for the loop. Ideally users would not
 * have to write that helper or loop - this should be fixed in the network
 * stack API.
 */
inline bool network_socket_close_retry(auto socket)
{
	Timeout unlimited{UnlimitedTimeout};
	int     retries = 10;
	for (; retries > 0; retries--)
	{
		int ret = network_socket_close(&unlimited, TEST_MALLOC, socket);
		if (ret == 0)
		{
			return true;
		}
		else if (ret != -EAGAIN)
		{
			return false;
		}
		// The network stack is still resetting.
		sleep_after_crash();
	}
	return false;
};

void debug_network_address(uintptr_t value, DebugWriter &writer)
{
	auto *address = reinterpret_cast<NetworkAddress *>(value);
	if (address->kind == NetworkAddress::AddressKindIPv6)
	{
		for (int i = 0; i < 14; i += 2)
		{
			writer.write_hex_byte(address->ipv6[i]);
			writer.write_hex_byte(address->ipv6[i + 1]);
			writer.write(':');
		}
		writer.write_hex_byte(address->ipv6[14]);
		writer.write_hex_byte(address->ipv6[15]);
	}
	else if (address->kind == NetworkAddress::AddressKindIPv4)
	{
		writer.write_decimal((address->ipv4 >> 0) & 0xff);
		writer.write('.');
		writer.write_decimal((address->ipv4 >> 8) & 0xff);
		writer.write('.');
		writer.write_decimal((address->ipv4 >> 16) & 0xff);
		writer.write('.');
		writer.write_decimal((address->ipv4 >> 24) & 0xff);
	}
	else
	{
		writer.write("<invalid address>");
	}
};

template<>
struct DebugFormatArgumentAdaptor<NetworkAddress>
{
	static DebugFormatArgument construct(NetworkAddress &address)
	{
		return {reinterpret_cast<uintptr_t>(&address),
		        reinterpret_cast<uintptr_t>(debug_network_address)};
	}
};

void __cheri_compartment("compartmentalized_http_server_example") example()
{
	// TODO We can eliminate this object once network APIs have been ported
	// to the new timeout API.
	Timeout unlimited{UnlimitedTimeout};

	network_start();

	auto heapAtStart = heap_quota_remaining(TEST_MALLOC);

	Debug::log("Starting the server.");

	// If the network stack crashes, the listening socket will be closed
	// (as will all accepted sockets). The outer loop recreates the
	// listening socket if this happens, up until we have handled the
	// correct number of clients.
	uint16_t clientsCounter = 0;
	while (clientsCounter < MaxClients)
	{
		Debug::log("Creating a listening socket.");
		auto socket = network_socket_listen_tcp(
		  &unlimited, TEST_MALLOC, STATIC_SEALED_VALUE(HTTPPort));

		if (!Capability{socket}.is_valid())
		{
			Debug::log("Failed to create a listening socket.");
			// This may have failed because of a network stack
			// crash. Sleep a little bit to enable a reset.
			sleep_after_crash();
			continue;
		}

		Debug::log("Listening on port {}...", LISTEN_PORT);
		while (clientsCounter < MaxClients)
		{
			NetworkAddress clientAddress = {0};
			uint16_t       clientPort    = 0;

			auto clientSocket = network_socket_accept_tcp(
			  &unlimited, TEST_MALLOC, socket, &clientAddress, &clientPort);

			if (!Capability{clientSocket}.is_valid())
			{
				Debug::log("Failed to accept a connection.");
				sleep_after_crash();
				break;
			}

			Debug::log("Established a connection with {}, port {}",
			           clientAddress,
			           static_cast<int>(clientPort));

			clientsCounter++;

			// Restrict the permissions we give to the receive and
			// send compartments. The receive compartment only
			// needs a socket that authorizes receiving and an
			// allocator capability for allocating and freeing. The
			// send compartment only needs a socket for sending.
			//
			// TODO We should also be removing the global
			// permissions from these capabilities, but a current
			// compiler limitation prevents us from doing so.
			//
			// This implementation requires four compartment
			// switches (server -> receiver -> server -> sender ->
			// server). We could reduce this to three (server ->
			// receiver -> sender -> server) by sharing the sockets
			// through shared variables and having the receive
			// compartment call the send compartment directly.
			struct ParsedHTTPRequest request{};
			int                      received = http_receive_and_parse_request(
			  network_socket_permissions_and(clientSocket, SocketPermitReceive),
			  allocator_permissions_and(TEST_MALLOC, AllocatorPermitAllocate),
			  &request);
			if (received == 0)
			{
				// In a real system, different method types
				// could be processed by different handlers,
				// each with different privileges in a
				// different compartment.
				if (request.methodType == HTTPRequestMethodType::GET)
				{
					Debug::log(
					  "Received a GET request for resource {}.",
					  std::string_view{request.targetResource,
					                   sizeof(request.targetResource)});
					http_send_get_response(network_socket_permissions_and(
					  clientSocket, SocketPermitSend));
				}
				else
				{
					Debug::log(
					  "Received a request for an unsupported method "
					  "type on resource {}.",
					  std::string_view{request.targetResource,
					                   sizeof(request.targetResource)});
				}
			}

			Debug::log("Terminating the connection with the client.");
			if (!network_socket_close_retry(clientSocket))
			{
				Debug::log("Failed to close the client socket.");
			}
		}

		Debug::log("Closing the listening socket.");
		if (!network_socket_close_retry(socket))
		{
			Debug::log("Failed to close the listening socket.");
		}
	}

	Debug::log("Now checking for leaks.");
	auto heapAtEnd = heap_quota_remaining(TEST_MALLOC);
	if (heapAtEnd < heapAtStart)
	{
		Debug::log("Warning: The implementation leaked {} bytes (start: {} vs. "
		           "end: {}).",
		           heapAtStart - heapAtEnd,
		           heapAtEnd,
		           heapAtStart);
	}
	else
	{
		Debug::log("No leaks detected.");
	}

	Debug::log("Terminating the server.");
}
