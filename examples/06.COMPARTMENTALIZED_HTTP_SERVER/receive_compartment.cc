#include "timeout.h"
#include <NetAPI.h>
#include <errno.h>
#if __has_include(<allocator.h>)
#	include <allocator.h>
#endif
#include "http_server.h"
#include <debug.hh>

using CHERI::Capability;

using Debug =
  ConditionalDebug<true, "HTTP server example test (receive compartment)">;

int __cheri_compartment("receive_compartment")
  http_receive_and_parse_request(Socket                    socket,
                                 AllocatorCapability       allocatorCapability,
                                 struct ParsedHTTPRequest *request)
{
	Timeout unlimited{UnlimitedTimeout};
	auto [received, buffer] =
	  network_socket_receive(&unlimited, allocatorCapability, socket);

	if (Capability{buffer}.is_valid())
	{
		Debug::log("Received {} bytes from the client.", received);

		// We assume that we have received at least enough bytes to
		// parse the first line of the request, and fail otherwise. A
		// real server would properly check that and wait for more
		// bytes if needed.

		int ret = -EPROTO;

		// Parse the request. This is error-prone: great we are doing
		// this in a compartment! Since this is just an example, we do
		// not fully parse the HTTP request: just look at the method
		// type and URI.
		uint32_t offset = 0;
		for (uint32_t position = 0; position < received; position++)
		{
			if (buffer[position] == ' ')
			{
				if (offset == 0)
				{
					// Parse the request method.
					buffer[position]    = '\0';
					request->methodType = http_request_method_type_from_string(
					  reinterpret_cast<const char *>(buffer));
					offset = position + 1;
					continue;
				}
				// Parse the URI.
				buffer[position] = '\0';
				strncpy(request->targetResource,
				        reinterpret_cast<char *>(buffer + offset),
				        sizeof(request->targetResource));

				ret = 0;
				break;
			}
		}

		int freeRet = heap_free(allocatorCapability, buffer);
		if (freeRet != 0)
		{
			// This may happen if the network stack crashed: if the network
			// stack crashes during `network_socket_receive`, `buffer` will
			// likely be a nullptr or any untagged value, and `heap_free`
			// will return an error when passed the invalid thing.
			Debug::log("Failed to free receive buffer: {}", ret);
			return freeRet;
		}

		return ret;
	}
	else
	{
		Debug::log("Failed to receive request from the client, error {}.",
		           received);
	}

	return received;
}
