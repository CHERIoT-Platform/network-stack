#include <NetAPI.h>

/**
 * HTTP request method types.
 */
enum class HTTPRequestMethodType
{
	GET,
	/* Placeholder for unsupported method types. */
	UNSUPPORTED
};

static const HTTPRequestMethodType
http_request_method_type_from_string(const char *string)
{
	if (strcmp(string, "GET") == 0)
	{
		return HTTPRequestMethodType::GET;
	}
	else
	{
		return HTTPRequestMethodType::UNSUPPORTED;
	}
}

/**
 * Parsed HTTP request. *Highly*-simplified for the needs of the example.
 */
struct ParsedHTTPRequest
{
	/**
	 * Request method type.
	 */
	HTTPRequestMethodType methodType = HTTPRequestMethodType::UNSUPPORTED;
	/**
	 * Request target resource.
	 *
	 * This extremely simplified implementation of a URI encapsulates a
	 * path with up to 14 ASCII characters and a null terminator.
	 *
	 * This is not how one would implements URIs in a real web server.
	 */
	char targetResource[15] = {0};
};

/**
 * Receive an HTTP message from a given socket and parse it.
 *
 * Takes a socket, an allocator capability, and an HTTP request object which is
 * filled with the parsed HTTP request on success. `request` is clobbered on
 * failure.
 *
 * Returns 0 on success and a negative error code on failure.
 */
int __cheri_compartment("receive_compartment")
  http_receive_and_parse_request(Socket                    socket,
                                 AllocatorCapability       allocatorCapability,
                                 struct ParsedHTTPRequest *request);

/**
 * Send an HTTP response to a given socket and a given request.
 */
void __cheri_compartment("send_compartment")
  http_send_get_response(Socket socket);
