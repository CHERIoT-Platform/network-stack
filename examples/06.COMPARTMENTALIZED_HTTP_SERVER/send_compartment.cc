#include "timeout.h"
#include <NetAPI.h>
#include <debug.hh>
#include <fail-simulator-on-error.h>

using Debug =
  ConditionalDebug<true, "HTTP server example test (send compartment)">;

/**
 * HTTP response. We always send the same response for this simplified example.
 *
 * Cannot be const due to type constraints of `network_socket_send`.
 */
static char reply[] =
  "HTTP/1.1 200 OK\r\n"
  "Content-type: text/html\r\n"
  "Connection: close\r\n"
  "\r\n"
  "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
  "<html>"
  "<head><title>Hello from CHERIoT!</title></head>"
  "<body><h1>It works!</h1><p>Served from a CHERIoT device.</p></body>"
  "</html>\n";

void __cheri_compartment("send_compartment")
  http_send_get_response(Socket socket)
{
	Timeout          unlimited{UnlimitedTimeout};
	constexpr size_t ToSend = sizeof(reply) - 1;
	size_t           sent   = 0;
	while (sent < ToSend)
	{
		size_t remaining = ToSend - sent;

		ssize_t sentThisCall =
		  network_socket_send(&unlimited, socket, &(reply[sent]), remaining);

		if (sentThisCall >= 0)
		{
			Debug::log("Served {} bytes of static content.", sentThisCall);
			sent += sentThisCall;
		}
		else
		{
			Debug::log("Send failed: {}", sentThisCall);
			break;
		}
	}
}
