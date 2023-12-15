#include <FreeRTOS.h>
#include <FreeRTOS_IP.h>
#include <FreeRTOS_ND.h>

#include <debug.hh>
#include <platform-ethernet.hh>

using Debug = ConditionalDebug<true, "Network test">;

extern "C" NetworkInterface_t *
pxCHERIoT_FillInterfaceDescriptor(BaseType_t          xEMACIndex,
                                  NetworkInterface_t *pxInterface);
namespace
{
	std::atomic<uint32_t> DHCPDone;
	std::atomic<uint32_t> IPv6Done;
	NetworkEndPoint_t     endpointIPv4;
	NetworkEndPoint_t     endpointIPv6;
	NetworkEndPoint_t     endpointIPv6LinkLocal;
	constexpr bool        UseIPv6 = true;
} // namespace

void __cheri_compartment("TCPIP") test_ethernet()
{
	static NetworkInterface_t interface;
	// Default values for the network configuration.  These will be overridden
	// by DHCP.
	static const uint8_t ucIPAddress[4]        = {192, 168, 1, 248};
	static const uint8_t ucNetMask[4]          = {255, 255, 255, 0};
	static const uint8_t ucGatewayAddress[4]   = {192, 168, 0, 1};
	static const uint8_t ucDNSServerAddress[4] = {8, 8, 8, 8};

	printf("Testing printf...\n");
	Debug::log("Initialising network adaptor");
	pxCHERIoT_FillInterfaceDescriptor(0, &interface);
	Debug::log("Output function: {}", (void *)interface.pfOutput);
	Debug::log("Setting up endpointIPv4");
	FreeRTOS_FillEndPoint(&interface,
	                      &endpointIPv4,
	                      ucIPAddress,
	                      ucNetMask,
	                      ucGatewayAddress,
	                      ucDNSServerAddress,
	                      KunyanEthernet::mac_address_default().data());
	// Enable DHCP
	endpointIPv4.bits.bWantDHCP = pdTRUE;

	if constexpr (UseIPv6)
	{
		IPv6_Address_t xIPAddress;
		IPv6_Address_t xPrefix;
		IPv6_Address_t xGateWay;
		IPv6_Address_t xDNSServer1, xDNSServer2;

		FreeRTOS_inet_pton6("2001:470:ed44::", xPrefix.ucBytes);

		FreeRTOS_CreateIPv6Address(&xIPAddress, &xPrefix, 64, pdTRUE);
		FreeRTOS_inet_pton6("fe80::ba27:ebff:fe5a:d751", xGateWay.ucBytes);

		FreeRTOS_FillEndPoint_IPv6(
		  &interface,
		  &endpointIPv6,
		  &(xIPAddress),
		  &(xPrefix),
		  64uL, /* Prefix length. */
		  &(xGateWay),
		  NULL, /* pxDNSServerAddress: Not used yet. */
		  KunyanEthernet::mac_address_default().data());
		FreeRTOS_inet_pton6(
		  "2001:4860:4860::8888",
		  endpointIPv6.ipv6_settings.xDNSServerAddresses[0].ucBytes);
		FreeRTOS_inet_pton6(
		  "fe80::1", endpointIPv6.ipv6_settings.xDNSServerAddresses[1].ucBytes);
		FreeRTOS_inet_pton6(
		  "2001:4860:4860::8888",
		  endpointIPv6.ipv6_defaults.xDNSServerAddresses[0].ucBytes);
		FreeRTOS_inet_pton6(
		  "fe80::1", endpointIPv6.ipv6_defaults.xDNSServerAddresses[1].ucBytes);
		endpointIPv6.bits.bWantRA = pdTRUE;
	}
	if constexpr (UseIPv6)
	{
		IPv6_Address_t xIPAddress;
		IPv6_Address_t xPrefix;

		FreeRTOS_inet_pton6("fe80::", xPrefix.ucBytes);
		FreeRTOS_inet_pton6("fe80::7009", xIPAddress.ucBytes);

		FreeRTOS_FillEndPoint_IPv6(
		  &interface,
		  &endpointIPv6LinkLocal,
		  &(xIPAddress),
		  &(xPrefix),
		  10U,  /* Prefix length. */
		  NULL, /* No gateway */
		  NULL, /* pxDNSServerAddress: Not used yet. */
		  KunyanEthernet::mac_address_default().data());
	}

	Debug::log("Kicking IP stack");
	if (FreeRTOS_IPInit_Multi() == pdPASS)
	{
		Debug::log("Successfully initialized IP stack\n");
	}
	else
	{
		Debug::log("Failed to initialize IP stack\n");
	}
	while (DHCPDone != 1)
	{
		DHCPDone.wait(0);
	}
	if constexpr (UseIPv6)
	{
		while (IPv6Done != 2)
		{
			IPv6Done.wait(0);
		}
	}
	Debug::log("Network stack startup finished");

	Socket_t socket = FreeRTOS_socket(
	  FREERTOS_AF_INET, FREERTOS_SOCK_STREAM, FREERTOS_IPPROTO_TCP);
	thread_millisecond_wait(5000);
	if (socket == FREERTOS_INVALID_SOCKET)
	{
		Debug::log("Failed to create socket");
	}
	else
	{
		Debug::log("Successfully created socket");
	}
	struct freertos_sockaddr server;
	memset(&server, 0, sizeof(server));
	server.sin_len               = sizeof(server);
		server.sin_port              = FreeRTOS_htons(1235);
	if constexpr (UseIPv6)
	{
		server.sin_family = FREERTOS_AF_INET6;
		FreeRTOS_inet_pton6("2a00:23c6:54dd:1001:4b2:cca6:132c:589",
		                    server.sin_address.xIP_IPv6.ucBytes);
	}
	else
	{
		server.sin_family            = FREERTOS_AF_INET;
		server.sin_address.ulIP_IPv4 = FreeRTOS_inet_addr_quick(192, 168, 1, 83);
	}
	Debug::log("Trying to connect to server");
	do
	{
		if (int ret = FreeRTOS_connect(socket, &server, sizeof(server));
		    ret != 0)
		{
			Debug::log("Failed to connect to server.  Error: {}.  Retrying",
			           ret);
			FreeRTOS_closesocket(socket);
			socket = FreeRTOS_socket(
			  FREERTOS_AF_INET, FREERTOS_SOCK_STREAM, FREERTOS_IPPROTO_TCP);
			if (socket == FREERTOS_INVALID_SOCKET)
			{
				Debug::log("Failed to create socket");
			}
			thread_millisecond_wait(1000);
		}
		else
		{
			break;
		}
	} while (true);
	Debug::log("Successfully connected to server");
	static char      message[] = "Hello, world!";
	constexpr size_t toSend    = sizeof(message) - 1;
	size_t           sent      = 0;
	while (sent < toSend)
	{
		size_t remaining = toSend - sent;

		size_t sentThisCall =
		  FreeRTOS_send(socket, &(message[sent]), remaining, 0);

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
	FreeRTOS_closesocket(socket);

	while (true)
	{
		Timeout t(MS_TO_TICKS(1000));
		thread_sleep(&t);
	}
}

void vApplicationIPNetworkEventHook_Multi(eIPCallbackEvent_t eNetworkEvent,
                                          struct xNetworkEndPoint *pxEndPoint)
{
	if (eNetworkEvent == eNetworkUp)
	{
		if (pxEndPoint == &endpointIPv4)
		{
			Debug::log("IPv4 network up");
			DHCPDone = 1;
			DHCPDone.notify_all();
		}
		else if (pxEndPoint == &endpointIPv6)
		{
			IPv6Done++;
			Debug::log("IPv6 network up");
		}
		else if (pxEndPoint == &endpointIPv6LinkLocal)
		{
			IPv6Done++;
			Debug::log("IPv6 link-local network up");
		}
	}
}
