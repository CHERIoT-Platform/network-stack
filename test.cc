#include <FreeRTOS.h>
#include <FreeRTOS_IP.h>
#include <FreeRTOS_ND.h>

#include <debug.hh>
#include <platform-ethernet.hh>

using Debug = ConditionalDebug<true, "Network test">;

extern "C" NetworkInterface_t *
pxCHERIoT_FillInterfaceDescriptor(BaseType_t          xEMACIndex,
                                  NetworkInterface_t *pxInterface);

void __cheri_compartment("TCPIP") test_ethernet()
{
	static NetworkInterface_t interface;
	static NetworkEndPoint_t  endpointIPv4;
	static NetworkEndPoint_t  endpointIPv6;
	static NetworkEndPoint_t  endpointIPv6LinkLocal;
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

	if constexpr (false)
	{
		IPv6_Address_t xIPAddress;
		IPv6_Address_t xPrefix;
		IPv6_Address_t xGateWay;
		IPv6_Address_t xDNSServer1, xDNSServer2;

		FreeRTOS_inet_pton6("2001:470:ed44::", xPrefix.ucBytes);

		FreeRTOS_CreateIPv6Address(&xIPAddress, &xPrefix, 64, pdTRUE);
		FreeRTOS_inet_pton6("fe80::ba27:ebff:fe5a:d751", xGateWay.ucBytes);

		FreeRTOS_FillEndPoint_IPv6(&interface,
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
	if constexpr (false)
	{
		IPv6_Address_t xIPAddress;
		IPv6_Address_t xPrefix;

		FreeRTOS_inet_pton6("fe80::", xPrefix.ucBytes);
		FreeRTOS_inet_pton6("fe80::7009", xIPAddress.ucBytes);

		FreeRTOS_FillEndPoint_IPv6(&interface,
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
	while (true)
	{
		Timeout t(MS_TO_TICKS(1000));
		thread_sleep(&t);
	}
}
