// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

/**
 * This file contains the code necessary for initialising the network stack.
 */
#include <FreeRTOS.h>
#include <FreeRTOS_IP.h>
#include <FreeRTOS_ND.h>

#include <debug.hh>
#include <platform-ethernet.hh>
#include <tcpip-internal.h>

#include "../firewall/firewall.hh"

using Debug = ConditionalDebug<false, "TCP/IP Stack startup">;

extern "C" void ip_cleanup(void);

/**
 * Exposed by the driver adaptor.  Uses a CHERIoT driver to provide a FreeRTOS
 * driver interface.
 */
NetworkInterface_t *fill_interface_descriptor(BaseType_t          xEMACIndex,
                                              NetworkInterface_t *pxInterface);
namespace
{
	/**
	 * Flags for the state of startup.
	 */
	enum [[clang::flag_enum]] StartupState{
	  Uninitialised = 0,
	  Starting      = 1,
	  DoneIPv4      = 2,
	  DoneIPv6      = 4,
	};
	/**
	 * A simple state machine represented with some bits in a bitfield for the
	 * network startup.  IPv4 and v6 initialisation both complete at different
	 * rates, so this is used to determine whether both are done.
	 */
	std::atomic<uint32_t> state;
	/**
	 * The IPv4 endpoint for the FreeRTOS network stack.
	 */
	NetworkEndPoint_t endpointIPv4;
	/**
	 * The IPv6 endpoint for the FreeRTOS network stack.
	 */
	NetworkEndPoint_t endpointIPv6;
	/**
	 * The IPv6 link-local endpoint for the FreeRTOS network stack.
	 */
	NetworkEndPoint_t endpointIPv6LinkLocal;
	/**
	 * Flag indicating whether to use IPv6 or not, set in xmake.
	 */
	constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

	/**
	 * The singleton network interface descriptor for the FreeRTOS network
	 * stack.
	 */
	NetworkInterface_t interface;

	// Default values for the network configuration.  These will be overridden
	// by DHCP.
	const uint8_t IPAddress[4]        = {192, 168, 1, 248};
	const uint8_t NetMask[4]          = {255, 255, 255, 0};
	const uint8_t GatewayAddress[4]   = {192, 168, 0, 1};
	const uint8_t DNSServerAddress[4] = {8, 8, 8, 8};

} // namespace

void __cheri_compartment("TCPIP") network_start()
{
	// Guard aginst multiple calls
	uint32_t expected = Uninitialised;
	if (!state.compare_exchange_strong(expected, Starting))
	{
		return;
	}

	Debug::log("Initialising network adaptor");
	fill_interface_descriptor(0, &interface);
	Debug::log("Output function: {}",
	           reinterpret_cast<void *>(interface.pfOutput));
	Debug::log("Setting up endpointIPv4");
	FreeRTOS_FillEndPoint(&interface,
	                      &endpointIPv4,
	                      IPAddress,
	                      NetMask,
	                      GatewayAddress,
	                      DNSServerAddress,
	                      EthernetDevice::mac_address_default().data());
	// Enable DHCP
	endpointIPv4.bits.bWantDHCP = pdTRUE;

	// FIXME: Factor this out into a template so that we can get rid of the
	// ifdefs.
#if CHERIOT_RTOS_OPTION_IPv6
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
		  EthernetDevice::mac_address_default().data());
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
		  EthernetDevice::mac_address_default().data());
	}
#endif

	Debug::log("Kicking IP stack");
	if (FreeRTOS_IPInit_Multi() == pdPASS)
	{
		Debug::log("Successfully initialized IP stack\n");
	}
	else
	{
		Debug::log("Failed to initialize IP stack\n");
	}
	if (restartState.load() == 0)
	{
		// Wait until the network is fully initialised.
		constexpr uint32_t RequiredBits =
		  UseIPv6 ? DoneIPv4 | DoneIPv6 : DoneIPv4;
		for (uint32_t stateBits = state.load();
		     (stateBits & RequiredBits) != RequiredBits;
		     stateBits = state.load())
		{
			state.wait(stateBits);
		}
	}

	Debug::log("Network stack startup finished");
}

/**
 * Call `network_start`, after ensuring that globals are reset to a pristine
 * state.
 */
void network_restart()
{
	state = Uninitialised;
	ip_cleanup();
	network_start();
}

void vApplicationIPNetworkEventHook_Multi(eIPCallbackEvent_t eNetworkEvent,
                                          struct xNetworkEndPoint *pxEndPoint)
{
	auto setBit = [](StartupState bit) {
		uint32_t expected = StartupState::Starting;
		uint32_t desired  = expected | bit;
		while (!state.compare_exchange_strong(expected, desired))
		{
			desired = expected | bit;
		}
		state.notify_all();
	};
	static int ipv6Events = 0;
	if (eNetworkEvent == eNetworkUp)
	{
		if (pxEndPoint == &endpointIPv4)
		{
			Debug::log("IPv4 network up");
			setBit(StartupState::DoneIPv4);
			uint32_t dnsIP;
			FreeRTOS_GetEndPointConfiguration(
			  nullptr, nullptr, nullptr, &dnsIP, &endpointIPv4);
			Debug::log("DNS server address: {}", dnsIP);
			firewall_dns_server_ip_set(dnsIP);
		}
		else if constexpr (UseIPv6)
		{
			if (pxEndPoint == &endpointIPv6)
			{
				Debug::log("IPv6 network up");
				ipv6Events++;
			}
			else if (pxEndPoint == &endpointIPv6LinkLocal)
			{
				ipv6Events++;
				Debug::log("IPv6 link-local network up");
			}
			if (ipv6Events == 2)
			{
				setBit(StartupState::DoneIPv6);
			}
		}
	}

	if (restartState.load() != 0)
	{
		constexpr uint32_t RequiredBits =
		  UseIPv6 ? DoneIPv4 | DoneIPv6 : DoneIPv4;
		if ((state.load() & RequiredBits) == RequiredBits)
		{
			Debug::log("Now officially done restarting");
			restartState.store(NotRestarting);
		}
	}
}
