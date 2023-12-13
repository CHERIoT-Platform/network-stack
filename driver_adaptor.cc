// Native APIs
#include <atomic>
#include <compartment-macros.h>
#include <debug.hh>
#include <fail-simulator-on-error.h>
#include <futex.h>
#include <locks.hh>
#include <platform-ethernet.hh>
#include <timeout.h>

// FreeRTOS APIs
#include <FreeRTOS.h>
#include <FreeRTOS_DHCP.h>
#include <FreeRTOS_IP.h>
#include <FreeRTOS_ND.h>
#include <NetworkBufferManagement.h>

namespace
{
	using Debug = ConditionalDebug<false, "Ethernet Adaptor">;

	enum class EtherType : uint16_t
	{
		Minimum = 0x0600,
		IPv4    = 0x0800,
		IPv6    = 0x86DD,
		ARP     = 0x0806,
	};

	const char *ethertype_as_string(EtherType etherType)
	{
		switch (etherType)
		{
			case EtherType::IPv4:
				return "IPv4";
			case EtherType::IPv6:
				return "IPv6";
			case EtherType::ARP:
				return "ARP";
			default:
				return "Unknown";
		}
	}

	std::atomic<uint32_t> barrier;

	auto &lazy_network_interface()
	{
		static EthernetDevice interface;
		return interface;
	}

	BaseType_t initialise(struct xNetworkInterface *pxDescriptor)
	{
		Debug::log("Initialising network interface");
		auto &ethernet = lazy_network_interface();
		ethernet.mac_address_set();
		barrier = 1;
		barrier.notify_one();
		return pdPASS;
	}

	FlagLockPriorityInherited sendLock;

	[[cheri::interrupt_state(disabled)]] void print_frame(const uint8_t *data,
	                                                      size_t         length)
	{
		return;
		static FlagLockPriorityInherited   printLock;
		LockGuard                          g{printLock};
		MessageBuilder<ImplicitUARTOutput> out;
		static char                        digits[] = "0123456789abcdef";
		for (int i = 0; i < length; i++)
		{
			if ((i % 8) == 0)
			{
				out.write('\n');
			}
			out.write(digits[data[i] >> 4]);
			out.write(digits[data[i] & 0xf]);
			out.write(' ');
		}
		out.write('\n');
	}

	BaseType_t output_frame(struct xNetworkInterface *,
	                        NetworkBufferDescriptor_t *const pxNetworkBuffer,
	                        BaseType_t                       xReleaseAfterSend)
	{
		Debug::log("Acquiring send lock");
		LockGuard g{sendLock};
		Debug::log("Sending frame: ");
		print_frame(pxNetworkBuffer->pucEthernetBuffer,
		            pxNetworkBuffer->xDataLength);

		auto &ethernet = lazy_network_interface();
		ethernet.send_frame(pxNetworkBuffer->pucEthernetBuffer,
		                    pxNetworkBuffer->xDataLength);
		if (xReleaseAfterSend)
		{
			vReleaseNetworkBufferAndDescriptor(pxNetworkBuffer);
		}
		return pdPASS;
	}

	BaseType_t phy_link_status(struct xNetworkInterface *pxInterface)
	{
		auto &ethernet = lazy_network_interface();
		Debug::log("Querying link status ({})", ethernet.phy_link_status());
		return ethernet.phy_link_status();
	}

	NetworkInterface_t *thisInterface = nullptr;

} // namespace

NetworkInterface_t *
pxCHERIoT_FillInterfaceDescriptor(BaseType_t          xEMACIndex,
                                  NetworkInterface_t *pxInterface)
{
	memset(pxInterface, '\0', sizeof(*pxInterface));
	pxInterface->pcName = "CHERIoTAdaptor"; /* Just for logging, debugging. */
	pxInterface->pvArgument         = nullptr;
	pxInterface->pfInitialise       = initialise;
	pxInterface->pfOutput           = output_frame;
	pxInterface->pfGetPhyLinkStatus = phy_link_status;
	thisInterface                   = pxInterface;

	FreeRTOS_AddNetworkInterface(pxInterface);
	return pxInterface;
}

void __cheri_compartment("TCPIP") run_driver()
{
	// Sleep until the driver is initialized.
	while (barrier == 0)
	{
		barrier.wait(0);
	}
	auto &interface = lazy_network_interface();

	while (true)
	{
		uint32_t lastInterrupt = interface.receive_interrupt_value();
		int      packets       = 0;
		Debug::log("Receive interrupt value: {}", lastInterrupt);
		// Debug::log("Checking for frames");
		while (auto maybeFrame = interface.receive_frame())
		{
			packets++;
			auto &frame = *maybeFrame;
			// Debug::log("Received frame: ");
			if (eConsiderFrameForProcessing(frame.buffer) != eProcessBuffer)
			{
				Debug::log("Frame not for us");
				continue;
			}
			NetworkBufferDescriptor_t *descriptor =
			  pxGetNetworkBufferWithDescriptor(frame.length, 10);
			if (descriptor == nullptr)
			{
				Debug::log(
				  "Failed to allocate network buffer for {}-byte frame\n",
				  frame.length);
				continue;
			}
			memcpy(descriptor->pucEthernetBuffer, frame.buffer, frame.length);
			descriptor->xDataLength = frame.length;
			descriptor->pxInterface = thisInterface;
			// This is an annoying waste of an allocation, we should be able to
			// drop this but FreeRTOS_MatchingEndpoint requires a different
			// alignment.  This will matter less when we are doing our own
			// filtering.
			descriptor->pxEndPoint = FreeRTOS_MatchingEndpoint(
			  thisInterface, descriptor->pucEthernetBuffer);
			if (descriptor->pxEndPoint == nullptr)
			{
				Debug::log("Failed to find endpoint for frame\n");
				vReleaseNetworkBufferAndDescriptor(descriptor);
				continue;
			}

			Debug::log("Sending frame to IP task");
			Debug::log("Incoming frame: ");
			print_frame(frame.buffer, frame.length);

			IPStackEvent_t event;
			event.eEventType = eNetworkRxEvent;
			event.pvData     = descriptor;
			// Allow a one-tick sleep so that the IP task can wake up if
			// necessary.
			if (xSendEventStructToIPTask(&event, 1) == pdFALSE)
			{
				Debug::log("Failed to send event to IP task\n");
				vReleaseNetworkBufferAndDescriptor(descriptor);
			}
		}
		if (packets > 1)
		{
			ConditionalDebug<true, "Packet filter">::log("Received {} packets",
			                                             packets);
		}
		// Sleep until the next frame arrives
		Timeout t{MS_TO_TICKS(UnlimitedTimeout)};
		interface.receive_interrupt_complete(&t, lastInterrupt);
	}
	Debug::log("Driver thread exiting");
}

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
	                      KunyanEthernet::macAddressDefault().data());
	// Enable DHCP
	endpointIPv4.bits.bWantDHCP = pdTRUE;

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
		                           KunyanEthernet::macAddressDefault().data());
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
		                           KunyanEthernet::macAddressDefault().data());
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

void debug_print_capability(const char *msg, const void *ptr)
{
	ConditionalDebug<true, "FreeRTOS">::log("{}: {}", msg, ptr);
}
