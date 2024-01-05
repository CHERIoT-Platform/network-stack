#include "NetAPI.h"
#include "firewall.h"
#include "network-internal.h"

#include <debug.hh>
#include <token.h>
#include <atomic>



namespace
{
	using Debug = ConditionalDebug<true, "Network API">;
	constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

	/**
	 * Returns the sealing key used for a ConnectionCapability.
	 */
	__always_inline SKey host_capability_key()
	{
		return STATIC_SEALING_TYPE(NetworkConnectionKey);
	}
}


SObj network_socket_connect_tcp(Timeout *timeout,
                                SObj     mallocCapability,
                                SObj     hostCapability)
{
	Sealed<ConnectionCapability> sealedHost{hostCapability};
	auto *host = token_unseal(host_capability_key(), sealedHost);
	if (host == nullptr)
	{
		Debug::log("Failed to unseal host capability");
		return nullptr;
	}
	if (host->type != ConnectionTypeTCP)
	{
		Debug::log("Host capability does not authorise a TCP connection");
		return nullptr;
	}
	NetworkAddress address = network_host_resolve(host->hostname, UseIPv6);
	if (address.kind == NetworkAddress::AddressKindInvalid)
	{
		Debug::log("Failed to resolve host");
		return nullptr;
	}
	bool isIPv6 = address.kind == NetworkAddress::AddressKindIPv6;
	// FIXME: IPv6
	if (!isIPv6)
	{
		firewall_add_tcpipv4_endpoint(address.ipv4);
	}
	auto sealedSocket = network_socket_create_and_connect(
	  timeout, mallocCapability, address, ConnectionTypeTCP, host->port);
	return sealedSocket;
}

