#include "NetAPI.h"
#include "firewall.h"
#include "network-internal.h"
#include "timeout.h"

#include <atomic>
#include <debug.hh>
#include <token.h>

namespace
{
	uint16_t ntohs(uint16_t value)
	{
		return __builtin_bswap16(value);
	}
	uint16_t htons(uint16_t value)
	{
		return __builtin_bswap16(value);
	}
} // namespace

namespace
{
	using Debug            = ConditionalDebug<true, "Network API">;
	constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

	/**
	 * Returns the sealing key used for a ConnectionCapability.
	 */
	__always_inline SKey host_capability_key()
	{
		return STATIC_SEALING_TYPE(NetworkConnectionKey);
	}
} // namespace

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
	firewall_permit_dns();
	NetworkAddress address = network_host_resolve(host->hostname, UseIPv6);
	firewall_permit_dns(false);
	if (address.kind == NetworkAddress::AddressKindInvalid)
	{
		Debug::log("Failed to resolve host");
		return nullptr;
	}
	bool isIPv6       = address.kind == NetworkAddress::AddressKindIPv6;
	auto sealedSocket = network_socket_create_and_bind(
	  timeout, mallocCapability, isIPv6, ConnectionTypeTCP);
	auto kind = network_socket_kind(sealedSocket);
	// FIXME: IPv6
	if (!isIPv6)
	{
		firewall_add_tcpipv4_endpoint(
		  address.ipv4, kind.localPort, ntohs(host->port));
	}
	if (network_socket_connect_tcp_internal(
	      timeout, sealedSocket, address, host->port) != 0)
	{
		Timeout t{UnlimitedTimeout};
		network_socket_close(&t, mallocCapability, sealedSocket);
		timeout->elapse(t.elapsed);
		if (isIPv6)
		{
			firewall_remove_tcpipv6_endpoint(ntohs(host->port));
		}
		else
		{
			firewall_remove_tcpipv4_endpoint(ntohs(host->port));
		}
		sealedSocket = nullptr;
	}
	return sealedSocket;
}

NetworkAddress network_socket_udp_authorise_host(Timeout *timeout,
                                                 SObj     socket,
                                                 SObj     hostCapability)
{
	NetworkAddress               address{NetworkAddress::AddressKindInvalid};
	Sealed<ConnectionCapability> sealedHost{hostCapability};
	auto *host = token_unseal(host_capability_key(), sealedHost);
	if (host == nullptr)
	{
		Debug::log("Failed to unseal host capability");
		return address;
	}
	if (host->type != ConnectionTypeUDP)
	{
		Debug::log("Host capability does not authorise a UDP connection");
		return address;
	}
	auto kind   = network_socket_kind(socket);
	bool isIPv6 = false;
	switch (kind.protocol)
	{
		default:
		case SocketKind::Invalid:
		case SocketKind::TCPIPv4:
		case SocketKind::TCPIPv6:
			return address;
		case SocketKind::UDPIPv4:
			break;
		case SocketKind::UDPIPv6:
			isIPv6 = true;
			break;
	}
	firewall_permit_dns();
	address = network_host_resolve(host->hostname, UseIPv6);
	firewall_permit_dns(false);
	if (address.kind == NetworkAddress::AddressKindInvalid)
	{
		Debug::log("Failed to resolve host");
		return address;
	}
	if (isIPv6 != (address.kind == NetworkAddress::AddressKindIPv6))
	{
		Debug::log("Host address does not match socket type");
		return address;
	}
	if (isIPv6)
	{
		firewall_add_udpipv6_endpoint(
		  address.ipv6, kind.localPort, ntohs(host->port));
	}
	else
	{
		Debug::log("Adding address {}.{}.{}.{} to firewall",
		           address.ipv4 & 0xFF,
		           (address.ipv4 >> 8) & 0xFF,
		           (address.ipv4 >> 16) & 0xFF,
		           (address.ipv4 >> 24) & 0xFF);
		firewall_add_udpipv4_endpoint(
		  address.ipv4, kind.localPort, ntohs(host->port));
	}
	return address;
}

const char *network_host_get(SObj hostCapability)
{
	Sealed<ConnectionCapability> sealedHost{hostCapability};
	auto *host = token_unseal(host_capability_key(), sealedHost);
	if (host == nullptr)
	{
		Debug::log("Failed to unseal host capability");
		return nullptr;
	}
	CHERI::Capability hostName = host->hostname;
	hostName.bounds()          = host->nameLength;
	hostName.permissions() &=
	  {CHERI::Permission::Load, CHERI::Permission::Global};
	return hostName;
}
