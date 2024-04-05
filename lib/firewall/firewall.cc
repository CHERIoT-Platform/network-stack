// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include "firewall.h"
#include <atomic>
#include <compartment-macros.h>
#include <debug.hh>
#include <fail-simulator-on-error.h>
#include <locks.hh>
#include <platform-ethernet.hh>
#include <timeout.h>
#include <timeout.hh>
#include <vector>

namespace
{
	// TODO These should probably be in their own library.
	uint16_t constexpr ntohs(uint16_t value)
	{
		return
#ifdef __LITTLE_ENDIAN__
		  __builtin_bswap16(value)
#else
		  value
#endif
		    ;
	}
	uint16_t constexpr htons(uint16_t value)
	{
		return
#ifdef __LITTLE_ENDIAN__
		  __builtin_bswap16(value)
#else
		  value
#endif
		    ;
	}
} // namespace

namespace
{
	using Debug = ConditionalDebug<false, "Firewall">;

	/**
	 * EtherType values, for Ethernet headers.  These are defined in network
	 * byte order to avoid byte swapping.
	 */
	enum class EtherType : uint16_t
	{
		IPv4 = 0x0008,
		IPv6 = 0xDD86,
		ARP  = 0x0608,
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

	FlagLockPriorityInherited sendLock;

	/**
	 * Ethernet MAC address.
	 */
	using MACAddress = std::array<uint8_t, 6>;

	/**
	 * Ethernet header.
	 */
	struct EthernetHeader
	{
		/**
		 * Destination MAC address.
		 */
		MACAddress destination;
		/**
		 * Source MAC address.
		 */
		MACAddress source;
		/**
		 * EtherType (the type of this Ethernet frame).
		 */
		EtherType etherType;
	} __packed;

	static_assert(sizeof(EthernetHeader) == 14);

	enum IPProtocolNumber : uint8_t
	{
		ICMP = 1,
		TCP  = 6,
		UDP  = 17,
	};

	static constexpr const uint16_t DhcpServerPort = 67;
	static constexpr const uint16_t DhcpClientPort = 68;

	struct IPv4Header
	{
		/**
		 * Version is in the low 4 bits, header length is in the high 4 bits.
		 */
		uint8_t versionAndHeaderLength;
		/**
		 * Differentiated Services Code Point is in the low six bits, Explicit
		 * Congestion Notification in the next two.
		 */
		uint8_t
		  differentiatedServicesCodePointAndExplicitCongestionNotification;
		/**
		 * Length of this packet.
		 */
		uint16_t packetLength;
		/**
		 * Identification, used when datagrams are fragmented.
		 */
		uint16_t identification;
		/**
		 * Fragment offset.
		 */
		uint16_t fragmentOffset;
		/**
		 * Time to live.
		 */
		uint8_t timeToLive;
		/**
		 * Protocol.
		 */
		IPProtocolNumber protocol;
		/**
		 * Header checksum.
		 */
		uint16_t headerChecksum;
		/**
		 * Source IP address.
		 */
		uint32_t sourceAddress;
		/**
		 * Destination IP address.
		 */
		uint32_t destinationAddress;

		/**
		 * Returns the offset of the start of the body of this packet.
		 */
		[[nodiscard]] size_t body_offset() const
		{
			return (versionAndHeaderLength & 0xf) * 4;
		}
	} __packed;

	struct TCPUDPCommonPrefix
	{
		uint16_t sourcePort;
		uint16_t destinationPort;
	} __packed;

	static_assert(sizeof(IPv4Header) == 20);

	static constexpr const uint8_t Ipv6AddressSize = 16;

	/**
	 * A permitted tuple (source and destination address and port).
	 *
	 * We assume a single local address, so the local address is not stored.
	 */
	struct ConnectionTuple
	{
		// Used to store both IPv4 and IPv6 addresses. IPv4
		// addresses will be padded with zeroes.
		uint8_t  remoteAddress[Ipv6AddressSize];
		uint16_t localPort;
		uint16_t remotePort;
		// A clang-tidy bug thinks that this should be = nullptr instead of
		// = default.
		auto operator<=>(const ConnectionTuple &) const = default; // NOLINT

		/**
		 * Defensively copy IPv6 `address` into `remoteAddress`, return
		 * a negative error code if the address is invalid.
		 */
		int set_ipv6_address(const uint8_t *address)
		{
			if (!blocking_forever<heap_claim_fast>(address, nullptr) ||
			    !CHERI::check_pointer<CHERI::PermissionSet{
			      CHERI::Permission::Load}>(address, Ipv6AddressSize))
			{
				Debug::log("Invalid IPv6 address {}", address);
				return -EINVAL;
			}
			memcpy(remoteAddress, address, Ipv6AddressSize);
			return 0;
		}

		/**
		 * Copy IPv4 address `address` into `remoteAddress`, padding
		 * with zeroes to reach the size of an IPv6 address.
		 */
		void set_ipv4_address(const uint32_t &address)
		{
			memcpy(remoteAddress, &address, sizeof(address));
			// Pad with zeroes
			constexpr const size_t SizePad = Ipv6AddressSize - sizeof(address);
			memset(remoteAddress + sizeof(address), 0, SizePad);
		}
	};

	/**
	 * Simple firewall table for IPv4 and IPv6 endpoints.
	 *
	 * This is intended to be reasonably fast for small numbers of rules and to
	 * have a low memory overhead.  It stores endpoints as a sorted array of
	 * addresses.  This means insertion and deletion is O(n) and lookup is
	 * O(log n).  Each connection typically requires a few KiBs of state, so
	 * we're unlikely to encounter systems where this is a problem in the near
	 * future.
	 */
	class EndpointsTable
	{
		std::vector<ConnectionTuple> permittedTCPEndpoints;
		std::vector<ConnectionTuple> permittedUDPEndpoints;
		FlagLockPriorityInherited    permittedEndpointsLock;
		EndpointsTable()
		{
			permittedTCPEndpoints.reserve(8);
			permittedUDPEndpoints.reserve(8);
		}

		using GuardedTable =
		  std::pair<LockGuard<decltype(permittedEndpointsLock)>,
		            decltype(permittedTCPEndpoints) &>;

		GuardedTable permitted_endpoints(IPProtocolNumber protocol)
		{
			Debug::Assert(protocol == IPProtocolNumber::TCP ||
			                protocol == IPProtocolNumber::UDP,
			              "Invalid protocol for firewall: {}",
			              protocol);
			return GuardedTable{LockGuard{permittedEndpointsLock},
			                    protocol == IPProtocolNumber::TCP
			                      ? permittedTCPEndpoints
			                      : permittedUDPEndpoints};
		}

		/**
		 * Return an iterator to the table entry corresponding to
		 * passed `endpoint`, or `table.end()` if no such entry was
		 * found.
		 */
		auto find_endpoint(decltype(permittedTCPEndpoints) &table,
		                   const ConnectionTuple           &endpoint)
		{
			auto iterator = table.begin();
			auto prev     = iterator;
			while (iterator != table.end())
			{
				if (*iterator == endpoint)
				{
					return prev;
				}
				prev = iterator++;
			}
			return table.end();
		}

		public:
		static EndpointsTable &instance()
		{
			static EndpointsTable table;
			return table;
		}

		void remove_endpoint(IPProtocolNumber       protocol,
		                     const ConnectionTuple &endpoint)
		{
			// Work around a bug in the clang-13 version of the static analyser
			// that does not correctly model the lifetimes of structured
			// bindings.
			// auto [g, table] = permitted_endpoints(protocol);
			auto guardedTable = permitted_endpoints(protocol);
			auto &[g, table]  = guardedTable;

			auto iterator = find_endpoint(table, endpoint);
			if (iterator != table.end() && (*iterator == endpoint))
			{
				table.erase(iterator);
				return;
			}

			Debug::log("Failed to remove endpoint (local: {}; remote: {})",
			           endpoint.localPort,
			           endpoint.remotePort);
		}

		void add_endpoint(IPProtocolNumber       protocol,
		                  const ConnectionTuple &endpoint)
		{
			// Work around a bug in the clang-13 version of the static analyser
			// that does not correctly model the lifetimes of structured
			// bindings.
			// auto [g, table] = permitted_endpoints(protocol);
			auto guardedTable = permitted_endpoints(protocol);
			auto &[g, table]  = guardedTable;

			auto iterator = find_endpoint(table, endpoint);
			if (iterator != table.end() && (*iterator == endpoint))
			{
				Debug::log("Failed to add endpoint: already in the table "
				           "(local: {}; remote: {})",
				           endpoint.localPort,
				           endpoint.remotePort);
				return;
			}
			table.insert(iterator, endpoint);
		}

		void remove_endpoint(IPProtocolNumber protocol, uint16_t localPort)
		{
			// Work around a bug in the clang-13 version of the static analyser
			// that does not correctly model the lifetimes of structured
			// bindings.
			// auto [g, table] = permitted_endpoints(protocol);
			auto guardedTable = permitted_endpoints(protocol);
			auto &[g, table]  = guardedTable;
			// TODO: If we sorted by local port, we could make this O(log(n))
			// If we expect n to be < 8 (currently do) then that's too much
			// work.
			auto iterator = table.begin();
			while (iterator != table.end())
			{
				if (iterator->localPort == localPort)
				{
					table.erase(iterator);
					return;
				}

				iterator++;
			}

			Debug::log("Failed to remove endpoint (local: {})", localPort);
		}

		bool is_endpoint_permitted(IPProtocolNumber       protocol,
		                           const ConnectionTuple &endpoint)
		{
			// Work around a bug in the clang-13 version of the static analyser
			// that does not correctly model the lifetimes of structured
			// bindings.
			// auto [g, table] = permitted_endpoints(protocol);
			auto guardedTable = permitted_endpoints(protocol);
			auto &[g, table]  = guardedTable;

			auto iterator = find_endpoint(table, endpoint);
			return iterator != table.end() && (*iterator == endpoint);
		}
	};

	bool is_dhcp_reply(enum IPProtocolNumber protocol,
	                   bool                  isIngress,
	                   uint16_t              remotePort,
	                   uint16_t              localPort)
	{
		// A DHCP reply is an ingress UDP packet whose remote port
		// matches the DHCP server port, and whose local port matches
		// the DHCP client port.
		if (isIngress && (protocol == IPProtocolNumber::UDP) &&
		    (remotePort == htons(DhcpServerPort)) &&
		    (localPort == htons(DhcpClientPort)))
		{
			return true;
		}
		return false;
	}

	uint32_t          dnsServerAddress;
	_Atomic(uint32_t) dnsIsPermitted;

	bool packet_filter_ipv4(const uint8_t *data,
	                        size_t         length,
	                        uint32_t(IPv4Header::*remoteAddress),
	                        uint16_t(TCPUDPCommonPrefix::*localPort),
	                        uint16_t(TCPUDPCommonPrefix::*remotePort),
	                        bool permitBroadcast)
	{
		if (__predict_false(length < sizeof(IPv4Header)))
		{
			Debug::log("Dropping outbound IPv4 packet with length {}", length);
			return false;
		}
		auto *ipv4Header = reinterpret_cast<const IPv4Header *>(data);
		switch (ipv4Header->protocol)
		{
			// Drop all packets with unknown IP protocol types.
			default:
				Debug::log("Dropping IPv4 packet with unknown protocol {}",
				           ipv4Header->protocol);
				return false;
			case IPProtocolNumber::UDP:

				// Permit DNS requests during a DNS query.
				if (dnsIsPermitted > 0)
				{
					if (ipv4Header->*remoteAddress == dnsServerAddress)
					{
						Debug::log("Permitting DNS request");
						return true;
					}
				}
				if (permitBroadcast)
				{
					if (ipv4Header->*remoteAddress == 0xffffffff)
					{
						Debug::log("Permitting broadcast UDP packet");
						return true;
					}
				}
				[[fallthrough]];
			case IPProtocolNumber::TCP:
			{
				if (ipv4Header->body_offset() < sizeof(ipv4Header))
				{
					Debug::log("Body offset is {} but IPv4 header is {} bytes",
					           ipv4Header->body_offset(),
					           sizeof(ipv4Header));
					return false;
				}
				if (ipv4Header->body_offset() + sizeof(TCPUDPCommonPrefix) >
				    length)
				{
					Debug::log("Dropping IPv4 packet with length {}", length);
					return false;
				}
				auto *tcpudpHeader =
				  reinterpret_cast<const TCPUDPCommonPrefix *>(
				    data + ipv4Header->body_offset());
				uint32_t endpoint         = ipv4Header->*remoteAddress;
				uint16_t localPortNumber  = tcpudpHeader->*localPort;
				uint16_t remotePortNumber = tcpudpHeader->*remotePort;
				bool isIngress = (remoteAddress == &IPv4Header::sourceAddress);

				ConnectionTuple tuple;
				// Do not initialize the address field as it will be fully
				// overwritten.
				tuple.localPort  = localPortNumber;
				tuple.remotePort = remotePortNumber;
				tuple.set_ipv4_address(endpoint);

				if (EndpointsTable::instance().is_endpoint_permitted(
				      ipv4Header->protocol, tuple))
				{
					Debug::log("Permitting {} {} {}.{}.{}.{}",
					           ipv4Header->protocol,
					           isIngress ? "from" : "to",
					           static_cast<int>(endpoint) & 0xff,
					           static_cast<int>(endpoint >> 8) & 0xff,
					           static_cast<int>(endpoint >> 16) & 0xff,
					           static_cast<int>(endpoint >> 24) & 0xff);
					return true;
				}
				// Permit DHCP replies
				if (is_dhcp_reply(ipv4Header->protocol,
				                  isIngress,
				                  remotePortNumber,
				                  localPortNumber))
				{
					return true;
				}
				return false;
			}
			break;
			case IPProtocolNumber::ICMP:
				// FIXME: Allow disabling ICMP.
				return true;
		}
	}

	bool packet_filter_egress(const uint8_t *data, size_t length)
	{
		EthernetHeader *ethernetHeader =
		  reinterpret_cast<EthernetHeader *>(const_cast<uint8_t *>(data));
		switch (ethernetHeader->etherType)
		{
			default:
				Debug::log("Dropping outbound frame with unknown EtherType {}",
				           ethertype_as_string(ethernetHeader->etherType));
				return false;
			// For now, permit all outbound ARP frames.  Eventually we may want
			// to do a bit more sanity checking.
			case EtherType::ARP:
				return true;
			case EtherType::IPv4:
			{
				static_assert(offsetof(TCPUDPCommonPrefix, sourcePort) == 0);
				static_assert(offsetof(TCPUDPCommonPrefix, destinationPort) ==
				              2);
				bool ret =
				  packet_filter_ipv4(data + sizeof(EthernetHeader),
				                     length - sizeof(EthernetHeader),
				                     &IPv4Header::destinationAddress,
				                     &TCPUDPCommonPrefix::sourcePort,
				                     &TCPUDPCommonPrefix::destinationPort,
				                     true);
				if (!ret)
				{
					Debug::log("Dropping outbound IPv4 packet");
				}
				else
				{
					Debug::log("Permitting outbound IPv4 packet");
				}
				return ret;
			}
			// For now, permit all outbound IPv6 packets.
			case EtherType::IPv6:
			{
				Debug::log("Permitting outbound IPv6 packet");
				return true;
				break;
			}
		}
		return true;
	}

	bool packet_filter_ingress(const uint8_t *data, size_t length)
	{
		// Not a valid Ethernet frame (64 bytes including four-byte FCS, which
		// is stripped by this point).
		if (length < 60)
		{
			Debug::log("Dropping frame with length {}", length);
			return false;
		}
		EthernetHeader *ethernetHeader =
		  reinterpret_cast<EthernetHeader *>(const_cast<uint8_t *>(data));
		switch (ethernetHeader->etherType)
		{
			// For now, testing with v6 disabled.
			case EtherType::IPv6:
				return true;
			case EtherType::ARP:
				Debug::log("Saw ARP frame");
				return true;
			case EtherType::IPv4:
				return packet_filter_ipv4(data + sizeof(EthernetHeader),
				                          length - sizeof(EthernetHeader),
				                          &IPv4Header::sourceAddress,
				                          &TCPUDPCommonPrefix::destinationPort,
				                          &TCPUDPCommonPrefix::sourcePort,
				                          false);
			default:
				return false;
		}

		return false;
	}

	std::atomic<uint32_t> receivedCounter;

} // namespace

bool ethernet_driver_start()
{
	// Protect against double entry.  If the barrier state is 0, no
	// initialisation has happened and we should proceed.  If it's 1, we're in
	// the middle of initialisation, if it's 2 then initialisation is done.  In
	// any non-zero case, we should not try to do anything.
	uint32_t expected = 0;
	if (!barrier.compare_exchange_strong(expected, 1))
	{
		return false;
	}
	Debug::log("Initialising network interface");
	auto &ethernet = lazy_network_interface();
	ethernet.mac_address_set();
	// Poke the barrier and make the driver thread start.
	barrier = 2;
	barrier.notify_one();
	return true;
}

bool ethernet_send_frame(uint8_t *frame, size_t length)
{
	// We do not check the frame and length here, because we do not use it
	// in the firewall (we pass it on to untouched to the driver). We
	// consider it the driver's job to check the pointer before using it.
	LockGuard g{sendLock};
	auto     &ethernet = lazy_network_interface();
	return ethernet.send_frame(frame, length, packet_filter_egress);
}

void __cheri_compartment("Firewall") ethernet_run_driver()
{
	// Sleep until the driver is initialized.
	for (int barrierState = barrier; barrier != 2;)
	{
		barrier.wait(barrierState);
	}
	auto &interface = lazy_network_interface();

	while (true)
	{
		uint32_t lastInterrupt = interface.receive_interrupt_value();
		int      packets       = 0;
		// Debug::log("Receive interrupt value: {}", lastInterrupt);
		//  Debug::log("Checking for frames");
		while (auto maybeFrame = interface.receive_frame())
		{
			packets++;
			auto &frame = *maybeFrame;
			if (packet_filter_ingress(frame.buffer, frame.length))
			{
				ethernet_receive_frame(frame.buffer, frame.length);
			}
		}
		receivedCounter += packets;
		// Sleep until the next frame arrives
		Timeout t{UnlimitedTimeout};
		// Timeout t{MS_TO_TICKS(1000)}; // For debugging, don't wait forever
		interface.receive_interrupt_complete(&t, lastInterrupt);
	}
	Debug::log("Driver thread exiting");
}

bool ethernet_link_is_up()
{
	auto &ethernet = lazy_network_interface();
	Debug::log("Querying link status ({})", ethernet.phy_link_status());
	return ethernet.phy_link_status();
}

void firewall_dns_server_ip_set(uint32_t ip)
{
	// This is potentially racy but, since it's called very early in network
	// stack initialisation, it's not worth worrying about an attacker being
	// able to control it.  We should eventually allow changing this as DHCP
	// leases expire.
	if (dnsServerAddress == 0)
	{
		dnsServerAddress = ip;
	}
	Debug::log("DNS server address set to {}", ip);
}

void firewall_permit_dns(bool dnsIsPermitted)
{
	::dnsIsPermitted += dnsIsPermitted ? 1 : -1;
}

void firewall_add_tcpipv4_endpoint(uint32_t remoteAddress,
                                   uint16_t localPort,
                                   uint16_t remotePort)
{
	ConnectionTuple tuple;
	// Do not initialize the address field as it will be fully overwritten
	// by `set_ipv4_address`.
	tuple.localPort  = localPort;
	tuple.remotePort = remotePort;
	tuple.set_ipv4_address(remoteAddress);

	EndpointsTable::instance().add_endpoint(IPProtocolNumber::TCP, tuple);
}

void firewall_add_udpipv4_endpoint(uint32_t remoteAddress,
                                   uint16_t localPort,
                                   uint16_t remotePort)
{
	ConnectionTuple tuple;
	// Do not initialize the address field as it will be fully overwritten
	// by `set_ipv4_address`.
	tuple.localPort  = localPort;
	tuple.remotePort = remotePort;
	tuple.set_ipv4_address(remoteAddress);

	EndpointsTable::instance().add_endpoint(IPProtocolNumber::UDP, tuple);
}

void firewall_remove_tcpipv4_endpoint(uint16_t localPort)
{
	EndpointsTable::instance().remove_endpoint(IPProtocolNumber::TCP,
	                                           localPort);
}

void firewall_remove_udpipv4_local_endpoint(uint16_t localPort)
{
	EndpointsTable::instance().remove_endpoint(IPProtocolNumber::UDP,
	                                           localPort);
}

void firewall_remove_udpipv4_remote_endpoint(uint32_t remoteAddress,
                                             uint16_t localPort,
                                             uint16_t remotePort)
{
	ConnectionTuple tuple;
	// Do not initialize the address field as it will be fully overwritten
	// by `set_ipv4_address`.
	tuple.localPort  = localPort;
	tuple.remotePort = remotePort;
	tuple.set_ipv4_address(remoteAddress);

	EndpointsTable::instance().remove_endpoint(IPProtocolNumber::UDP, tuple);
}

namespace
{
	void firewall_add_ipv6_endpoint_internal(enum IPProtocolNumber protocol,
	                                         uint8_t *remoteAddress,
	                                         uint16_t localPort,
	                                         uint16_t remotePort)
	{
		ConnectionTuple tuple;
		// Do not initialize the address field as it will be fully overwritten
		// by `set_ipv6_address`.
		tuple.localPort  = localPort;
		tuple.remotePort = remotePort;

		if (tuple.set_ipv6_address(remoteAddress) < 0)
		{
			return;
		}
		EndpointsTable::instance().add_endpoint(protocol, tuple);
	}
} // namespace

void firewall_add_tcpipv6_endpoint(uint8_t *remoteAddress,
                                   uint16_t localPort,
                                   uint16_t remotePort)
{
	firewall_add_ipv6_endpoint_internal(
	  IPProtocolNumber::TCP, remoteAddress, localPort, remotePort);
}

void firewall_add_udpipv6_endpoint(uint8_t *remoteAddress,
                                   uint16_t localPort,
                                   uint16_t remotePort)
{
	firewall_add_ipv6_endpoint_internal(
	  IPProtocolNumber::UDP, remoteAddress, localPort, remotePort);
}

void firewall_remove_udpipv6_remote_endpoint(uint8_t *remoteAddress,
                                             uint16_t localPort,
                                             uint16_t remotePort)
{
	ConnectionTuple tuple;
	// Do not initialize the address field as it will be fully overwritten
	// by `set_ipv6_address`.
	tuple.localPort  = localPort;
	tuple.remotePort = remotePort;

	if (tuple.set_ipv6_address(remoteAddress) < 0)
	{
		return;
	}
	EndpointsTable::instance().remove_endpoint(IPProtocolNumber::UDP, tuple);
}

void firewall_remove_tcpipv6_endpoint(uint16_t localPort)
{
	EndpointsTable::instance().remove_endpoint(IPProtocolNumber::TCP,
	                                           localPort);
}

void firewall_remove_udpipv6_local_endpoint(uint16_t localPort)
{
	EndpointsTable::instance().remove_endpoint(IPProtocolNumber::UDP,
	                                           localPort);
}
