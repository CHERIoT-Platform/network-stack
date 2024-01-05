#include "firewall.h"
#include "cdefs.h"
#include <atomic>
#include <compartment-macros.h>
#include <cstdint>
#include <debug.hh>
#include <fail-simulator-on-error.h>
#include <locks.hh>
#include <platform-ethernet.hh>
#include <timeout.h>
#include <vector>

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
	 * Helper for use when debugging.  Prints a frame in a format that can be
	 * pasted into wireshark for decoding.
	 */
	[[cheri::interrupt_state(disabled)]] void print_frame(const uint8_t *data,
	                                                      size_t         length)
	{
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

	struct IPv4Header
	{
		/**
		 * Verson is in the low 4 bits, header length is in the high 4 bits.
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
	} __packed;

	static_assert(sizeof(IPv4Header) == 20);

	/**
	 * Simple firewall table for IPv4 endpoints.
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
		/**
		 * A reference-counted IPv4 endpoint.
		 *
		 * This may be extended to include ports at some point.
		 */
		struct IPv4Endpoint
		{
			uint32_t endpoint;
			uint32_t refcount;
		};
		std::vector<IPv4Endpoint> permittedTCPEndpoints;
		std::vector<IPv4Endpoint> permittedUDPEndpoints;
		FlagLockPriorityInherited permittedEndpointsLock;
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
			LockGuard g{permittedEndpointsLock};
			return GuardedTable(std::move(g),
			                    protocol == IPProtocolNumber::TCP
			                      ? permittedTCPEndpoints
			                      : permittedUDPEndpoints);
		}

		auto find_endpoint_ipv4(decltype(permittedTCPEndpoints) &table,
		                        uint32_t                         endpoint)
		{
			return std::lower_bound(
			  table.begin(),
			  table.end(),
			  endpoint,
			  [](const IPv4Endpoint &a, const uint32_t b) {
				  return a.endpoint < b;
			  });
		}

		public:
		static EndpointsTable &instance()
		{
			static EndpointsTable table;
			return table;
		}

		void add_endpoint_ipv4(IPProtocolNumber protocol, uint32_t endpoint)
		{
			Debug::log(
			  "Adding endpoint {} for protocol {}", endpoint, protocol);
			auto [g, table] = permitted_endpoints(protocol);
			auto iterator   = find_endpoint_ipv4(table, endpoint);
			if (iterator != table.end() && iterator->endpoint == endpoint)
			{
				iterator->refcount++;
				Debug::log("Endpoint {} already in table", endpoint);
				return;
			}
			table.push_back({endpoint, 1});
			std::sort(table.begin(),
			          table.end(),
			          [](const IPv4Endpoint &a, const IPv4Endpoint &b) {
				          return a.endpoint < b.endpoint;
			          });
		}

		void remove_endpoint_ipv4(IPProtocolNumber protocol, uint32_t endpoint)
		{
			Debug::log(
			  "Removing endpoint {} for protocol {}", endpoint, protocol);
			auto [g, table] = permitted_endpoints(protocol);
			auto iterator   = find_endpoint_ipv4(table, endpoint);
			if (iterator == table.end() || iterator->endpoint != endpoint)
			{
				Debug::log("Endpoint {} not in table", endpoint);
				return;
			}
			if (iterator->refcount > 1)
			{
				iterator->refcount--;
				Debug::log("Endpoint {} still in table", endpoint);
			}
			else
			{
				table.erase(iterator);
			}
		}

		bool is_endpoint_permitted(IPProtocolNumber protocol, uint32_t endpoint)
		{
			auto [g, table] = permitted_endpoints(protocol);
			auto iterator   = find_endpoint_ipv4(table, endpoint);
			return iterator != table.end() && iterator->endpoint == endpoint;
		}
	};

	uint32_t dnsServerAddress;
	bool     dnsIsPermitted = false;

	bool packet_filter_ipv4(const uint8_t *data,
	                        size_t         length,
	                        uint32_t(IPv4Header::*field),
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
			// Drop all packets with unknown protocol types.
			default:
				Debug::log("Dropping IPv4 packet with unknown protocol {}",
				           ipv4Header->protocol);
				return false;
			case IPProtocolNumber::UDP:
				// If we haven't finished doing DHCP, permit all UDP packets
				// (we don't know the address of the DHCP server yet, so
				// IP-based filtering is not going to be reliable).
				if (__predict_false(dnsServerAddress == 0))
				{
					return true;
				}
				// Permit DNS requests during a DNS query.
				if (dnsIsPermitted)
				{
					if (ipv4Header->*field == dnsServerAddress)
					{
						Debug::log("Permitting DNS request");
						return true;
					}
				}
				if (permitBroadcast)
				{
					if (ipv4Header->*field == 0xffffffff)
					{
						Debug::log("Permitting broadcast UDP packet");
						return true;
					}
				}
				[[fallthrough]];
			case IPProtocolNumber::TCP:
			{
				uint32_t endpoint = ipv4Header->*field;
				if (EndpointsTable::instance().is_endpoint_permitted(
				      ipv4Header->protocol, endpoint))
				{
					Debug::log(
					  "Permitting {} {} {}.{}.{}.{}",
					  ipv4Header->protocol,
					  field == &IPv4Header::destinationAddress ? "to" : "from",
					  (int)endpoint & 0xff,
					  (int)(endpoint >> 8) & 0xff,
					  (int)(endpoint >> 16) & 0xff,
					  (int)(endpoint >> 24) & 0xff);
					return true;
				}
				if (0)
					Debug::log(
					  "Dropping {} {} {}.{}.{}.{}",
					  ipv4Header->protocol,
					  field == &IPv4Header::destinationAddress ? "to" : "from",
					  (int)endpoint & 0xff,
					  (int)(endpoint >> 8) & 0xff,
					  (int)(endpoint >> 16) & 0xff,
					  (int)(endpoint >> 24) & 0xff);
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
				bool ret = packet_filter_ipv4(data + sizeof(EthernetHeader),
				                              length - sizeof(EthernetHeader),
				                              &IPv4Header::destinationAddress,
				                              true);
				return ret;
			}
			// For now, permit all outbound IPv6 packets.
			case EtherType::IPv6:
			{
				Debug::log("Permitting outbound IPv6 frame");
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
	::dnsIsPermitted = dnsIsPermitted;
}

void firewall_add_tcpipv4_endpoint(uint32_t endpoint)
{
	EndpointsTable::instance().add_endpoint_ipv4(IPProtocolNumber::TCP,
	                                             endpoint);
}

void firewall_add_udpipv4_endpoint(uint32_t endpoint)
{
	EndpointsTable::instance().add_endpoint_ipv4(IPProtocolNumber::UDP,
	                                             endpoint);
}

void firewall_remove_tcpipv4_endpoint(uint32_t endpoint)
{
	EndpointsTable::instance().remove_endpoint_ipv4(IPProtocolNumber::TCP,
	                                                endpoint);
}

void firewall_remove_udpipv4_endpoint(uint32_t endpoint)
{
	EndpointsTable::instance().remove_endpoint_ipv4(IPProtocolNumber::UDP,
	                                                endpoint);
}
