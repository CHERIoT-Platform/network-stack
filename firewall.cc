#include "cdefs.h"
#include "driver_compartment.h"
#include <atomic>
#include <compartment-macros.h>
#include <cstdint>
#include <debug.hh>
#include <fail-simulator-on-error.h>
#include <futex.h>
#include <locks.hh>
#include <platform-ethernet.hh>
#include <timeout.h>

namespace
{
	using Debug = ConditionalDebug<true, "Firewall">;

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

	bool packet_filter_egress(const uint8_t *data, size_t length)
	{
		EthernetHeader *ethernetHeader =
		  reinterpret_cast<EthernetHeader *>(const_cast<uint8_t *>(data));
		Debug::log("Sending {} frame",
		           ethertype_as_string(ethernetHeader->etherType));
		if (ethernetHeader->etherType == EtherType::ARP)
		{
			// print_frame(data, length);
		}
		return true;
	}

	bool ipv4_ingress_filter(const uint8_t *data, size_t length)
	{
		if (length < sizeof(IPv4Header))
		{
			Debug::log("Dropping IPv4 packet with length {}", length);
			return false;
		}
		auto *ipv4Header = reinterpret_cast<const IPv4Header *>(data);
		// if (ipv4Header->protocol == IPProtocolNumber::ICMP)
		{
			int32_t sender = ipv4Header->sourceAddress;
			Debug::log("{} from {}.{}.{}.{}",
			           ipv4Header->protocol,
			           sender & 0xff,
			           (sender >> 8) & 0xff,
			           (sender >> 16) & 0xff,
			           (sender >> 24) & 0xff);
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
				// Debug::log("Dropping IPv6 packet");
				return true;
			case EtherType::ARP:
				Debug::log("Saw ARP packet");
				break;
			case EtherType::IPv4:
				return ipv4_ingress_filter(data + sizeof(EthernetHeader),
				                           length - sizeof(EthernetHeader));
			default:
				Debug::log("Dropping frame with unknown EtherType {}",
				           static_cast<uint16_t>(ethernetHeader->etherType));
				return false;
		}

		return true;
	}

	std::atomic<uint32_t> receivedCounter;

} // namespace

bool __cheri_compartment("Ethernet") ethernet_driver_start()
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

bool __cheri_compartment("Ethernet")
  ethernet_send_frame(uint8_t *frame, size_t length)
{
	// TODO: Egress filtering goes here.
	Debug::log("Acquiring send lock");
	LockGuard g{sendLock};
	Debug::log("Sending frame: ");
	auto &ethernet = lazy_network_interface();
	ethernet.dropped_frames_log_all_if_changed();
	ethernet.received_frames_log();
	Debug::log("Received {} frames in software", receivedCounter.load());
	return ethernet.send_frame(frame, length, packet_filter_egress);
}

void __cheri_compartment("Ethernet") ethernet_run_driver()
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
		if (packets > 1)
		{
			ConditionalDebug<true, "Packet filter">::log("Received {} packets",
			                                             packets);
		}
		receivedCounter += packets;
		// Sleep until the next frame arrives
		Timeout t{UnlimitedTimeout};
		// Timeout t{MS_TO_TICKS(1000)}; // For debugging, don't wait forever
		interface.receive_interrupt_complete(&t, lastInterrupt);
	}
	Debug::log("Driver thread exiting");
}

bool __cheri_compartment("Ethernet") ethernet_link_is_up()
{
	auto &ethernet = lazy_network_interface();
	Debug::log("Querying link status ({})", ethernet.phy_link_status());
	return ethernet.phy_link_status();
}
