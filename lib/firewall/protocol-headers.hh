// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once

/**
 * EtherType values, for Ethernet headers.  These are defined in network
 * byte order to avoid byte swapping.
 */
enum class EtherType : uint16_t
{
	IPv4 = 0x0008,
#if CHERIOT_RTOS_OPTION_IPv6
	IPv6 = 0xDD86,
#endif
	ARP = 0x0608,
};

const char *ethertype_as_string(EtherType etherType)
{
	switch (etherType)
	{
		case EtherType::IPv4:
			return "IPv4";
#if CHERIOT_RTOS_OPTION_IPv6
		case EtherType::IPv6:
			return "IPv6";
#endif
		case EtherType::ARP:
			return "ARP";
		default:
			return "Unknown";
	}
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

enum IPProtocolNumber : uint8_t
{
	ICMP = 1,
	TCP  = 6,
	UDP  = 17,
};

/**
 * IPv6 address.
 *
 * This should be `std::array<uint8_t, 16>` but our version of `std::array`
 * does not yet have a three-way comparison operator.
 */
struct IPv6Address
{
	/**
	 * The bytes of the address.
	 */
	uint8_t bytes[16];
	/**
	 * Returns a pointer to the bytes of this address.
	 */
	auto data()
	{
		return bytes;
	}
	/**
	 * Returns the size of an address.
	 */
	[[nodiscard]] size_t size() const
	{
		return sizeof(bytes);
	}
	/// Comparison operator.
	// A clang-tidy bug thinks that this should be = nullptr instead of =
	// default.
	auto operator<=>(const IPv6Address &) const = default; // NOLINT
};

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
	uint8_t differentiatedServicesCodePointAndExplicitCongestionNotification;
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

static constexpr const uint16_t DnsServerPort  = 53;
static constexpr const uint16_t DhcpServerPort = 67;
static constexpr const uint16_t DhcpClientPort = 68;

struct TCPUDPCommonPrefix
{
	uint16_t sourcePort;
	uint16_t destinationPort;
} __packed;

struct UDPHeader
{
	/**
	 * Source port.
	 */
	uint16_t sourcePort;
	/**
	 * Destination port.
	 */
	uint16_t destinationPort;
	/**
	 * Message length.
	 */
	uint16_t messageLength;
	/**
	 * Checksum.
	 */
	uint16_t checksum;
} __packed;

struct TCPHeader
{
	/**
	 * Source port.
	 */
	uint16_t sourcePort;
	/**
	 * Destination port.
	 */
	uint16_t destinationPort;
	/**
	 * Sequence number.
	 */
	uint32_t sequenceNumber;
	/**
	 * Acknowledgement number.
	 */
	uint32_t acknowledgementNumber;
	/**
	 * Reserved bits, data offset, and flags.
	 */
	uint16_t bitfield;
	/**
	 * Window size.
	 */
	uint16_t windowSize;
	/**
	 * Checksum.
	 */
	uint16_t checksum;
	/**
	 * Urgent pointer.
	 */
	uint16_t urgentPointer;
} __packed;

/**
 * Masks to extract the value of the SYN and ACK flags in the bitfield
 * of a TCP header (`TCPHeader.bitfield`).
 *
 * Sequence of bits in the bitfield (in network endianness):
 *   dataOffset : 4
 *   reserved   : 4
 *   cwr : 1, ece : 1, urg : 1, ack : 1
 *   psh : 1, rst : 1, syn : 1, fin : 1
 */
static constexpr const uint16_t TCPBitfieldACKMask = 0x0010;
static constexpr const uint16_t TCPBitfieldSYNMask = 0x0002;

struct DHCPHeader
{
	/**
	 * TODO.
	 */
	uint8_t op;
	/**
	 * TODO.
	 */
	uint8_t htype;
	/**
	 * TODO.
	 */
	uint8_t hlen;
	/**
	 * TODO.
	 */
	uint8_t hops;
	/**
	 * TODO.
	 */
	uint32_t xid;
	/**
	 * TODO.
	 */
	uint16_t secs;
	/**
	 * TODO.
	 */
	uint16_t flags;
	/**
	 * TODO.
	 */
	uint32_t ciaddr;
	/**
	 * TODO.
	 */
	uint32_t yiaddr;
	/**
	 * TODO.
	 */
	uint32_t siaddr;
	/**
	 * TODO.
	 */
	uint32_t giaddr;
	/**
	 * TODO.
	 */
	uint8_t chaddr[16];
	/**
	 * TODO.
	 */
	uint8_t sname[64];
	/**
	 * TODO.
	 */
	uint8_t bname[128];
	/**
	 * TODO.
	 */
	uint32_t cookie;
	/**
	 * TODO.
	 */
	uint8_t options;
} __packed;

/**
 * DHCP magic cookie, in network byte order.
 */
static constexpr const uint32_t dhcpMagicCookie = 0x63538263;

/**
 * DHCP subnet mask option. This states the subnet mask.
 */
static constexpr const uint8_t DhcpSubnetMaskOption = 1;
/**
 * DHCP router address option. This states the address of the gateway.
 */
static constexpr const uint8_t DhcpRouterAddressOption = 3;
/**
 * DHCP DNS server address option. This states the address of available DNS
 * servers, in order of preference.
 */
static constexpr const uint8_t DhcpDnsServerAddressOption = 6;
/**
 * DHCP message type option. This states the type of the DHCP message (e.g.,
 * OFFER, ACK).
 */
static constexpr const uint8_t DhcpMessageTypeOption = 53;

/**
 * DHCP OFFER message type. To be compared with the value of option
 * `DhcpMessageTypeOption`.
 */
static constexpr const uint8_t DhcpOfferMessageType = 0x2;
/**
 * DHCP ACK message type. To be compared with the value of option
 * `DhcpMessageTypeOption`.
 */
static constexpr const uint8_t DhcpAckMessageType = 0x5;
