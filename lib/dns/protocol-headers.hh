// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once

#include "../firewall/protocol-headers.hh"

/**
 * ARP header.
 */
struct ARPHeader
{
	/**
	 * Hardware type (network link protocol type). 0x100 (in
	 * network byte order) indicates Ethernet.
	 */
	uint16_t htype;
	/**
	 * Protocol type for which the ARP request is intended.
	 */
	EtherType ptype;
	/**
	 * Length (in octets) of a hardware address.
	 */
	uint8_t hlen;
	/**
	 * Length (in octets) of addresses in the `ptype` protocol.
	 */
	uint8_t plen;
	/**
	 * Operation that the sender is performing. See `ARPRequest`
	 * and `ARPReply` below.
	 */
	uint16_t oper;
	/**
	 * MAC address of the sender.
	 */
	uint8_t sha[6];
	/**
	 * `ptype` address of the sender.
	 */
	uint32_t spa;
	/**
	 * MAC address of the intended receiver (ignored for ARP
	 * requests).
	 */
	uint8_t tha[6];
	/**
	 * `ptype` address of the receiver.
	 */
	uint32_t tpa;
} __packed;

/**
 * Valid values of the ARP header `oper` field, in network byte order.
 */
static constexpr uint16_t ARPRequest = 0x100;
static constexpr uint16_t ARPReply   = 0x200;

/**
 * Compute the IPv4 checksum for passed IPv4 header.
 *
 * Adapted from the reference implementation of RFC 1071.
 */
uint16_t compute_ipv4_checksum(const uint8_t *header, uint16_t length)
{
	uint32_t sum = 0;

	while (length > 1)
	{
		sum += *reinterpret_cast<const uint16_t *>(header);
		header += 2;
		length -= 2;
	}

	// Add left-over byte, if any
	if (length > 0)
	{
		sum += *header;
	}

	// Fold 32-bit sum to 16 bits.
	while (sum >> 16)
	{
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

/**
 * DHCP header.
 */
struct DHCPHeader
{
	/**
	 * Message type (request or reply).
	 */
	uint8_t op;
	/**
	 * Hardware address type.
	 */
	uint8_t htype;
	/**
	 * Hardware address length.
	 */
	uint8_t hlen;
	/**
	 * Hop count.
	 */
	uint8_t hops;
	/**
	 * Transaction ID.
	 */
	uint32_t xid;
	/**
	 * Seconds elapsed since client began address acquisition or renewal
	 * process.
	 */
	uint16_t secs;
	/**
	 * Flags.
	 */
	uint16_t flags;
	/**
	 * Client IP address.
	 */
	uint32_t ciaddr;
	/**
	 * "Your" IP address.
	 */
	uint32_t yiaddr;
	/**
	 * IP address of the server.
	 */
	uint32_t siaddr;
	/**
	 * Relay agent IP address.
	 */
	uint32_t giaddr;
	/**
	 * Client hardware address.
	 */
	uint8_t chaddr[16];
	/**
	 * Optional server host name.
	 */
	uint8_t sname[64];
	/**
	 * Boot file name.
	 */
	uint8_t bname[128];
	/**
	 * DHCP cookie (see `dhcpMagicCookie`).
	 */
	uint32_t cookie;
	/**
	 * Optional parameters field.
	 */
	uint8_t options[];
} __packed;

/**
 * DHCP magic cookie, in network byte order.
 */
static constexpr const uint32_t DhcpMagicCookie = 0x63538263;

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

/**
 * DNS query/response header.
 */
struct DNSHeader
{
	/**
	 * Identifies the query and is echoed in the response so they
	 * can be matched.
	 */
	uint16_t id;
	/**
	 * DNS query/response flags. See documentation for individual
	 * bits below.
	 */
	uint16_t flags;
	/**
	 * Counts the number of question records.
	 */
	uint16_t qdcount;
	/**
	 * Counts the number of answer records.
	 */
	uint16_t ancount;
	/**
	 * Counts the number of authority records.
	 */
	uint16_t nscount;
	/**
	 * Counts the number of additional information records.
	 */
	uint16_t arcount;
	/**
	 * Sections: Answers, questions, authorities, additional information.
	 */
	uint8_t sections[];
} __packed;

/**
 * Masks for the DNS header `flags`. Only specifies the ones we need to
 * set for a standard DNS query and to parse a response.
 */
/**
 * When set, this bit directs the name server to pursue the query
 * recursively.
 */
static constexpr const uint16_t DNSBitfieldRDMask = 0x0001;
/**
 * Four bits containing the type of the response from the DNS server.
 * See values below.
 */
static constexpr const uint16_t DNSBitfieldResponseTypeMask = 0x0f00;

/**
 * Value for `DNSBitfieldResponseTypeMask` indicating success.
 */
static constexpr const uint8_t DNSResponseNoError = 0x0;

/**
 * Values for the TYPE field of DNS questions and answers.
 */
static constexpr const uint16_t DNSRecordTypeA     = 0x0100;
static constexpr const uint16_t DNSRecordTypeAAAA  = 0x1c00;
static constexpr const uint16_t DNSRecordTypeCNAME = 0x0500;

/**
 * Internet CLASS field value for DNS questions and answers.
 */
static constexpr const uint16_t DNSClassIN = 0x0100;

/**
 * Takes a FQDN `hostname` (which may or may not include the final dot)
 * of length `length`, and encode it for sending in a DNS packet.
 * `length` must not include the null terminator.
 *
 * The encoded hostname is written to `encoded`. Encoded must be at
 * least `length + 2` bytes.
 *
 * For example: example.com -> \7example\3com\0
 *
 * Note: This does not check that the hostname is valid. If several
 * dots come in a row, or non-ASCII characters are used, this will
 * simply result in us sending an invalid DNS query and eventually
 * timing out.
 */
void dns_encode_hostname(const char *hostname, size_t length, uint8_t *encoded)
{
	const char *cursor = hostname;
	uint8_t     count  = 0;
	while ((cursor - hostname) < length)
	{
		if (*cursor == '.')
		{
			*encoded++ = count;
			memcpy(encoded, cursor - count, count);
			encoded += count;
			count = 0;
		}
		else
		{
			count++;
		}
		cursor++;
	}
	// We are already done if the hostname finished with a dot.
	if (count)
	{
		*encoded++ = count;
		memcpy(encoded, cursor - count, count);
		encoded += count;
		*encoded = 0;
	}
}

/**
 * Return `true` if passed DNS name label is compressed, `false`
 * otherwise.
 */
bool dns_is_compressed_label(uint8_t label)
{
	// Compressed labels start with 0xc0 (RFC 1035).
	return (label & 0xc0) == 0xc0;
}

/**
 * Return the length in bytes of a DNS hostname `hostname`. `maxLength`
 * holds the length of the `hostname` buffer (which would typically be
 * the rest of a DNS packet).
 *
 * For example, \7example\3com\0 will return 13.  Its compressed form,
 * coming later in the packet, e.g., 0xc010, would return 2.
 *
 * Return -1 if the hostname is truncated or malformed.
 */
ssize_t length_encoded_hostname(const uint8_t *hostname, size_t maxLength)
{
	size_t length = 0;
	while (length < maxLength)
	{
		// Read label by label, until we reach the zero-byte or
		// a compressed label (RFC 1035).
		uint8_t label = *(hostname + length);
		if (label == 0)
		{
			// The zero label concludes the name.
			length += 1;
			break;
		}
		if (dns_is_compressed_label(label))
		{
			// This is a compressed label. Its length is
			// fixed. Since compressed labels always come
			// at the end of a name, we are done.
			if ((length += 2) >= maxLength)
			{
				return -1;
			}
			break;
		}

		// This is an uncompressed label, it has a
		// variable length of `l` bytes. Add 1 to
		// include the label itself.
		if ((length += (label + 1)) >= maxLength)
		{
			return -1;
		}
	}
	// A hostname of length zero is invalid, it must at least
	// contain a dot (zero-label).
	return (length == 0) ? -1 : length;
}
