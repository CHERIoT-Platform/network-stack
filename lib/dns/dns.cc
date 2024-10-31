// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <NetAPI.h>
#include <debug.hh>
#include <endianness.hh>
#include <errno.h>
#include <thread.h>
#include <tick_macros.h>

using Debug = ConditionalDebug<false, "DNS Resolver">;

#include "../dns/dns.hh"
#include "../firewall/firewall.hh"
#include "../firewall/protocol-headers.hh"

/**
 * TODO general documentation on this code.
 *
 * Mention that this is a stub resolver.
 *
 * Supports A, AAAA, and CNAME.
 *
 * We assume that the resolver is recursive and resolves CNAME for us.
 * TODO document this in the commit message as well.
 *
 * Mention that DHCP is required until we make it possible to statically
 * configure the DNS server IP (and other required network information).
 */

namespace
{
	// TODO move some of the generic structs to a separate header.
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
	 * Full ARP packet, assembled from Ethernet and ARP headers.
	 */
	struct FullARPPacket
	{
		EthernetHeader ethernet;
		ARPHeader      arp;
	} __packed;

	/**
	 * Compute the IPv4 checksum for passed IPv4 header.
	 *
	 * Adapted from the reference implementation of RFC 1071.
	 */
	uint16_t compute_ipv4_checksum(uint8_t *header, uint16_t length)
	{
		uint32_t sum = 0;

		while (length > 1)
		{
			sum += *(uint16_t *)header;
			header += 2;
			length -= 2;
		}

		// Add left-over byte, if any
		if (length > 0)
		{
			sum += *(uint8_t *)header;
		}

		// Fold 32-bit sum to 16 bits.
		while (sum >> 16)
		{
			sum = (sum & 0xffff) + (sum >> 16);
		}

		return ~sum;
	}

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
	 * Full DNS packet, assembled from Ethernet, IPv4, UDP, and DNS
	 * headers. Questions and answers, not included here (because of
	 * variable length) follow the DNS header.
	 */
	struct FullDNSPacket
	{
		EthernetHeader ethernet;
		IPv4Header     ipv4;
		UDPHeader      udp;
		DNSHeader      dns;
	} __packed;

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
	void
	dns_encode_hostname(const char *hostname, size_t length, uint8_t *encoded)
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
	bool is_compressed_label(uint8_t label)
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
	ssize_t length_encoded_hostname(uint8_t *hostname, size_t maxLength)
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
			else if (is_compressed_label(label))
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
			else
			{
				// This is an uncompressed label, it has a
				// variable length of `l` bytes. Add 1 to
				// include the label itself.
				if ((length += (label + 1)) >= maxLength)
				{
					return -1;
				}
			}
		}
		// A hostname of length zero is invalid, it must at least
		// contain a dot (zero-label).
		return (length == 0) ? -1 : length;
	}

	/**
	 * Internal state of the DNS resolver.
	 */
	enum ResolverState : uint32_t
	{
		Uninitialized = 0,

		// Initialization intermediate states
		DeviceMACSet    = 1 << 0,
		DNSServerMACSet = 1 << 1,
		DeviceIPSet     = 1 << 2,
		ServerIPSet     = 1 << 3,

		// Ready to process requests
		Ready = DeviceMACSet | DNSServerMACSet | DeviceIPSet | ServerIPSet,

		// Waiting for an answer from the DNS server
		WaitingForDNSReply = (1 << 4) | Ready,

		// We got a successful answer, processing it
		ProcessingDNSReply = (1 << 5) | Ready,

		// The server returned an error, processing it
		LookupFailed   = (1 << 6) | Ready,
		LookupTimedOut = (1 << 7) | Ready
	};
	std::atomic<uint32_t> state = ResolverState::Uninitialized;

	/**
	 * When the resolver is waiting for an answer, the ID of the pending
	 * query is stored in `queryID` by the caller thread. The firewall
	 * thread will compare incoming DNS packets' identifiers with
	 * `queryID`, and store matching answers in `queryResult` before
	 * updating the state.
	 */
	uint16_t       queryID     = {0};
	NetworkAddress queryResult = {0};

	/**
	 * MAC address of the DNS server, or of the gateway if the DNS server
	 * is not on the local network. We obtain this from ARP, or from DHCP
	 * server if the IP of the server/gateway matches that of the DHCP
	 * server.
	 */
	MACAddress dnsServerMAC = {0};

	/**
	 * MAC address of the device. We obtain this from the firewall.
	 */
	MACAddress deviceMAC = {0};

	/**
	 * IP address of the DNS server. We obtain this from the DHCP OFFER. We
	 * may want to evolve this to support statically defined DNS servers.
	 */
	static uint32_t dnsServerIP = 0;

	/**
	 * Set to true if the DNS server is not on the local network.
	 */
	static bool dnsServerIPisLocal = false;

	/**
	 * IP address of the gateway. We obtain this from the DHCP OFFER. This
	 * is necessary to obtain the MAC address of the gateway when we
	 * perform an ARP request.
	 */
	static uint32_t gatewayIP = 0;

	/**
	 * IP address of the device. We obtain this from the DHCP ACK.
	 */
	static uint32_t deviceIP = 0;

	/**
	 * Send an ARP request to passed local IP.
	 *
	 * Note: if our own IP address has not yet been determined, this will
	 * send an ARP probe.
	 */
	void send_arp_request(uint32_t ip)
	{
		struct FullARPPacket arpPacket = {0};

		memcpy(&arpPacket.ethernet.source, deviceMAC.data(), 6);
		memset(&arpPacket.ethernet.destination, 0xff, 6);

		arpPacket.ethernet.etherType = EtherType::ARP;
		arpPacket.arp.htype          = htons(0x1);
		arpPacket.arp.ptype          = EtherType::IPv4;
		arpPacket.arp.hlen           = 0x6 /* size of a MAC address */;
		arpPacket.arp.plen           = sizeof(uint32_t);
		arpPacket.arp.oper           = ARPRequest;
		memcpy(&arpPacket.arp.sha, deviceMAC.data(), 6);
		// This will be zero if our own IP address has not yet been
		// determined.
		arpPacket.arp.spa = deviceIP;
		arpPacket.arp.tpa = ip;

		ethernet_send_frame((uint8_t *)&arpPacket, sizeof(arpPacket));
	}

	/**
	 * Send a DNS query for passed `hostname` of length `length` (not
	 * including the zero terminator).
	 */
	void send_dns_query(const char *hostname, size_t length, bool askIPv6)
	{
		Debug::log("Sending a DNS query for {} (IPv6: {})", hostname, askIPv6);

		// DNS query = length of the hostname + 2 (needed for the
		// encoding of the hostname) + 2 (qtype) + 2 (qclass)
		size_t packetSize = sizeof(FullDNSPacket) + length + 6;

		uint8_t dnsPacket[packetSize];
		memset(dnsPacket, 0, packetSize);
		FullDNSPacket *header = (FullDNSPacket *)dnsPacket;

		// Device (source) MAC.
		memcpy(&header->ethernet.source, deviceMAC.data(), 6);
		memcpy(&header->ethernet.destination, dnsServerMAC.data(), 6);
		// Only support IPv4 for now.
		header->ethernet.etherType = EtherType::IPv4;

		// 5 x 32 bit = 20 bytes (= IPv4 header length).
		header->ipv4.versionAndHeaderLength = (4 << 4) | 5;
		header->ipv4.packetLength = htons(packetSize - sizeof(EthernetHeader));
		// Default TTL as recommended by RFC 1700.
		header->ipv4.timeToLive         = 64;
		header->ipv4.protocol           = IPProtocolNumber::UDP;
		header->ipv4.sourceAddress      = deviceIP;
		header->ipv4.destinationAddress = dnsServerIP;
		// Calculate the checksum last.
		header->ipv4.headerChecksum =
		  compute_ipv4_checksum((uint8_t *)&header->ipv4, sizeof(IPv4Header));

		// Use the DNS server port to originate requests, as we are
		// sure the TCP/IP stack won't use this one.
		header->udp.sourcePort      = htons(DnsServerPort);
		header->udp.destinationPort = htons(DnsServerPort);
		header->udp.messageLength =
		  htons(packetSize - sizeof(EthernetHeader) - sizeof(IPv4Header));
		// The UDP checksum is optional, don't compute it for now. Zero
		// means "not computed".
		header->udp.checksum = 0;

		// Set the current query ID (incremented when receiving an
		// answer).
		header->dns.id = queryID;
		// This is a query (= 0, default value), request recursion.
		header->dns.flags = (DNSBitfieldRDMask);
		// One question, answers, authorities, etc. are all zero.
		header->dns.qdcount = htons(1);

		uint8_t *question = dnsPacket + sizeof(FullDNSPacket);

		// Set the question.
		dns_encode_hostname(hostname, length, question);
		if (askIPv6)
		{
			// Request AAAA query type
			*(uint16_t *)(question + length + 2) = DNSRecordTypeAAAA;
		}
		else
		{
			// Request A query type
			*(uint16_t *)(question + length + 2) = DNSRecordTypeA;
		}
		// Request IN (Internet) class information
		*(uint16_t *)(question + length + 4) = DNSClassIN;

		ethernet_send_frame((uint8_t *)&dnsPacket, sizeof(dnsPacket));
	}

	/**
	 * Maximum number of retries for a DNS query. See `dns_lookup`.
	 */
	static constexpr const uint8_t DNSMaxRetries = 10;

	/**
	 * Timeout for one DNS query, in milliseconds. Passed this timeout, we
	 * will try re-sending a query to the server. RFC 1035 recommends a
	 * value of 2-5 seconds, i.e., 2000 to 5000 milliseconds.
	 */
	static constexpr const int DNSQueryTimeout = 3000;

	/**
	 * Perform a DNS lookup for `hostname` of length `length`. If `askIPv6`
	 * is set to `true`, query for AAAA records, otherwise A. Resolve CNAME
	 * records transparently.
	 */
	void dns_lookup(Timeout    *timeout,
	                const char *hostname,
	                size_t      length,
	                bool        askIPv6)
	{
		// This implementation is UDP-based, so we need to retry
		// regularly. Do so at most `DNSMaxRetries`, or until the
		// timeout is exhausted, whichever comes first. We want to
		// limit the number of tries in case the timeout is very long
		// or infinite - in most cases if the lookup fails after, say,
		// 10 times, it is unlikely that we will get anywhere.
		for (uint8_t max_retries = DNSMaxRetries;
		     (max_retries > 0) && timeout->may_block();
		     max_retries--)
		{
			SystickReturn timestampBefore = thread_systemtick_get();

			// It is OK if this races with us receiving an answer for a
			// query that we have already made since IDs are the same.
			send_dns_query(hostname, length, askIPv6);

			Timeout t{
			  std::min(MS_TO_TICKS(DNSQueryTimeout), timeout->remaining)};
			while ((state == ResolverState::WaitingForDNSReply) &&
			       t.may_block())
			{
				Debug::log("Sleeping until the DNS query answer comes.");
				state.wait(&t, ResolverState::WaitingForDNSReply);
			}

			SystickReturn timestampAfter = thread_systemtick_get();
			// Timeouts should not overflow a 32 bit value
			timeout->elapse(timestampAfter.lo - timestampBefore.lo);

			if (state != ResolverState::WaitingForDNSReply)
			{
				return;
			}
		}

		// At that stage declare the lookup timed out. We need a CAS in
		// case this races with the firewall thread completing the
		// processing of a DNS reply and concurrently updating `state`.
		// If the CAS fails, great! This means that we actually did not
		// time out (just in time). No need to notify anyone, we are on
		// the user thread.
		uint32_t expected = ResolverState::WaitingForDNSReply;
		state.compare_exchange_strong(expected, ResolverState::LookupTimedOut);
	}
} // namespace

/**
 * Initialize the DNS resolver. This must be passed the `macAddress` of the
 * device.
 *
 * This must be called by the firewall exclusively (checked via rego), before
 * any other API of the DNS resolver.
 */
void initialize_dns_resolver(uint8_t *macAddress)
{
	Debug::log("Initializing the DNS resolver.");
	memcpy(deviceMAC.data(), macAddress, 6);
	state |= ResolverState::DeviceMACSet;
}

/**
 * Process an incoming packet relevant to the DNS resolver. This must be passed
 * the `packet` and its total `length` including the Ethernet header.
 *
 * This must be called by the firewall exclusively (checked via rego).
 *
 * The DNS resolver expects to be passed all ARP, DHCP, and DNS packets.
 *
 * This does not support IPv6 for now, we should add it at a later point.
 *
 * This does not currently work with DHCP lease renewal if the address of the
 * gateway changes, but neither does the firewall.
 *
 * TODO handle crashes in the firewall thread.
 */
void __cheri_compartment("DNS")
  dns_resolver_receive_frame(uint8_t *packet, size_t length)
{
	size_t currentOffset = 0;
	// Trust the firewall checked the size of the packet is large enough
	// for an Ethernet header.
	EthernetHeader *ethernetHeader =
	  reinterpret_cast<EthernetHeader *>(const_cast<uint8_t *>(packet));
	currentOffset += sizeof(EthernetHeader);
	switch (ethernetHeader->etherType)
	{
		case EtherType::ARP:
		{
			Debug::log("Received an ARP packet.");

			// We must check that the ARP header is complete, as
			// the firewall does not do it.
			if (sizeof(ARPHeader) > length)
			{
				Debug::log("Ignoring truncated ARP packet of length {}",
				           length);
				return;
			}

			auto *arpHeader =
			  reinterpret_cast<const ARPHeader *>(packet + currentOffset);

			if ((arpHeader->htype == htons(0x1) /* Ethernet*/) &&
			    (arpHeader->ptype == EtherType::IPv4))
			{
				// There are two ways ARP tells us a MAC
				// address. Either through an ARP announcement,
				// or through an ARP reply.
				bool isARPAnnouncement =
				  ((arpHeader->oper == ARPRequest) &&
				   (arpHeader->spa == arpHeader->tpa /* announcement */));

				if (isARPAnnouncement || (arpHeader->oper == ARPReply))
				{
					// Regardless of announcement or reply,
					// the target MAC is stored in the
					// sender hardware address field.
					if ((!dnsServerIPisLocal) && (arpHeader->spa == gatewayIP))
					{
						Debug::log(
						  "ARP packet tells us the MAC of the gateway.");
						// TODO Should we always update, even
						// if we already know the MAC?
						memcpy(dnsServerMAC.data(), &arpHeader->sha, 6);
						state |= ResolverState::DNSServerMACSet;
					}
					else if (arpHeader->spa == dnsServerIP)
					{
						Debug::log(
						  "ARP packet tells us the MAC of the DNS server.");
						// TODO Should we always update, even
						// if we already know the MAC?
						memcpy(dnsServerMAC.data(), &arpHeader->sha, 6);
						state |= ResolverState::DNSServerMACSet;
					}
				}
			}
			break;
		}
		case EtherType::IPv4:
		{
			// Trust the firewall checked the size of the packet is
			// large enough for an IPv4 header.
			auto *ipv4Header =
			  reinterpret_cast<const IPv4Header *>(packet + currentOffset);
			currentOffset += ipv4Header->body_offset();

			// We are only interested in UDP packets.
			if (ipv4Header->protocol != IPProtocolNumber::UDP)
			{
				return;
			}

			// Trust the firewall checked the size of the packet is
			// large enough for a TCP/UDP common header.
			auto *tcpudpHeader = reinterpret_cast<const TCPUDPCommonPrefix *>(
			  packet + currentOffset);
			// Count the offset of a UDP header but don't create an
			// object as we don't need it.
			currentOffset += sizeof(UDPHeader);

			if ((tcpudpHeader->destinationPort == htons(DhcpClientPort)) &&
			    (tcpudpHeader->sourcePort == htons(DhcpServerPort)))
			{
				// DHCP packets may be updating our IP address
				// or the address of the gateway.
				Debug::log("Received a DHCP packet.");

				// We must check that the DHCP header is
				// complete, as the firewall does not do it.
				if (currentOffset + sizeof(DHCPHeader) > length)
				{
					Debug::log("Ignoring truncated DHCP packet of length {}",
					           length);
					return;
				}
				auto *dhcpHeader =
				  reinterpret_cast<const DHCPHeader *>(packet + currentOffset);
				currentOffset += sizeof(DHCPHeader);

				if (dhcpHeader->cookie != dhcpMagicCookie)
				{
					Debug::log(
					  "Ignoring DHCP packet with incorrect magic cookie {}",
					  dhcpHeader->cookie);
					return;
				}

				// Go through the options to get the DHCP
				// message type and the router address
				uint8_t        messageType          = 0;
				uint32_t       extractedGateway     = 0;
				uint32_t       extractedDnsServerIP = 0;
				uint32_t       extractedMask        = 0;
				const uint8_t *option               = &(dhcpHeader->options);
				while (option < (packet + length))
				{
					const uint8_t optionTag = *option++;

					// RFC 2132: Fixed-length options
					// without data consist of only a tag
					// octet. Only options 0 and 255 are
					// fixed length.
					if (optionTag == 0xff)
					{
						// This is the end field.
						break;
					}
					else if (optionTag == 0x0)
					{
						// This is a pad field.
						continue;
					}

					// RFC 2132: All other options are
					// variable-length with a length octet
					// following the tag octet.
					if (!(option < (packet + length)))
					{
						// Not enough space for the
						// length octet.
						Debug::log("Encountered truncated DHCP packet while "
						           "processing option {}.",
						           (int)optionTag);
						break;
					}
					const uint8_t optionLength = *option++;
					if (!((option + optionLength) < (packet + length)))
					{
						// Not enough space for the
						// advertised option.
						Debug::log("Encountered truncated DHCP packet while "
						           "processing option {}.",
						           (int)optionTag);
						break;
					}

					if (optionTag == DhcpMessageTypeOption)
					{
						messageType = *option;
					}
					else if (optionTag == DhcpSubnetMaskOption)
					{
						if (optionLength != 4)
						{
							Debug::log("DHCP packet declares invalid length "
							           "for option {} ({}, should be 4).",
							           (int)optionTag,
							           optionLength);
							break;
						}
						memcpy(&extractedMask, option, sizeof(extractedMask));
					}
					else if (optionTag == DhcpRouterAddressOption)
					{
						if (optionLength != 4)
						{
							Debug::log("DHCP packet declares invalid length "
							           "for option {} ({}, should be 4).",
							           (int)optionTag,
							           optionLength);
							break;
						}
						memcpy(
						  &extractedGateway, option, sizeof(extractedGateway));
					}
					else if (optionTag == DhcpDnsServerAddressOption)
					{
						// Several DNS servers may be
						// listed. Take the first one.
						if (optionLength < 4)
						{
							Debug::log("DHCP packet declares invalid length "
							           "for option {} ({}, should be > 4).",
							           (int)optionTag,
							           optionLength);
							break;
						}
						memcpy(&extractedDnsServerIP,
						       option,
						       sizeof(extractedDnsServerIP));
					}

					option += optionLength;
				}

				if (messageType == DhcpOfferMessageType)
				{
					// This is a DHCP OFFER packet. Extract
					// the IP of the DNS server as well as
					// the IP address of the gateway and
					// subnet mask in case we need it.
					if (extractedDnsServerIP == 0 || extractedGateway == 0 ||
					    extractedMask == 0)
					{
						Debug::log("DHCP OFFER does not provide DNS server IP, "
						           "gateway, or mask.");
						return;
					}

					dnsServerIP = extractedDnsServerIP;
					state |= ResolverState::ServerIPSet;
					Debug::log("The DNS server IP is {}.{}.{}.{}",
					           static_cast<int>(dnsServerIP) & 0xff,
					           static_cast<int>(dnsServerIP >> 8) & 0xff,
					           static_cast<int>(dnsServerIP >> 16) & 0xff,
					           static_cast<int>(dnsServerIP >> 24) & 0xff);
					firewall_dns_server_ip_set(dnsServerIP);

					gatewayIP = extractedGateway;
					Debug::log("The gateway IP is {}.{}.{}.{}",
					           static_cast<int>(gatewayIP) & 0xff,
					           static_cast<int>(gatewayIP >> 8) & 0xff,
					           static_cast<int>(gatewayIP >> 16) & 0xff,
					           static_cast<int>(gatewayIP >> 24) & 0xff);

					// We now need to determine the MAC
					// address of the DNS server.

					if (dhcpHeader->siaddr == dnsServerIP)
					{
						// If the DNS server IP is the
						// same as that of the DHCP
						// server, we already know its
						// MAC address.
						dnsServerIPisLocal = true;
						Debug::log(
						  "The DHCP server is also the DNS server, use "
						  "their MAC.");
						memcpy(dnsServerMAC.data(), &ethernetHeader->source, 6);
						state |= ResolverState::DNSServerMACSet;
					}
					else if ((dnsServerIP & extractedMask) ==
					         (gatewayIP & extractedMask))
					{
						// If the DNS server is on the
						// local network, send an ARP
						// request to know its MAC
						// address.
						dnsServerIPisLocal = true;
						Debug::log("The DHCP server is on the local network, "
						           "query their MAC.");
						send_arp_request(dnsServerIP);
					}
					else
					{
						// If the DNS server is not on
						// the local network, we need
						// to know the MAC address of
						// the gateway.
						dnsServerIPisLocal = false;

						if (dhcpHeader->siaddr == gatewayIP)
						{
							// If the gateway IP is
							// the same as that of
							// the DHCP server, we
							// already know its MAC
							// address.
							Debug::log(
							  "The DHCP server is also the gateway, use "
							  "their MAC.");
							memcpy(
							  dnsServerMAC.data(), &ethernetHeader->source, 6);
							state |= ResolverState::DNSServerMACSet;
						}
						else
						{
							// Otherwise we need to send an
							// ARP request. We cannot count
							// on the TCP/IP stack doing
							// that in case the only
							// non-local communication is
							// for DNS.
							Debug::log("Querying the MAC of the gateway.");
							send_arp_request(gatewayIP);
						}
					}
				}
				else if (messageType == DhcpAckMessageType)
				{
					// This is a DHCP ACK packet. Extract
					// our IP address.
					Debug::log(
					  "Our IP is {}.{}.{}.{}",
					  static_cast<int>(dhcpHeader->yiaddr) & 0xff,
					  static_cast<int>(dhcpHeader->yiaddr >> 8) & 0xff,
					  static_cast<int>(dhcpHeader->yiaddr >> 16) & 0xff,
					  static_cast<int>(dhcpHeader->yiaddr >> 24) & 0xff);
					deviceIP = dhcpHeader->yiaddr;
					state |= ResolverState::DeviceIPSet;
				}
			}
			else if (tcpudpHeader->sourcePort == htons(DnsServerPort))
			{
				// DNS packets may be answering one of our queries.
				Debug::log("Received a DNS packet.");

				// We must check that the DNS header is
				// complete, as the firewall does not do it.
				if (currentOffset + sizeof(DNSHeader) > length)
				{
					Debug::log("Ignoring truncated DNS packet (DNS header).");
					return;
				}
				auto *dnsHeader =
				  reinterpret_cast<const DNSHeader *>(packet + currentOffset);
				currentOffset += sizeof(DNSHeader);

				// Only process DNS messages that correspond to
				// the query we sent.
				if (dnsHeader->id == ntohs(queryID))
				{
					Debug::log("Ignoring DNS answer for the wrong query.");
					return;
				}

				// Only process success responses.
				if ((dnsHeader->flags & DNSBitfieldResponseTypeMask) !=
				    DNSResponseNoError)
				{
					// These are all fatal in our case,
					// best we can do is bail out.
					Debug::log("The DNS query failed.");

					state = ResolverState::LookupFailed;
					state.notify_all();

					return;
				}

				// In the case of a success answer, the DNS
				// server will echo the question and append one
				// or more answers. There may be multiple
				// answers if there are multiple A or AAAA
				// records or if a CNAME was recursively
				// resolved. There should never be more than
				// one question since we only send one.
				if (dnsHeader->qdcount != ntohs(1) ||
				    dnsHeader->ancount == ntohs(0))
				{
					Debug::log(
					  "Ignoring DNS answer with incorrect number of records.");
					return;
				}

				// Parse the packet to check that the result is
				// valid.

				// Next, we find the answer to our question in
				// the DNS payload.
				//
				// This code assumes that:
				// 1. The server only returns answers that match
				//    the hostname we queried or their CNAME
				//    aliases. For example, if we query
				//    example.com, the DNS server only returns
				//    records for example.com or its CNAME
				//    aliases, not google.com;
				// 2. The server only returns answers that match
				//    the record type we asked for. We ask for A
				//    or AAAA, so only return A, AAAA, or CNAME
				//    records;
				// 3. CNAME records are either followed or
				//    preceeded by the A or AAAA record of their
				//    alias target.
				//
				// These assumptions should be valid for any
				// sane recursive DNS server implementation. If
				// the DNS server does not match 1., we may
				// return a wrong IP address to the callee, and
				// if it does not match 2. or 3. we may fail to
				// parse the packet.
				//
				// We proceed as following: skip the question
				// section, then skip CNAME answers until we
				// find an answer of type A or AAAA.
				bool isQuestion = true;
				bool valid      = false;
				bool isIPv6     = false;
				while (true)
				{
					// Parsing a new question or resource record.

					// Skip the NAME.
					auto nameLength = length_encoded_hostname(
					  packet + currentOffset, length - currentOffset);
					if (nameLength < 0)
					{
						break;
					}
					currentOffset += nameLength;

					if (isQuestion)
					{
						// The first entry we process is a question.
						isQuestion = false;

						// Skip TYPE and CLASS: this
						// brings us to the next entry.
						if ((currentOffset += 4) >= length)
						{
							break;
						}
					}
					else
					{
						// We are looking at an answer.
						// The first answer is not
						// necessarily the one we are
						// looking for, as we may have
						// to skip some CNAME records.
						if ((currentOffset + 2) >= length)
						{
							break;
						}
						auto type = *(uint16_t *)(packet + currentOffset);
						if (type == DNSRecordTypeA)
						{
							valid = true;
							break;
						}
						else if (type == DNSRecordTypeAAAA)
						{
							valid  = true;
							isIPv6 = true;
							break;
						}
						else if (type != DNSRecordTypeCNAME)
						{
							break;
						}

						// This is a CNAME record:
						// continue processing to skip
						// it. First skip TYPE, CLASS,
						// TTL, and RDLENGTH.
						if ((currentOffset += 10) >= length)
						{
							break;
						}
						// Then skip RDATA.
						auto nameLength = length_encoded_hostname(
						  packet + currentOffset, length - currentOffset);
						if (nameLength < 0)
						{
							break;
						}
						currentOffset += nameLength;
					}
				}

				if (!valid)
				{
					Debug::log(
					  "Ignoring truncated or invalid DNS packet (hostname).");
					return;
				}

				// We have now located the answer to our query
				// in the packet. Check it.

				if ((currentOffset + 10) >= length)
				{
					Debug::log(
					  "Ignoring truncated DNS packet (answer length).");
					return;
				}

				currentOffset += 2;
				if (*(uint16_t *)(packet + currentOffset) != DNSClassIN)
				{
					Debug::log(
					  "Ignoring reply which is not for CLASS internet.");
					return;
				}

				// Skip the TTL.
				currentOffset += 6;

				uint16_t ipLength =
				  ntohs(*(uint16_t *)(packet + currentOffset));
				currentOffset += 2;

				if ((currentOffset + ipLength) > length ||
				    (!isIPv6 && (ipLength != 4)) ||
				    (isIPv6 && (ipLength != 16)))
				{
					Debug::log("Ignoring truncated DNS packet (IP length).");
					return;
				}

				// We now consider the answer as valid.

				// This protects against situations where we
				// get a DNS packet for the right ID when we
				// are not actually waiting for a packet. We
				// could move this further up.
				if (state != ResolverState::WaitingForDNSReply)
				{
					Debug::log("Ignoring spurious DNS answer.");
					return;
				}

				// Copy the result into the output buffer. Do
				// this *before* updating the state to
				// `ProcessingDNSReply` to avoid a race with
				// the user thread reading it while we write.
				if (isIPv6)
				{
					queryResult.kind = NetworkAddress::AddressKindIPv6;
					uint16_t *ipv6   = (uint16_t *)&queryResult.ipv6[0];
					// Enforce machine byte order by block of 2 byte.
					for (int i = 0; i < 8; i++)
					{
						*ipv6++ = ntohs(*(uint16_t *)(packet + currentOffset));
						currentOffset += 2;
					}
				}
				else
				{
					queryResult.kind = NetworkAddress::AddressKindIPv4;
					queryResult.ipv4 = *(uint32_t *)(packet + currentOffset);
				}

				// Tell caller that the lookup completed.  We
				// need a CAS in case this races with the user
				// thread timing out and setting the state to
				// `LookupTimedOut`. If we loose the CAS, the
				// user thread will simply ignore the result we
				// put in `queryResult` and overwrite it with
				// 0s and an invalid address kind.
				uint32_t expected = ResolverState::WaitingForDNSReply;
				if (state.compare_exchange_strong(
				      expected, ResolverState::ProcessingDNSReply))
				{
					state.notify_all();
				}
			}
			break;
		}
	}
}

// TODO Handle crashes in the user thread.
int network_host_resolve(Timeout        *timeout,
                         const char     *hostname,
                         bool            useIPv6,
                         NetworkAddress *outAddress)
{
	// Do not check the `hostname` and `outAddress` pointers - this can
	// only be called by the NetAPI, which is trusted. We assume that
	// `hostname` is null-terminated - since this string is derived from
	// the sealed connection capability, we check this through auditing.
	//
	// TODO Ensure that we actually check this in the rego.
	// TODO Also document this in the API's documentation.
	int ret = 0;

	size_t length = strlen(hostname);
	// As per RFC 1035, the limit is 254 characters - 1 for the trailing
	// dot.
	size_t maxLength = 254;
	if (hostname[length - 1] != '.')
	{
		maxLength--;
	}
	if ((length == 0) || (length > maxLength))
	{
		return -EINVAL;
	}

	// Check if the DNS query packet template is fully initialized and not
	// already performing a lookup. If not, we cannot make a DNS query.
	while (timeout->may_block())
	{
		uint32_t expected = ResolverState::Ready;
		if (!state.compare_exchange_strong(expected,
		                                   ResolverState::WaitingForDNSReply))
		{
			Debug::log("DNS resolver is not ready or busy, waiting.");
			state.wait(timeout, ResolverState::Ready);
		}
		else
		{
			break;
		}
	}

	if (!timeout->may_block())
	{
		return -ETIMEDOUT;
	}

	// Prepare the query answer buffer and ID for the new query.
	memset(&queryResult, 0, sizeof(NetworkAddress));
	queryID++;

	dns_lookup(timeout, hostname, length, useIPv6);

	if ((state == ResolverState::LookupFailed) && useIPv6)
	{
		// Try with IPv4 if the lookup failed.
		dns_lookup(timeout, hostname, length, false);
	}

	if (state == ResolverState::LookupFailed)
	{
		Debug::log("DNS request failed.");
		ret = -EAGAIN;
	}
	else if (state == ResolverState::LookupTimedOut)
	{
		Debug::log("DNS request timed out.");
		ret = -ETIMEDOUT;
	}
	else
	{
		// Copy the result of the lookup into the output buffer.
		memcpy(outAddress, &queryResult, sizeof(NetworkAddress));

		if (queryResult.kind == NetworkAddress::AddressKindIPv4)
		{
			Debug::log("Resolved {} -> {}.{}.{}.{}",
			           hostname,
			           static_cast<int>(queryResult.ipv4) & 0xff,
			           static_cast<int>(queryResult.ipv4 >> 8) & 0xff,
			           static_cast<int>(queryResult.ipv4 >> 16) & 0xff,
			           static_cast<int>(queryResult.ipv4 >> 24) & 0xff);
		}
		else
		{
			Debug::log(
			  "Resolved {} -> {}:{}:{}:{}:{}:{}:{}:{}",
			  hostname,
			  static_cast<uint16_t>(*(uint16_t *)&queryResult.ipv6[0]),
			  static_cast<uint16_t>(*(uint16_t *)&queryResult.ipv6[2]),
			  static_cast<uint16_t>(*(uint16_t *)&queryResult.ipv6[4]),
			  static_cast<uint16_t>(*(uint16_t *)&queryResult.ipv6[6]),
			  static_cast<uint16_t>(*(uint16_t *)&queryResult.ipv6[8]),
			  static_cast<uint16_t>(*(uint16_t *)&queryResult.ipv6[10]),
			  static_cast<uint16_t>(*(uint16_t *)&queryResult.ipv6[12]),
			  static_cast<uint16_t>(*(uint16_t *)&queryResult.ipv6[14]),
			  static_cast<uint16_t>(*(uint16_t *)&queryResult.ipv6[16]));
		}
	}

	if (ret < 0)
	{
		outAddress->kind = NetworkAddress::AddressKindInvalid;
		outAddress->ipv4 = 0;
	}

	// We are now good to process the next lookup.
	state = ResolverState::Ready;

	return ret;
}
