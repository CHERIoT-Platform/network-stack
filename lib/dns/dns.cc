// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <NetAPI.h>
#include <debug.hh>
#include <endianness.hh>
#include <errno.h>

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
	 * Valid values of `oper`, in network byte order.
	 */
	static constexpr uint16_t ARPRequest = 0x100;
	static constexpr uint16_t ARPReply   = 0x200;

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
	 * set for a standard DNS query.
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

	struct FullDNSPacket
	{
		EthernetHeader ethernet;
		IPv4Header     ipv4;
		UDPHeader      udp;
		DNSHeader      dns;
	} __packed;

	/**
	 * Takes a FQDN (which may or may not include the final dot), and
	 * encode it for sending in the DNS packet.
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
		LookupFailed = (1 << 6) | Ready
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

	void dns_lookup(const char *hostname, size_t length, bool askIPv6)
	{
		// This implementation is UDP-based, so we need to retry regularly.
		// TODO Don't hardcode max retries, use a passed timeout.
		for (uint8_t max_retries = 10; max_retries > 0; max_retries--)
		{
			// It is OK if this races with us receiving an answer for a
			// query that we have already made since IDs are the same.
			send_dns_query(hostname, length, askIPv6);

			// TODO is this timeout the right length? Relate this
			// to RFC 1035 (says 2-5 second wait time minimum)
			Timeout t{1000};
			while ((state == ResolverState::WaitingForDNSReply) &&
			       t.may_block())
			{
				Debug::log("Sleeping until the DNS query answer comes.");
				state.wait(&t, ResolverState::WaitingForDNSReply);
			}

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
		state.compare_exchange_strong(expected, ResolverState::LookupFailed);
	}
} // namespace

/**
 * TODO.
 *
 * This must be called before any other API of the DNS resolver.
 */
void initialize_dns_resolver(uint8_t *macAddress)
{
	Debug::log("Initializing the DNS resolver.");
	memcpy(deviceMAC.data(), macAddress, 6);
	state |= ResolverState::DeviceMACSet;
}

/**
 * TODO.
 *
 * FIXME Do not support IPv6 for now.
 *
 * TODO does this code work with DHCP lease renewal?
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

				if (dnsHeader->id == ntohs(queryID))
				{
					Debug::log("Ignoring DNS answer for the wrong query.");
					return;
				}

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

				// The DNS server will echo the question and append an answer.
				// TODO Starting from here we want to modify to
				// support CNAME. The server will send one
				// answer for CNAME, followed by another for A
				// (the one pointed to by the CNAME).
				if (dnsHeader->qdcount != ntohs(1) ||
				    dnsHeader->ancount != ntohs(1))
				{
					Debug::log(
					  "Ignoring DNS answer with incorrect number of records.");
					return;
				}

				// Parse the packet to check that the result is valid.

				// First, go through the NAME section.
				// TODO Document why this loop, it's non-trivial.
				for (int i = 0; i < 2; i++)
				{
					if ((*(packet + currentOffset) & 0xc0) != 0xc0)
					{
						uint8_t l;
						do
						{
							l = *(packet + currentOffset);
							if ((currentOffset += (l + 1)) >= length)
							{
								Debug::log(
								  "Ignoring truncated DNS packet (hostname).");
								return;
							}
						} while (l != 0);
					}
					else
					{
						currentOffset += 2;
					}
					if (i == 0)
					{
						// Type and class for the question.
						currentOffset += 4;
					}
				}

				if ((currentOffset + 10) >= length)
				{
					Debug::log(
					  "Ignoring truncated DNS packet (answer length).");
					return;
				}

				bool isIPv6 = false;
				if (*(uint16_t *)(packet + currentOffset) == DNSRecordTypeAAAA)
				{
					isIPv6 = true;
				}
				else if (*(uint16_t *)(packet + currentOffset) !=
				         DNSRecordTypeA)
				{
					Debug::log("Ignoring reply which is neither for TYPE A nor "
					           "for AAAA.");
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
				// `LookupFailed`. If we loose the CAS, the
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

// TODO This API should probably take a timeout.
// TODO We need to support CNAME as well.
// TODO Handle crashes in the user thread.
int network_host_resolve(const char     *hostname,
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
	uint32_t expected = ResolverState::Ready;
	if (!state.compare_exchange_strong(expected,
	                                   ResolverState::WaitingForDNSReply))
	{
		Debug::log("DNS resolver is not ready or busy.");
		// Here we may want to wait for the DNS server to initialize or
		// to become available, and return -EAGAIN only if we run out
		// of timeout.
		return -EAGAIN;
	}

	// Prepare the query answer buffer and ID for the new query.
	memset(&queryResult, 0, sizeof(NetworkAddress));
	queryID++;

	dns_lookup(hostname, length, useIPv6);

	if ((state == ResolverState::LookupFailed) && useIPv6)
	{
		// Try with IPv4 if the lookup failed.
		dns_lookup(hostname, length, false);
	}

	if (state == ResolverState::LookupFailed)
	{
		Debug::log("DNS request failed.");

		outAddress->kind = NetworkAddress::AddressKindInvalid;
		outAddress->ipv4 = 0;
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

	// We are now good to process the next lookup.
	state = ResolverState::Ready;

	return 0;
}
