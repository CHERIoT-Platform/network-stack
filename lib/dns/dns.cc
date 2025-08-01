// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <NetAPI.h>
#include <debug.hh>
#include <endianness.hh>
#include <errno.h>
#include <platform-entropy.hh>
#include <thread.h>
#include <tick_macros.h>
#include <unwind.h>

using Debug = ConditionalDebug<false, "DNS Resolver">;

#include "../firewall/firewall.hh"

#include "dns.hh"
#include "protocol-headers.hh"

/**
 * This is an isolated stub DNS resolver for the CHERIoT network stack.
 *
 * This resolver supports A, AAAA, and CNAME queries on IPv4, for recursive DNS
 * servers. We assume that the recursive resolver recurses into CNAME records.
 *
 * Support for IPv6 is left for future works.
 *
 * Since the resolver plugs directly with the firewall, it needs to know its
 * own IP address, the IP address of the DNS server, its own MAC address, as
 * well as the MAC address of the DNS server (or that of the gateway if the
 * server is outside of the local network). The MAC address of the device is
 * obtained from the firewall. The IP address of the device, of the DNS server,
 * and the MAC address of the server/gateway are obtained from DHCP and ARP,
 * whose corresponding packets are also forwarded to this resolver.
 */

namespace
{
	/**
	 * Full ARP packet, assembled from Ethernet and ARP headers.
	 */
	struct FullARPPacket
	{
		EthernetHeader ethernet;
		ARPHeader      arp;
	} __packed;

	/**
	 * Full DNS packet, assembled from Ethernet, IPv4, UDP, and DNS
	 * headers. Questions and answers are not included here (they have a
	 * variable length) and follow the DNS header.
	 *
	 * Note that this does not work with IEEE 801.1Q VLAN tagging. This is
	 * not a problem for now since neither the FreeRTOS+TCP network stack
	 * nor the firewall support it. When the limitation is addressed for
	 * the firewall, a similar solution can be applied here.
	 */
	struct FullDNSPacket
	{
		EthernetHeader ethernet;
		IPv4Header     ipv4;
		UDPHeader      udp;
		DNSHeader      dns;
	} __packed;

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
	 * updating the `state`.
	 */
	uint16_t       queryID     = {0};
	NetworkAddress queryResult = {0};

	/**
	 * Returns a weak pseudo-random number. Used to generate the query ID.
	 */
	uint64_t rand()
	{
		static EntropySource rng;
		return rng();
	}

	/**
	 * MAC address of the device. We obtain this from the firewall.
	 *
	 * This is reset-critical: if corrupted, this will prevent the
	 * compartment to recover from a crash.
	 *
	 * FIXME: In the future, we should remove this variable by putting the
	 * device MAC into a pre-shared/read-only variable from the firewall.
	 */
	MACAddress deviceMAC = {0};

	/**
	 * MAC address of the DNS server, or of the gateway if the DNS server
	 * is not on the local network. We obtain this from ARP, or from DHCP
	 * server if the IP of the server/gateway matches that of the DHCP
	 * server.
	 *
	 * This is reset-critical: if corrupted, this will prevent the
	 * compartment to recover from a crash.
	 */
	MACAddress dnsServerMAC = {0};

	/**
	 * IP address of the device. We obtain this from the DHCP ACK.
	 *
	 * This is reset-critical: if corrupted, this will prevent the
	 * compartment to recover from a crash.
	 */
	static uint32_t deviceIP = 0;

	/**
	 * IP address of the DNS server. We obtain this from the DHCP OFFER.
	 *
	 * We may want to evolve this to support statically defined DNS servers
	 * instead of the ISP one.
	 *
	 * This is reset-critical: if corrupted, this will prevent the
	 * compartment to recover from a crash.
	 */
	static uint32_t dnsServerIP = 0;

	/**
	 * Set to true if the DNS server is not on the local network.
	 */
	static bool dnsServerIPisLocal = false;

	/**
	 * IP address of the gateway. We obtain this from the DHCP OFFER. This
	 * is necessary to obtain the MAC address of the gateway when we
	 * perform an ARP request. The MAC address of the gateway replaces that
	 * of the DNS server when the DNS server is not on the local network.
	 */
	static uint32_t gatewayIP = 0;

	/**
	 * FIXME: In the future, it would be good to split the DNS resolver
	 * into two more compartments: one that handles ARP and DHCP packets
	 * and provides the location of the DNS server, with all of these
	 * things exposed over a pre-shared object; and one that handles DNS
	 * lookups, has a read-only view of the network state and can happily
	 * crash without taking out any state. This would allow us to get rid
	 * of the "reset-critical" tags above for the DNS resolver.
	 */

	/**
	 * Maximum number of retries for a DNS query. See `perform_dns_lookup`.
	 */
	static constexpr const uint8_t DNSMaxRetries = 10;

	/**
	 * Timeout for one DNS query, in milliseconds. Passed this timeout, we
	 * will try re-sending a query to the server. RFC 1035 recommends a
	 * value of 2-5 seconds, i.e., between 2000 and 5000 milliseconds.
	 */
	static constexpr const int DNSQueryTimeout = 3000;

	/**
	 * Static buffer used for preparing outgoing packets (ARP, DNS).
	 *
	 * 254 is the maximum length of the hostname (RFC 1035) and 6 = 2
	 * (needed for the encoding of the hostname) + 2 (qtype) + 2 (qclass)
	 */
	static uint8_t packetBuffer[sizeof(FullDNSPacket) + 254 + 6];
	static_assert(sizeof(packetBuffer) > sizeof(FullARPPacket));

	/**
	 * Send an ARP request to passed local IP.
	 *
	 * Note: if our own IP address has not yet been determined, this will
	 * send an ARP probe.
	 */
	void send_arp_request(uint32_t ip)
	{
		struct FullARPPacket *arpPacket =
		  reinterpret_cast<struct FullARPPacket *>(packetBuffer);

		memcpy(&arpPacket->ethernet.source, deviceMAC.data(), 6);
		memset(&arpPacket->ethernet.destination, 0xff, 6);

		arpPacket->ethernet.etherType = EtherType::ARP;
		arpPacket->arp.htype          = htons(0x1);
		arpPacket->arp.ptype          = EtherType::IPv4;
		arpPacket->arp.hlen           = 0x6 /* size of a MAC address */;
		arpPacket->arp.plen           = sizeof(uint32_t);
		arpPacket->arp.oper           = ARPRequest;
		memcpy(&arpPacket->arp.sha, deviceMAC.data(), 6);
		// This will be zero if our own IP address has not yet been
		// determined.
		arpPacket->arp.spa = deviceIP;
		arpPacket->arp.tpa = ip;

		ethernet_send_frame(packetBuffer, sizeof(FullARPPacket));
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

		memset(packetBuffer, 0, packetSize);
		FullDNSPacket *header = reinterpret_cast<FullDNSPacket *>(packetBuffer);

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
		header->ipv4.headerChecksum = compute_ipv4_checksum(
		  reinterpret_cast<uint8_t *>(&header->ipv4), sizeof(IPv4Header));

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

		uint8_t *question = packetBuffer + sizeof(FullDNSPacket);

		// Set the question.
		dns_encode_hostname(hostname, length, question);
		if (askIPv6)
		{
			// Request AAAA query type
			*reinterpret_cast<uint16_t *>(question + length + 2) =
			  DNSRecordTypeAAAA;
		}
		else
		{
			// Request A query type
			*reinterpret_cast<uint16_t *>(question + length + 2) =
			  DNSRecordTypeA;
		}
		// Request IN (Internet) class information
		*reinterpret_cast<uint16_t *>(question + length + 4) = DNSClassIN;

		ethernet_send_frame(packetBuffer, packetSize);
	}

	/**
	 * Process incoming ARP packets. If the message tells us the MAC
	 * address of the DNS server, update it.
	 */
	void process_incoming_arp_packet(const uint8_t *arpPacket, size_t length)
	{
		Debug::log("Received an ARP packet.");

		// We must check that the ARP header is complete, as
		// the firewall does not do it.
		if (sizeof(ARPHeader) > length)
		{
			Debug::log("Ignoring truncated ARP packet of length {}", length);
			return;
		}

		auto *arpHeader = reinterpret_cast<const ARPHeader *>(arpPacket);

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
					Debug::log("ARP packet tells us the MAC of the gateway.");
					memcpy(dnsServerMAC.data(), &arpHeader->sha, 6);
					state |= ResolverState::DNSServerMACSet;
				}
				else if (arpHeader->spa == dnsServerIP)
				{
					Debug::log(
					  "ARP packet tells us the MAC of the DNS server.");
					memcpy(dnsServerMAC.data(), &arpHeader->sha, 6);
					state |= ResolverState::DNSServerMACSet;
				}
			}
		}
	}

	/**
	 * Process incoming DHCP packets. Extract the IP address of the device
	 * and the IP address of the DNS server. Send ARP requests if necessary
	 * to get the MAC address of the DNS server.
	 *
	 * This must also be passed a capability to the Ethernet header, as we
	 * may need to access MAC addresses.
	 *
	 * Note: We strictly passively process incoming packets and do not keep
	 * a state machine. This supports DHCP lease renewal. There is one case
	 * where not keeping a state machine may lead us to be non-compliant
	 * with the DHCP standard: if the DHCP server becomes unresponsive and
	 * our lease expires, we are supposed to immediately stop using the IP
	 * and move back to an unconfigured state (RFC 2131). Here, we will
	 * continue using the IP and configuration until a new one is
	 * negotiated with the new DHCP server by the network stack. This is an
	 * edge-case which we should be able to safely ignore for now.
	 */
	void process_incoming_dhcp_packet(const uint8_t  *dhcpPacket,
	                                  size_t          length,
	                                  EthernetHeader *ethernetHeader)
	{
		// DHCP packets may be updating our IP address
		// or the address of the gateway.
		Debug::log("Received a DHCP packet.");

		// We must check that the DHCP header is
		// complete, as the firewall does not do it.
		if (sizeof(DHCPHeader) > length)
		{
			Debug::log("Ignoring truncated DHCP packet");
			return;
		}
		auto  *dhcpHeader    = reinterpret_cast<const DHCPHeader *>(dhcpPacket);
		size_t currentOffset = sizeof(DHCPHeader);

		if (dhcpHeader->cookie != DhcpMagicCookie)
		{
			Debug::log("Ignoring DHCP packet with incorrect magic cookie {}",
			           dhcpHeader->cookie);
			return;
		}

		// Go through the options to get the DHCP
		// message type and the router address
		uint8_t        messageType          = 0;
		uint32_t       extractedGateway     = 0;
		uint32_t       extractedDnsServerIP = 0;
		uint32_t       extractedMask        = 0;
		const uint8_t *option               = dhcpHeader->options;
		while (option < (dhcpPacket + length))
		{
			const uint8_t OptionTag = *option++;

			// RFC 2132: Fixed-length options
			// without data consist of only a tag
			// octet. Only options 0 and 255 are
			// fixed length.
			if (OptionTag == 0xff)
			{
				// This is the end field.
				break;
			}
			if (OptionTag == 0x0)
			{
				// This is a pad field.
				continue;
			}

			// RFC 2132: All other options are
			// variable-length with a length octet
			// following the tag octet.
			if (!(option < (dhcpPacket + length)))
			{
				// Not enough space for the
				// length octet.
				Debug::log("Encountered truncated DHCP packet while "
				           "processing option {}.",
				           static_cast<int>(OptionTag));
				break;
			}
			const uint8_t OptionLength = *option++;
			if (!((option + OptionLength) < (dhcpPacket + length)))
			{
				// Not enough space for the
				// advertised option.
				Debug::log("Encountered truncated DHCP packet while "
				           "processing option {}.",
				           static_cast<int>(OptionTag));
				break;
			}

			if (OptionTag == DhcpMessageTypeOption)
			{
				messageType = *option;
			}
			else if (OptionTag == DhcpSubnetMaskOption)
			{
				if (OptionLength != 4)
				{
					Debug::log("DHCP packet declares invalid length "
					           "for option {} ({}, should be 4).",
					           static_cast<int>(OptionTag),
					           OptionLength);
					break;
				}
				memcpy(&extractedMask, option, sizeof(extractedMask));
			}
			else if (OptionTag == DhcpRouterAddressOption)
			{
				if (OptionLength != 4)
				{
					Debug::log("DHCP packet declares invalid length "
					           "for option {} ({}, should be 4).",
					           static_cast<int>(OptionTag),
					           OptionLength);
					break;
				}
				memcpy(&extractedGateway, option, sizeof(extractedGateway));
			}
			else if (OptionTag == DhcpDnsServerAddressOption)
			{
				// Several DNS servers may be
				// listed. Take the first one.
				if (OptionLength < 4)
				{
					Debug::log("DHCP packet declares invalid length "
					           "for option {} ({}, should be > 4).",
					           static_cast<int>(OptionTag),
					           OptionLength);
					break;
				}
				memcpy(
				  &extractedDnsServerIP, option, sizeof(extractedDnsServerIP));
			}

			option += OptionLength;
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
				Debug::log("The DHCP server is also the DNS server, use "
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
					Debug::log("The DHCP server is also the gateway, use "
					           "their MAC.");
					memcpy(dnsServerMAC.data(), &ethernetHeader->source, 6);
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
			Debug::log("Our IP is {}.{}.{}.{}",
			           static_cast<int>(dhcpHeader->yiaddr) & 0xff,
			           static_cast<int>(dhcpHeader->yiaddr >> 8) & 0xff,
			           static_cast<int>(dhcpHeader->yiaddr >> 16) & 0xff,
			           static_cast<int>(dhcpHeader->yiaddr >> 24) & 0xff);
			deviceIP = dhcpHeader->yiaddr;
			state |= ResolverState::DeviceIPSet;
		}
	}

	/**
	 * Process incoming DNS packets. Provided the packet is an answer to
	 * one of our questions and is safe to parse, extract answers and
	 * notify waiters.
	 */
	void process_incoming_dns_packet(uint8_t *dnsPacket, size_t length)
	{
		// DNS packets may be answering one of our queries.
		Debug::log("Received a DNS packet.");

		// We must check that the DNS header is
		// complete, as the firewall does not do it.
		if (sizeof(DNSHeader) > length)
		{
			Debug::log("Ignoring truncated DNS packet (DNS header).");
			return;
		}
		auto  *dnsHeader     = reinterpret_cast<const DNSHeader *>(dnsPacket);
		size_t currentOffset = sizeof(DNSHeader);

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
		if (dnsHeader->qdcount != ntohs(1) || dnsHeader->ancount == ntohs(0))
		{
			Debug::log("Ignoring DNS answer with incorrect number of records.");
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
			auto nameLength = length_encoded_hostname(dnsPacket + currentOffset,
			                                          length - currentOffset);
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
				auto type =
				  *reinterpret_cast<uint16_t *>(dnsPacket + currentOffset);
				if (type == DNSRecordTypeA)
				{
					valid = true;
					break;
				}
				if (type == DNSRecordTypeAAAA)
				{
					valid  = true;
					isIPv6 = true;
					break;
				}
				if (type != DNSRecordTypeCNAME)
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
				  dnsPacket + currentOffset, length - currentOffset);
				if (nameLength < 0)
				{
					break;
				}
				currentOffset += nameLength;
			}
		}

		if (!valid)
		{
			Debug::log("Ignoring truncated or invalid DNS packet (hostname).");
			return;
		}

		// We have now located the answer to our query
		// in the packet. Check it.

		if ((currentOffset + 10) >= length)
		{
			Debug::log("Ignoring truncated DNS packet (answer length).");
			return;
		}

		currentOffset += 2;
		if (*reinterpret_cast<uint16_t *>(dnsPacket + currentOffset) !=
		    DNSClassIN)
		{
			Debug::log("Ignoring reply which is not for CLASS internet.");
			return;
		}

		// Skip the TTL.
		currentOffset += 6;

		uint16_t ipLength =
		  ntohs(*reinterpret_cast<uint16_t *>(dnsPacket + currentOffset));
		currentOffset += 2;

		if ((currentOffset + ipLength) > length ||
		    (!isIPv6 && (ipLength != 4)) || (isIPv6 && (ipLength != 16)))
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
			uint8_t *ipv6    = queryResult.ipv6;
			// Enforce machine byte order by block of 2 byte.
			for (int i = 0; i < 8; i++)
			{
				*ipv6++ =
				  ntohs(read_unaligned<uint16_t>(dnsPacket + currentOffset));
				currentOffset += 2;
			}
		}
		else
		{
			queryResult.kind = NetworkAddress::AddressKindIPv4;
			queryResult.ipv4 =
			  *reinterpret_cast<uint32_t *>(dnsPacket + currentOffset);
		}

		// Tell caller that the lookup completed.  We
		// need a CAS in case this races with the user
		// thread timing out and setting the state to
		// `LookupTimedOut`. If we loose the CAS, the
		// user thread will simply ignore the result we
		// put in `queryResult` and overwrite it with
		// 0s and an invalid address kind.
		uint32_t expected = ResolverState::WaitingForDNSReply;
		if (state.compare_exchange_strong(expected,
		                                  ResolverState::ProcessingDNSReply))
		{
			state.notify_all();
		}
	}

	/**
	 * Perform a DNS lookup for `hostname` of length `length`. If `askIPv6`
	 * is set to `true`, query for AAAA records, otherwise A. Resolve CNAME
	 * records transparently.
	 */
	void perform_dns_lookup(Timeout    *timeout,
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
		for (uint8_t maxRetries = DNSMaxRetries;
		     (maxRetries > 0) && timeout->may_block();
		     maxRetries--)
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
__cheri_compartment("DNS") void initialize_dns_resolver(uint8_t *macAddress)
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
 * The DNS resolver expects to be passed all ARP, DHCP, and DNS packets.  This
 * does not support IPv6 for now, we should add it at a later point.
 *
 * This does not currently work with DHCP lease renewal if the address of the
 * gateway changes, but neither does the firewall.
 */
void __cheri_compartment("DNS")
  dns_resolver_receive_frame(uint8_t *packet, size_t length)
{
	CHERIOT_DURING
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
			process_incoming_arp_packet(packet + currentOffset,
			                            length - currentOffset);
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
				process_incoming_dhcp_packet(packet + currentOffset,
				                             length - currentOffset,
				                             ethernetHeader);
			}
			else if (tcpudpHeader->sourcePort == htons(DnsServerPort))
			{
				process_incoming_dns_packet(packet + currentOffset,
				                            length - currentOffset);
			}
			break;
		}
		default:
			break;
	}
	CHERIOT_HANDLER
	Debug::log("Handling crash in the DNS resolver firewall thread");
	if ((state & ResolverState::Ready) == ResolverState::Ready)
	{
		// There is nothing to do.

		// If we are in the `WaitingForDNSReply` state, the
		// crash will be just like loosing a UDP packet. The
		// user thread will retransmit and hopefully
		// everything will be OK next time. If not, the user
		// thread will eventually time out.

		// If we are in the `ProcessingDNSReply` state, we
		// already processed the answer.  We probably crashed
		// while processing a packet that we were not
		// expecting anyways.

		// If we are in the `Ready` state, we crashed while
		// processing a packet that we were not expecting
		// anyways.
		return;
	}
	// Otherwise, the crash happened while we were not
	// yet initialized. Recovering from such crashes is
	// left for future works. If we crashed while parsing
	// DHCP, recovery could be implemented by asking the
	// DHCP server to re-send the OFFER or the ACK. If we
	// crashed while parsing ARP, this could be done by
	// making another ARP query for the DNS server.
	Debug::log("Crashed while the DNS resolver was not yet initialized. This "
	           "may result in a non-functional resolver.");
	CHERIOT_END_HANDLER
}

/**
 * Resolve `hostname` to an IPv4 or IPv6 address. See documentation in
 * `dns.hh`.
 */
__cheri_compartment("DNS") int network_host_resolve(Timeout        *timeout,
                                                    const char     *hostname,
                                                    bool            useIPv6,
                                                    NetworkAddress *outAddress)
{
	CHERIOT_DURING
	// Do not check the `hostname` and `outAddress` pointers -
	// this can only be called by the NetAPI, which is trusted.
	// We assume that `hostname` is null-terminated - since this
	// string is derived from the sealed connection capability,
	// we check this through auditing.
	size_t length = strlen(hostname);
	// As per RFC 1035, the limit is 254 characters - 1 for the
	// trailing dot.
	size_t maxLength = 254;
	if (hostname[length - 1] != '.')
	{
		maxLength--;
	}
	if ((length == 0) || (length > maxLength))
	{
		return -EINVAL;
	}

	// Check if the DNS query packet template is fully
	// initialized and not already performing a lookup. If not,
	// we cannot make a DNS query.
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
	queryID = rand();

	// Zero-out in case we fail (DNS resolution is not on the critical path
	// anyways).
	outAddress->kind = NetworkAddress::AddressKindInvalid;
	outAddress->ipv4 = 0;

	perform_dns_lookup(timeout, hostname, length, useIPv6);

	if ((state == ResolverState::LookupFailed) && useIPv6)
	{
		// Try with IPv4 if the lookup failed.
		perform_dns_lookup(timeout, hostname, length, false);
	}

	if (state == ResolverState::LookupFailed)
	{
		Debug::log("DNS request failed.");
		return -EAGAIN;
	}
	if (state == ResolverState::LookupTimedOut)
	{
		Debug::log("DNS request timed out.");
		return -ETIMEDOUT;
	}

	// Copy the result of the lookup into the output
	// buffer.
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
		Debug::log("Resolved {} -> {}:{}:{}:{}:{}:{}:{}:{}",
		           hostname,
		           read_unaligned<uint16_t>(&queryResult.ipv6[0]),
		           read_unaligned<uint16_t>(&queryResult.ipv6[2]),
		           read_unaligned<uint16_t>(&queryResult.ipv6[4]),
		           read_unaligned<uint16_t>(&queryResult.ipv6[6]),
		           read_unaligned<uint16_t>(&queryResult.ipv6[8]),
		           read_unaligned<uint16_t>(&queryResult.ipv6[10]),
		           read_unaligned<uint16_t>(&queryResult.ipv6[12]),
		           read_unaligned<uint16_t>(&queryResult.ipv6[14]),
		           read_unaligned<uint16_t>(&queryResult.ipv6[16]));
	}

	// We are now good to process the next lookup.
	state = ResolverState::Ready;
	CHERIOT_HANDLER
	Debug::log("Handling crash in the DNS resolver user thread");
	state            = ResolverState::Ready;
	outAddress->kind = NetworkAddress::AddressKindInvalid;
	outAddress->ipv4 = 0;
	return -EINVAL;
	CHERIOT_END_HANDLER
	return 0;
}
