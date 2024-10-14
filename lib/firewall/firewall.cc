// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <atomic>
#include <compartment-macros.h>
#include <debug.hh>
//#include <fail-simulator-on-error.h>
#include <locks.hh>
#include <platform-entropy.hh>
#include <platform-ethernet.hh>
#include <timeout.h>
#include <timeout.hh>
#include <vector>

using Debug = ConditionalDebug<false, "Firewall">;

#include "firewall.hh"

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

	std::atomic<uint32_t> barrier;

	/**
	 * Base class for small table.  Factors out the common code that is generic
	 * to all small tables in no-inline methods so that the type-safe wrapper
	 * adds a very small amount of code.
	 */
	struct SmallTableBase
	{
		protected:
		/**
		 * Insert an element into a sorted buffer.
		 */
		__noinline void insert(void       *buffer,
		                       size_t      bufferSize,
		                       const void *element,
		                       size_t      elementSize)
		{
			// This currently does a linear search.  This is less code than a
			// binary search and we don't insert on a hot path, so this should
			// be fine.
			for (size_t i = 0; i < bufferSize; i += elementSize)
			{
				void *current = reinterpret_cast<uint8_t *>(buffer) + i;
				if (memcmp(current, element, elementSize) > 0)
				{
					memmove(reinterpret_cast<uint8_t *>(current) + elementSize,
					        current,
					        bufferSize - i);
					memcpy(current, element, elementSize);
					return;
				}
			}
			memcpy(reinterpret_cast<uint8_t *>(buffer) + bufferSize,
			       element,
			       elementSize);
		}

		/**
		 * Find an element in the sorted buffer.  This returns a pointer to the
		 * element if it's found or nullptr if it's not.
		 */
		__noinline void *binary_search(void       *buffer,
		                               size_t      bufferSize,
		                               const void *element,
		                               size_t      elementSize)
		{
			if (bufferSize > 0)
			{
				size_t low  = 0;
				size_t high = bufferSize / elementSize;
				while (low <= high)
				{
					size_t mid = low + (high - low) / 2;
					void  *current =
					  reinterpret_cast<uint8_t *>(buffer) + (mid * elementSize);
					int comparison = memcmp(current, element, elementSize);
					if (comparison == 0)
					{
						return current;
					}
					if (comparison < 0)
					{
						low = mid + 1;
					}
					else
					{
						// If we're already at the first element, going further
						// down will underflow the offset.
						if (mid == 0)
						{
							return nullptr;
						}
						high = mid - 1;
					}
				}
			}
			return nullptr;
		}

		/**
		 * Remove an element from the sorted buffer.
		 */
		__noinline bool remove(void       *buffer,
		                       size_t      bufferSize,
		                       const void *element,
		                       size_t      elementSize)
		{
			void *found =
			  binary_search(buffer, bufferSize, element, elementSize);
			if (found == nullptr)
			{
				return false;
			}
			void *next = reinterpret_cast<uint8_t *>(found) + elementSize;
			memmove(found,
			        next,
			        bufferSize - (reinterpret_cast<uint8_t *>(next) -
			                      reinterpret_cast<uint8_t *>(buffer)));
			return true;
		}

		/**
		 * Resizes the buffer if the capacity equals the size.
		 *
		 * Note: Unlike the other APIs, size and capacity here are measured in
		 * elements, not bytes.  This is inconsistent and would be terrible in
		 * a public API, but it's called in one place so the code-size
		 * reduction is worth the inconsistency.
		 */
		void *resize_if_needed(void  *buffer,
		                       size_t size,
		                       size_t capacity,
		                       size_t elementSize)
		{
			void *newBuffer = buffer;
			if (size == capacity)
			{
				Timeout t{UnlimitedTimeout};
				newBuffer = heap_allocate_array(
				  &t, MALLOC_CAPABILITY, capacity * 2, elementSize);
				memcpy(newBuffer, buffer, size * elementSize);
				free(buffer);
				buffer = newBuffer;
			}
			return buffer;
		}
	};

	/**
	 * A simple table of `T`s, stored as a sorted array.  This uses `memcmp` and
	 * `memcpy` to compare and copy elements and so requires that `T` is a
	 * trivial type.
	 *
	 * This never shrinks and does a full copy if it needs to grow.
	 */
	template<typename T>
	class SmallTable : public SmallTableBase
	{
		static_assert(std::is_trivial_v<T>, "T must be a trivial type");
		/**
		 * The buffer for the table.  We store all of the metadata in a single
		 * capability:
		 *
		 * The base address is the start of the buffer.
		 * The length defines the size of the buffer (the capacity).
		 * The address points to the end of the used portion of the buffer.
		 *
		 * This lets us store all three words of state of a `std::vector` in a
		 * single capability.  This works because the buffer is guaranteed to
		 * be representable.  Note that capacity may be rounded up, but integer
		 * division truncates towards zero and so the result remains correct.
		 */
		CHERI::Capability<T> buffer;
		__always_inline T   *base()
		{
			CHERI::Capability base{buffer};
			base.address() = buffer.base();
			return base;
		}

		/**
		 * Update the size by setting the address in the capability.
		 */
		void set_size(size_t size)
		{
			buffer.address() = buffer.base() + (size * sizeof(T));
		}

		public:
		/**
		 * Create a new small table with the given capacity.
		 */
		SmallTable(size_t size = 8)
		{
			buffer = static_cast<T *>(calloc(size, sizeof(T)));
		}

		/**
		 * Destroy the small table, freeing the buffer.
		 */
		~SmallTable()
		{
			free(buffer);
		}

		/**
		 * Returns the size of the table, computed from the address (end of the
		 * used buffer) and base.
		 */
		size_t size()
		{
			return (buffer.address() - buffer.base()) / sizeof(T);
		}

		/**
		 * Returns the capacity of the buffer (the length of the capability, as
		 * units of size T).
		 */
		size_t capacity()
		{
			return buffer.length() / sizeof(T);
		}

		/**
		 * Remove all elements from the table.
		 *
		 * Note: This does *not* free memory.
		 */
		void clear()
		{
			set_size(0);
		}

		/**
		 * Inserts a new element into the table.  Does nothing if the element is
		 * already present.
		 */
		void insert(const T &element)
		{
			// if (contains(element))
			{
				// return;
			}
			// If the capacity isn't large enough for the new element, resize.
			size_t currentSize = size();
			void  *currentBase =
			  resize_if_needed(base(), currentSize, capacity(), sizeof(T));
			SmallTableBase::insert(
			  currentBase, currentSize * sizeof(T), &element, sizeof(T));
			set_size(currentSize + 1);
		}

		/**
		 * Removes an element from the table.  Does nothing if the element is
		 * not present.
		 */
		void remove(const T &element)
		{
			if (SmallTableBase::remove(
			      base(), size() * sizeof(T), &element, sizeof(T)))
			{
				set_size(size() - 1);
			}
		}

		/**
		 * Removes an element from the table, identified by a pointer to the
		 * element.
		 */
		void remove(T *element)
		{
			memmove(element,
			        element + 1,
			        size() - ((reinterpret_cast<uint8_t *>(element + 1) -
			                   reinterpret_cast<uint8_t *>(base())) /
			                  sizeof(T)));
			set_size(size() - 1);
		}

		/**
		 * Returns true if the table contains the given element.
		 */
		bool contains(const T &element)
		{
			return binary_search(
			         base(), size() * sizeof(T), &element, sizeof(T)) !=
			       nullptr;
		}

		/**
		 * Returns a pointer (which can be used as a begin iterator) to the
		 * start of the table.
		 */
		T *begin()
		{
			return base();
		}

		/**
		 * Returns a pointer (which can be used as an end iterator) to the end
		 * of the table.
		 */
		T *end()
		{
			return buffer;
		}
	};

	/**
	 * Test the small table implementation (disabled unless we're debugging
	 * the small table explicitly).  If you enable this, make sure that you
	 * also enable Debug, or these tests won't actually do anything.
	 */
	void test_small_table()
	{
		if constexpr (false)
		{
			Debug::log("Testing small table");
			SmallTable<int> testSmallTable;
			Debug::log("Testing small table insert");
			testSmallTable.insert(1);
			testSmallTable.insert(2);
			testSmallTable.insert(5);
			testSmallTable.insert(3);
			testSmallTable.insert(4);
			testSmallTable.insert(7);
			testSmallTable.contains(0);
			auto printSmallTable = [&]() {
				int i = 0;
				for (auto v : testSmallTable)
				{
					Debug::log("Small table[{}] {}", i++, v);
				}
			};
			auto testSmallTableContains =
			  [&](std::initializer_list<int> array) {
				  for (int i : array)
				  {
					  Debug::Assert(testSmallTable.contains(i),
					                "Small table does not contain {}",
					                i);
				  }
			  };
			printSmallTable();
			Debug::Assert(testSmallTable.size() == 6,
			              "Small table size is wrong");
			Debug::Assert(testSmallTable.capacity() == 8,
			              "Small table capacity is wrong");
			Debug::log("Testing small table contains");
			testSmallTableContains({1, 2, 3, 4, 5, 7});
			Debug::log("Testing small table remove");
			testSmallTable.remove(5);
			printSmallTable();
			testSmallTableContains({1, 2, 3, 4, 7});
			testSmallTable.remove(1);
			testSmallTableContains({2, 3, 4, 7});
			testSmallTable.remove(2);
			testSmallTableContains({3, 4, 7});
			testSmallTable.remove(4);
			testSmallTableContains({3, 7});
			testSmallTable.remove(7);
			testSmallTableContains({3});
			testSmallTable.remove(3);
			printSmallTable();
			Debug::Assert(
			  testSmallTable.size() == 0,
			  "Small table size is wrong after removal ({}, expected 0}",
			  testSmallTable.size());
			Debug::log("Testing small table contains on a length 0 table");
			SmallTable<int> testSmallTableZeroLength(0);
			testSmallTableZeroLength.contains(1);

			Debug::log("Testing small table pointer-based remove");
			testSmallTable.insert(1);
			testSmallTable.remove(testSmallTable.begin());
			Debug::Assert(
			  testSmallTable.size() == 0,
			  "Small table size is wrong after removal ({}, expected 0}",
			  testSmallTable.size());

			Debug::log("Finished small table tests");
		}
	}

	/**
	 * This is used to synchronize with the TCP/IP stack during resets.
	 */
	std::atomic<uint8_t> *tcpipRestartState = nullptr;

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
	 * Returns the MAC address for the network interface.
	 */
	MACAddress &mac_address()
	{
		static MACAddress macAddress = []() {
			auto &ethernet = lazy_network_interface();
			if constexpr (EthernetDevice::has_unique_mac_address() ||
			              CHERIOT_RTOS_OPTION_FORCE_NON_UNIQUE_MAC)
			{
				return ethernet.mac_address_default();
			}
			else
			{
				std::array<uint8_t, 6> macAddress;
				EntropySource          entropy;
				for (auto &byte : macAddress)
				{
					byte = entropy();
				}
				// Set the local bit (second bit transmitted from first byte) to
				// 1 to indicate a locally administered MAC
				macAddress[0] |= 0b10;
				// Make sure that the broadcast bit is 0
				macAddress[0] &= ~0b1;
				Debug::log("MAC address: {}:{}:{}:{}:{}:{}",
				           macAddress[0],
				           macAddress[1],
				           macAddress[2],
				           macAddress[3],
				           macAddress[4],
				           macAddress[5]);
				return macAddress;
			}
		}();
		return macAddress;
	}

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
	template<typename Address>
	class EndpointsTable
	{
		/**
		 * A permitted tuple (source and destination address and port).
		 *
		 * We assume a single local address, so the local address is not stored.
		 */
		struct ConnectionTuple
		{
			Address  remoteAddress;
			uint16_t localPort;
			uint16_t remotePort;
			// A clang-tidy bug thinks that this should be = nullptr instead of
			// = default.
			auto operator<=>(const ConnectionTuple &) const = default; // NOLINT
		};
		SmallTable<uint16_t>        tcpServerPorts;
		SmallTable<ConnectionTuple> permittedTCPEndpoints;
		SmallTable<ConnectionTuple> permittedUDPEndpoints;
		FlagLockPriorityInherited   permittedEndpointsLock;

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

		public:
		static EndpointsTable &instance()
		{
			static EndpointsTable table;
			return table;
		}

		void clear(IPProtocolNumber protocol)
		{
			auto guardedTable = permitted_endpoints(protocol);
			auto &[g, table]  = guardedTable;
			table.clear();
			tcpServerPorts.clear();
		}

		void remove_endpoint(IPProtocolNumber protocol,
		                     Address          endpoint,
		                     uint16_t         localPort,
		                     uint16_t         remotePort)
		{
			// Work around a bug in the clang-13 version of the static analyser
			// that does not correctly model the lifetimes of structured
			// bindings.
			// auto [g, table] = permitted_endpoints(protocol);
			auto guardedTable = permitted_endpoints(protocol);
			auto &[g, table]  = guardedTable;
			ConnectionTuple tuple{endpoint, localPort, remotePort};
			table.remove(tuple);
		}

		void add_server_port(uint16_t localPort)
		{
			LockGuard g{permittedEndpointsLock};
			tcpServerPorts.insert(localPort);
		}

		void remove_server_port(uint16_t localPort)
		{
			LockGuard g{permittedEndpointsLock};
			tcpServerPorts.remove(localPort);
		}

		bool is_server_port(uint16_t localPort)
		{
			LockGuard g{permittedEndpointsLock};
			return tcpServerPorts.contains(localPort);
		}

		void add_endpoint(IPProtocolNumber protocol,
		                  Address          remoteAddress,
		                  uint16_t         localPort,
		                  uint16_t         remotePort)
		{
			// Work around a bug in the clang-13 version of the static analyser
			// that does not correctly model the lifetimes of structured
			// bindings.
			// auto [g, table] = permitted_endpoints(protocol);
			auto guardedTable = permitted_endpoints(protocol);
			auto &[g, table]  = guardedTable;
			ConnectionTuple tuple{remoteAddress, localPort, remotePort};
			table.insert(tuple);
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
			for (auto &tuple : table)
			{
				if (tuple.localPort == localPort)
				{
					table.remove(&tuple);
					break;
				}
			}
		}

		bool is_endpoint_permitted(IPProtocolNumber protocol,
		                           Address          endpoint,
		                           uint16_t         localPort,
		                           uint16_t         remotePort)
		{
			// Work around a bug in the clang-13 version of the static analyser
			// that does not correctly model the lifetimes of structured
			// bindings.
			// auto [g, table] = permitted_endpoints(protocol);
			auto guardedTable = permitted_endpoints(protocol);
			auto &[g, table]  = guardedTable;
			ConnectionTuple tuple{endpoint, localPort, remotePort};
			return table.contains(tuple);
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

	/**
	 * `currentClientCount` keeps track of the current number of open
	 * client connections. When `currentClientCount` reaches
	 * `FirewallMaximumNumberOfClients`, new incoming TCP connections are
	 * dropped. See `FirewallMaximumNumberOfClients`.
	 */
	_Atomic(uint8_t) currentClientCount = 0;

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
				if (EndpointsTable<uint32_t>::instance().is_endpoint_permitted(
				      ipv4Header->protocol,
				      endpoint,
				      localPortNumber,
				      remotePortNumber))
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
				// First SYN to a local server port should
				// trigger creation of a firewall entry. We
				// must do this after checking the table to
				// avoid creating an entry multiple times if we
				// get multiple SYNs from the same client
				// (e.g., retransmissions).
				if ((isIngress) &&
				    (ipv4Header->protocol == IPProtocolNumber::TCP) &&
				    (EndpointsTable<uint32_t>::instance().is_server_port(
				      localPortNumber)))
				{
					if (ipv4Header->body_offset() + sizeof(TCPHeader) > length)
					{
						Debug::log("Dropping truncated TCP packet of length {}",
						           length);
						return false;
					}
					auto *tcpHeader =
					  reinterpret_cast<const TCPHeader *>(tcpudpHeader);
					if (((ntohs(tcpHeader->bitfield) & TCPBitfieldSYNMask) !=
					     0) &&
					    ((ntohs(tcpHeader->bitfield) & TCPBitfieldACKMask) ==
					     0))
					{
						if (currentClientCount + 1 >=
						    FirewallMaximumNumberOfClients)
						{
							// Maximum number of client connections
							// reached.
							Debug::log("Maximum number of clients reached, "
							           "dropping TCP SYN");
							return false;
						}
						currentClientCount++;
						Debug::log("Permitting new client TCP connection from "
						           "{}.{}.{}.{}:{}",
						           static_cast<int>(endpoint) & 0xff,
						           static_cast<int>(endpoint >> 8) & 0xff,
						           static_cast<int>(endpoint >> 16) & 0xff,
						           static_cast<int>(endpoint >> 24) & 0xff,
						           static_cast<int>(ntohs(remotePortNumber)));
						EndpointsTable<uint32_t>::instance().add_endpoint(
						  IPProtocolNumber::TCP,
						  endpoint,
						  localPortNumber,
						  remotePortNumber);
						return true;
					}
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
#if CHERIOT_RTOS_OPTION_IPv6
			// For now, permit all outbound IPv6 packets.
			// FIXME: Check the firewall for IPv6!
			case EtherType::IPv6:
			{
				Debug::log("Permitting outbound IPv6 packet");
				return true;
				break;
			}
#endif
		}
		return false;
	}

	bool packet_filter_ingress(const uint8_t *data, size_t length)
	{
		uint32_t stateSnapshot = tcpipRestartState->load();
		if (stateSnapshot != 0 &&
		    ((stateSnapshot & RestartStateDriverKickedBit) == 0))
		{
			// We are in a reset and the driver has not yet been
			// restarted.
			Debug::log("Dropping packet due to network stack restart.");
			return false;
		}

		static constinit MACAddress broadcastMAC = {
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
		// Not a valid Ethernet frame (64 bytes including four-byte FCS, which
		// is stripped by this point).
		if (length < 60)
		{
			Debug::log("Dropping frame with length {}", length);
			return false;
		}
		EthernetHeader *ethernetHeader =
		  reinterpret_cast<EthernetHeader *>(const_cast<uint8_t *>(data));
		if ((ethernetHeader->destination != mac_address()) &&
		    (ethernetHeader->destination != broadcastMAC))
		{
			Debug::log(
			  "Dropping frame with destination MAC address {}:{}:{}:{}:{}:{}",
			  ethernetHeader->destination[0],
			  ethernetHeader->destination[1],
			  ethernetHeader->destination[2],
			  ethernetHeader->destination[3],
			  ethernetHeader->destination[4],
			  ethernetHeader->destination[5]);
			return false;
		}
		switch (ethernetHeader->etherType)
		{
#if CHERIOT_RTOS_OPTION_IPv6
			// For now, testing with v6 disabled.
			// FIXME: Check the firewall for IPv6!
			case EtherType::IPv6:
				return true;
#endif
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
	// Test the small table (does nothing in release builds).
	test_small_table();
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

void firewall_add_tcpipv4_server_port(uint16_t localPort)
{
	EndpointsTable<uint32_t>::instance().add_server_port(localPort);
}

void firewall_remove_tcpipv4_server_port(uint16_t localPort)
{
	EndpointsTable<uint32_t>::instance().remove_server_port(localPort);
}

void firewall_add_tcpipv4_endpoint(uint32_t remoteAddress,
                                   uint16_t localPort,
                                   uint16_t remotePort)
{
	EndpointsTable<uint32_t>::instance().add_endpoint(
	  IPProtocolNumber::TCP, remoteAddress, localPort, remotePort);
}

void firewall_add_udpipv4_endpoint(uint32_t remoteAddress,
                                   uint16_t localPort,
                                   uint16_t remotePort)
{
	EndpointsTable<uint32_t>::instance().add_endpoint(
	  IPProtocolNumber::UDP, remoteAddress, localPort, remotePort);
}

void firewall_remove_tcpipv4_local_endpoint(uint16_t localPort)
{
	// Server ports are likely to be associated to more than one entry in
	// the firewall.
	Debug::Assert(
	  !EndpointsTable<uint32_t>::instance().is_server_port(localPort),
	  "Trying to remove a local endpoint on a server port.");
	EndpointsTable<uint32_t>::instance().remove_endpoint(IPProtocolNumber::TCP,
	                                                     localPort);
}

void firewall_remove_tcpipv4_remote_endpoint(uint32_t remoteAddress,
                                             uint16_t localPort,
                                             uint16_t remotePort)
{
	EndpointsTable<uint32_t>::instance().remove_endpoint(
	  IPProtocolNumber::TCP, remoteAddress, localPort, remotePort);
	if (EndpointsTable<uint32_t>::instance().is_server_port(localPort))
	{
		currentClientCount--;
	}
}

void firewall_remove_udpipv4_local_endpoint(uint16_t localPort)
{
	EndpointsTable<uint32_t>::instance().remove_endpoint(IPProtocolNumber::UDP,
	                                                     localPort);
}

void firewall_remove_udpipv4_remote_endpoint(uint32_t remoteAddress,
                                             uint16_t localPort,
                                             uint16_t remotePort)
{
	EndpointsTable<uint32_t>::instance().remove_endpoint(
	  IPProtocolNumber::UDP, remoteAddress, localPort, remotePort);
}

namespace
{

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

	/**
	 * Defensively copy the address, returns nullopt if the address is invalid.
	 */
	std::optional<IPv6Address> copy_address(const uint8_t *address)
	{
		IPv6Address copy;
		if (!blocking_forever<heap_claim_fast>(address, nullptr) ||
		    !CHERI::check_pointer<CHERI::PermissionSet{
		      CHERI::Permission::Load}>(address, copy.size()))
		{
			Debug::log("Invalid IPv6 address {}", address);
			return std::nullopt;
		}
		memcpy(copy.data(), address, copy.size());
		return copy;
	}
} // namespace

#if CHERIOT_RTOS_OPTION_IPv6
void firewall_add_tcpipv6_server_port(uint16_t localPort)
{
	EndpointsTable<IPv6Address>::instance().add_server_port(localPort);
}

void firewall_remove_tcpipv6_server_port(uint16_t localPort)
{
	EndpointsTable<IPv6Address>::instance().remove_server_port(localPort);
}

void firewall_add_tcpipv6_endpoint(uint8_t *remoteAddress,
                                   uint16_t localPort,
                                   uint16_t remotePort)
{
	if (auto copy = copy_address(remoteAddress))
	{
		EndpointsTable<IPv6Address>::instance().add_endpoint(
		  IPProtocolNumber::TCP, *copy, localPort, remotePort);
	}
}

void firewall_add_udpipv6_endpoint(uint8_t *remoteAddress,
                                   uint16_t localPort,
                                   uint16_t remotePort)
{
	if (auto copy = copy_address(remoteAddress))
	{
		EndpointsTable<IPv6Address>::instance().add_endpoint(
		  IPProtocolNumber::UDP, *copy, localPort, remotePort);
	}
}

void firewall_remove_tcpipv6_local_endpoint(uint16_t localPort)
{
	Debug::Assert(
	  !EndpointsTable<IPv6Address>::instance().is_server_port(localPort),
	  "Trying to remove a local endpoint on a server port.");
	EndpointsTable<IPv6Address>::instance().remove_endpoint(
	  IPProtocolNumber::TCP, localPort);
}

void firewall_remove_tcpipv6_remote_endpoint(uint8_t *remoteAddress,
                                             uint16_t localPort,
                                             uint16_t remotePort)
{
	if (auto copy = copy_address(remoteAddress))
	{
		EndpointsTable<IPv6Address>::instance().remove_endpoint(
		  IPProtocolNumber::TCP, *copy, localPort, remotePort);
		if (EndpointsTable<IPv6Address>::instance().is_server_port(localPort))
		{
			currentClientCount--;
		}
	}
}

void firewall_remove_udpipv6_local_endpoint(uint16_t localPort)
{
	EndpointsTable<IPv6Address>::instance().remove_endpoint(
	  IPProtocolNumber::UDP, localPort);
}

void firewall_remove_udpipv6_remote_endpoint(uint8_t *remoteAddress,
                                             uint16_t localPort,
                                             uint16_t remotePort)
{
	if (auto copy = copy_address(remoteAddress))
	{
		EndpointsTable<IPv6Address>::instance().remove_endpoint(
		  IPProtocolNumber::UDP, *copy, localPort, remotePort);
	}
}
#endif

bool ethernet_driver_start(std::atomic<uint8_t> *state)
{
	if (tcpipRestartState == nullptr)
	{
		if (!CHERI::check_pointer<CHERI::PermissionSet{
		      CHERI::Permission::Load, CHERI::Permission::Global}>(
		      state, sizeof(*state)))
		{
			Debug::log("Invalid TCP/IP state pointer {}", state);
			return false;
		}
		tcpipRestartState = state;
	}
	if (tcpipRestartState->load() != 0)
	{
		// This is a restart, no need to actually reset the driver.
		// Instead, just remove all firewall entries.
		Debug::log("Network stack restart: clearing all entries.");
		EndpointsTable<IPv6Address>::instance().clear(IPProtocolNumber::UDP);
		EndpointsTable<IPv6Address>::instance().clear(IPProtocolNumber::TCP);
		EndpointsTable<uint32_t>::instance().clear(IPProtocolNumber::UDP);
		EndpointsTable<uint32_t>::instance().clear(IPProtocolNumber::TCP);
		return true;
	}
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
	ethernet.mac_address_set(mac_address());
	// Poke the barrier and make the driver thread start.
	barrier = 2;
	barrier.notify_one();
	return true;
}

uint8_t *firewall_mac_address_get()
{
	CHERI::Capability ret{mac_address().data()};
	ret.permissions() &= {CHERI::Permission::Load, CHERI::Permission::Global};
	Debug::Assert(ret.bounds() == 6, "Invalid MAC address bounds");
	return ret;
}
