// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <FreeRTOS.h>
#include <FreeRTOS_IP.h>
#include <FreeRTOS_ND.h>

#include "../firewall/firewall.h"
#include "network-internal.h"

#include <FreeRTOS_IP_Private.h>
#include <NetAPI.h>
#include <debug.hh>
#include <function_wrapper.hh>
#include <limits>
#include <locks.hh>
#include <platform-ethernet.hh>
#include <token.h>

using Debug            = ConditionalDebug<false, "Network stack wrapper">;
constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

using CHERI::Capability;
using CHERI::check_pointer;
using CHERI::Permission;
using CHERI::PermissionSet;

namespace
{

	/**
	 * The sealed wrapper around a FreeRTOS socket.
	 */
	struct SealedSocket
	{
		/**
		 * The lock protecting this socket.
		 */
		FlagLockPriorityInherited socketLock;
		/**
		 * The FreeRTOS socket.  It would be nice if this didn't require a
		 * separate allocation but FreeRTOS+TCP isn't designed to support that
		 * use case.
		 */
		FreeRTOS_Socket_t *socket;
	};

	/**
	 * Returns the key with which SealedSocket instances are sealed.
	 */
	__always_inline SKey socket_key()
	{
		return STATIC_SEALING_TYPE(Socket);
	}

	/**
	 * Unseal `sealedSocket` and, if it is sealed with the correct type, pass
	 * it to `operation`.  If the unsealing fails, return `-EINVAL`.  This is a
	 * helper function used for operations on sockets.
	 */
	int with_sealed_socket(auto operation, Sealed<SealedSocket> sealedSocket)
	{
		auto *socket = token_unseal(socket_key(), sealedSocket);
		if (socket == nullptr)
		{
			Debug::log("Failed to unseal socket");
			return -EINVAL;
		}
		return operation(socket);
	}

	/**
	 * Wrapper around `with_sealed_socket` that locks the socket before calling
	 * the operation.  This is used by everything except the close operation
	 * (which must not try to release the lock after the lock has been
	 * deallocated).
	 */
	int with_sealed_socket(Timeout             *timeout,
	                       auto                 operation,
	                       Sealed<SealedSocket> sealedSocket)
	{
		return with_sealed_socket(
		  [&](SealedSocket *socket) {
			  if (LockGuard g{socket->socketLock, timeout})
			  {
				  return operation(socket);
			  }
			  return -ETIMEDOUT;
		  },
		  sealedSocket);
	}

	/**
	 * RAII helper for claiming heap objects.  This can be used with heap and
	 * non-heap objects and will maintain a claim on the object until it goes
	 * out of scope.  If the object is not heap-allocated then this silently
	 * pretends to have added a claim (non-heap objects cannot be deallocated).
	 */
	template<typename T>
	class Claim
	{
		/**
		 * True if the object can be guaranteed not to be deallocated for the
		 * lifetime of this object.
		 */
		bool isValid;
		/**
		 * True if the object is heap-allocated.
		 */
		bool isHeapObject;
		/**
		 * The object that we are claiming.
		 */
		T *value;
		/**
		 * The capability that we are using to claim the object (and to
		 * subsequently drop the claim).
		 */
		SObj mallocCapability;

		public:
		/**
		 * Create a claim on `value` using `mallocCapability`.
		 */
		__always_inline Claim(SObj mallocCapability, T *value)
		  : value{value}, mallocCapability{mallocCapability}
		{
			if (!heap_address_is_valid(value))
			{
				isValid      = true;
				isHeapObject = false;
			}
			else
			{
				auto claimRet =
				  heap_claim(mallocCapability,
				             const_cast<std::remove_const_t<T> *>(value)) > 0;
				isValid      = claimRet > 0;
				isHeapObject = true;
			}
		}

		/**
		 * Drop the claim on the object.
		 */
		__always_inline ~Claim()
		{
			if (isValid && isHeapObject)
			{
				heap_free(mallocCapability,
				          const_cast<std::remove_const_t<T> *>(value));
			}
		}

		/**
		 * Drop ownership of the claim and return the claimed object.  The
		 * caller is responsible for releasing the claim.
		 */
		__always_inline T *release()
		{
			isValid = false;
			return value;
		}

		/**
		 * Implicit conversion to bool.  True if the claim is valid.
		 */
		__always_inline operator bool() const
		{
			return isValid;
		}
	};

	/**
	 * The freertos_addrinfo structure is huge (>300 bytes) and so we
	 * definitely don't want to stack-allocate it.  Fortunately, when used for
	 * hints, only the second field is referenced.  This means that we can use
	 * the prefix.
	 */
	struct addrinfo_hints
	{
		BaseType_t ai_flags;
		BaseType_t ai_family;
	};
	static_assert(offsetof(addrinfo_hints, ai_family) ==
	              offsetof(freertos_addrinfo, ai_family));

	/**
	 * Resolve a hostname to an IP address.  If `useIPv6` is true, then this
	 * will favour IPv6 addresses, but can still return IPv4 addresses if no
	 * IPv6 address is available.
	 */
	NetworkAddress host_resolve(const char *hostname, bool useIPv6 = UseIPv6)
	{
		struct addrinfo_hints hints;
		hints.ai_family = useIPv6 ? FREERTOS_AF_INET6 : FREERTOS_AF_INET;
		struct freertos_addrinfo *results = nullptr;
		auto                      ret =
		  FreeRTOS_getaddrinfo(hostname,
		                       nullptr,
		                       reinterpret_cast<freertos_addrinfo *>(&hints),
		                       &results);
		if (ret != 0)
		{
			if (useIPv6)
			{
				return host_resolve(hostname, false);
			}
			Debug::log("DNS request returned: {}", ret);
			return {0, NetworkAddress::AddressKindInvalid};
		}

		NetworkAddress address;
		bool           isIPv6 = false;
		for (freertos_addrinfo *r = results; r != nullptr; r = r->ai_next)
		{
			Debug::log("Canonical name: {}", r->ai_canonname);
			if (r->ai_family == FREERTOS_AF_INET6)
			{
				memcpy(
				  address.ipv6, r->ai_addr->sin_address.xIP_IPv6.ucBytes, 16);
				address.kind = NetworkAddress::AddressKindIPv6;
				Debug::log("Got IPv6 address");
			}
			else
			{
				address.ipv4 = r->ai_addr->sin_address.ulIP_IPv4;
				address.kind = NetworkAddress::AddressKindIPv4;
				Debug::log("Got IPv4 address");
				Debug::log("Got address: {}.{}.{}.{}",
				           (int)r->ai_addr->sin_address.ulIP_IPv4 & 0xff,
				           (int)r->ai_addr->sin_address.ulIP_IPv4 >> 8 & 0xff,
				           (int)r->ai_addr->sin_address.ulIP_IPv4 >> 16 & 0xff,
				           (int)r->ai_addr->sin_address.ulIP_IPv4 >> 24 & 0xff);
			}
		}
		return address;
	}

	/**
	 * Helper to run a FreeRTOS blocking socket call with a CHERIoT RTOS
	 * timeout.  It's annoying that this needs to query the system tick
	 * multiple times, but the FreeRTOS APIs are not composable.  This sets the
	 * timeout on the socket (for the direction identified by `directionFlag`),
	 * calls `fn`, and then updates the timeout with the number of ticks taken.
	 */
	auto with_freertos_timeout(Timeout           *timeout,
	                           FreeRTOS_Socket_t *socket,
	                           auto               directionFlag,
	                           auto             &&fn)
	{
		auto       startTick = thread_systemtick_get();
		TickType_t remaining = timeout->remaining;
		FreeRTOS_setsockopt(socket, 0, directionFlag, &remaining, 0);
		// Wait for at least one byte to be available.
		auto ret = fn();
		Debug::log("Blocking call returned {}", ret);
		auto endTick = thread_systemtick_get();
		timeout->elapse(((uint64_t(endTick.hi) << 32) | endTick.lo) -
		                ((uint64_t(startTick.hi) << 32) | startTick.lo));
		return ret;
	}

	__noinline int network_socket_receive_internal(
	  Timeout                                *timeout,
	  SObj                                    sealedSocket,
	  FunctionWrapper<void *(int &available)> prepareBuffer)
	{
		if (!check_timeout_pointer(timeout))
		{
			return -EINVAL;
		}
		return with_sealed_socket(
		  timeout,
		  [&](SealedSocket *socket) {
			  do
			  {
				  int available =
				    FreeRTOS_recv(socket->socket,
				                  nullptr,
				                  std::numeric_limits<size_t>::max(),
				                  FREERTOS_MSG_PEEK | FREERTOS_MSG_DONTWAIT);
				  if (available > 0)
				  {
					  void *buffer = prepareBuffer(available);
					  Debug::log(
					    "Receiving {} bytes into {}", available, buffer);
					  if (buffer == nullptr)
					  {
						  return available;
					  }
					  return FreeRTOS_recv(socket->socket,
					                       buffer,
					                       available,
					                       FREERTOS_MSG_DONTWAIT);
				  }
				  if (available < 0)
				  {
					  if (available == -pdFREERTOS_ERRNO_ENOTCONN)
					  {
						  Debug::log("Connection closed, not receiving");
						  return -ENOTCONN;
					  }
					  // Something went wrong?
					  Debug::log("Receive failed with unexpected error: {}",
					             available);
					  return -EINVAL;
				  }
				  if (!timeout->may_block())
				  {
					  return -ETIMEDOUT;
				  }
				  auto ret = with_freertos_timeout(
				    timeout, socket->socket, FREERTOS_SO_RCVTIMEO, [&] {
					    // Wait for at least one byte to be available.
					    return FreeRTOS_recv(
					      socket->socket, nullptr, 1, FREERTOS_MSG_PEEK);
				    });
			  } while (timeout->may_block());
			  return -ETIMEDOUT;
		  },
		  sealedSocket);
	}

} // namespace

NetworkAddress network_host_resolve(const char *hostname, bool useIPv6)
{
	return host_resolve(hostname, useIPv6);
}

SObj network_socket_create_and_bind(Timeout       *timeout,
                                    SObj           mallocCapability,
                                    bool           isIPv6,
                                    ConnectionType type,
                                    uint16_t       localPort)
{
	const auto Family = isIPv6 ? FREERTOS_AF_INET6 : FREERTOS_AF_INET;
	Socket_t   socket = FreeRTOS_socket(
	    Family,
      type == ConnectionTypeTCP ? FREERTOS_SOCK_STREAM : FREERTOS_SOCK_DGRAM,
      type == ConnectionTypeTCP ? FREERTOS_IPPROTO_TCP : FREERTOS_IPPROTO_UDP);
	if (socket == nullptr)
	{
		Debug::log("Failed to create socket");
		return nullptr;
	}
	freertos_sockaddr localAddress;
	memset(&localAddress, 0, sizeof(localAddress));
	localAddress.sin_len    = sizeof(localAddress);
	localAddress.sin_port   = FreeRTOS_htons(localPort);
	localAddress.sin_family = Family;

	auto bindResult =
	  FreeRTOS_bind(socket, &localAddress, sizeof(localAddress));
	if (bindResult != 0)
	{
		return nullptr;
	}
	// Claim the socket so that it counts towards the caller's quota.  The
	// network stack also keeps a claim to it.  We will drop this claim on
	// deallocation.
	Claim c{mallocCapability, socket};
	if (!c)
	{
		Debug::log("Failed to claim socket");
		FreeRTOS_closesocket(socket);
		return nullptr;
	}
	// TODO: This should have nice RAII wrappers!
	auto [socketWrapper, sealedSocket] =
	  token_allocate<SealedSocket>(timeout, mallocCapability, socket_key());
	if (socketWrapper == nullptr)
	{
		Debug::log("Failed to allocate socket wrapper");
		FreeRTOS_closesocket(socket);
		return nullptr;
	}
	socketWrapper->socket = socket;
	c.release();
	return sealedSocket;
}

int network_socket_connect_tcp_internal(Timeout       *timeout,
                                        SObj           socket,
                                        NetworkAddress address,
                                        short          port)
{
	return with_sealed_socket(
	  [&](SealedSocket *socket) {
		  bool                     isIPv6 = socket->socket->bits.bIsIPv6;
		  struct freertos_sockaddr server;
		  memset(&server, 0, sizeof(server));
		  server.sin_len  = sizeof(server);
		  server.sin_port = FreeRTOS_htons(port);
		  if (isIPv6)
		  {
			  server.sin_family = FREERTOS_AF_INET6;
			  memcpy(server.sin_address.xIP_IPv6.ucBytes, address.ipv6, 16);
		  }
		  else
		  {
			  server.sin_family            = FREERTOS_AF_INET;
			  server.sin_address.ulIP_IPv4 = address.ipv4;
		  }
		  Debug::log("Trying to connect to server");
		  switch (FreeRTOS_connect(socket->socket, &server, sizeof(server)))
		  {
			  default:
				  return -EINVAL;
			  case 0:
				  Debug::log("Successfully connected to server");
				  return 0;
			  case -pdFREERTOS_ERRNO_EWOULDBLOCK:
			  case -pdFREERTOS_ERRNO_ETIMEDOUT:
				  return -ETIMEDOUT;
		  }
	  },
	  socket);
}

SObj network_socket_udp(Timeout *timeout, SObj mallocCapability, bool isIPv6)
{
	if (!check_timeout_pointer(timeout))
	{
		return nullptr;
	}
	return network_socket_create_and_bind(
	  timeout, mallocCapability, isIPv6, ConnectionTypeUDP);
}

int network_socket_close(Timeout *t, SObj mallocCapability, SObj sealedSocket)
{
	if (!check_timeout_pointer(t))
	{
		return -EINVAL;
	}
	return with_sealed_socket(
	  [=](SealedSocket *socket) {
		  // Don't use a lock guard here, we don't want to release the lock if
		  // it's been deallocated.  This must be released on all return paths
		  // except the one for success.
		  if (!socket->socketLock.try_lock(t))
		  {
			  return -ETIMEDOUT;
		  }
		  socket->socketLock.upgrade_for_destruction();
		  // Drop the caller's claim on the socket.
		  if (heap_free(mallocCapability, socket->socket) != 0)
		  {
			  Debug::log("Failed to free socket");
			  // Release the lock so that we don't leak it.
			  socket->socketLock.unlock();
			  return -EINVAL;
		  }
		  bool isTCP = socket->socket->ucProtocol == FREERTOS_IPPROTO_TCP;
		  // Shut down the socket before closing the firewall.
		  FreeRTOS_shutdown(socket->socket, FREERTOS_SHUT_RDWR);
		  if (socket->socket->bits.bIsIPv6)
		  {
			  if (isTCP)
			  {
				  firewall_remove_tcpipv6_endpoint(socket->socket->usLocalPort);
			  }
			  else
			  {
				  firewall_remove_udpipv6_local_endpoint(
				    socket->socket->usLocalPort);
			  }
		  }
		  else
		  {
			  if (isTCP)
			  {
				  firewall_remove_tcpipv4_endpoint(socket->socket->usLocalPort);
			  }
			  else
			  {
				  firewall_remove_udpipv4_local_endpoint(
				    socket->socket->usLocalPort);
			  }
		  }
		  // Close the socket.  Another thread will actually clean up the
		  // memory.
		  FreeRTOS_closesocket(socket->socket);
		  token_obj_destroy(mallocCapability, socket_key(), sealedSocket);
		  return 0;
	  },
	  sealedSocket);
}

NetworkReceiveResult network_socket_receive_from(Timeout *timeout,
                                                 SObj     mallocCapability,
                                                 SObj     socket,
                                                 NetworkAddress *address,
                                                 uint16_t       *port)
{
	uint8_t *buffer = nullptr;
	ssize_t  result = with_sealed_socket(
	   timeout,
	   [&](SealedSocket *socket) {
          freertos_sockaddr remoteAddress;
          socklen_t         remoteAddressLength = sizeof(remoteAddress);
          uint8_t          *unclaimedBuffer     = nullptr;
          int               received            = with_freertos_timeout(
		                              timeout, socket->socket, FREERTOS_SO_RCVTIMEO, [&] {
                // Receive a packet with zero copy.  The zero-copy interface for
                // UDP returns a pointer to the packet buffer, so we don't end
                // up claiming a huge stream buffer.
                return FreeRTOS_recvfrom(socket->socket,
			                                                       &unclaimedBuffer,
			                                                       0,
			                                                       FREERTOS_ZERO_COPY,
			                                                       &remoteAddress,
			                                                       &remoteAddressLength);
            });
		   if (received > 0)
          {
              ssize_t claimed = heap_claim(mallocCapability, unclaimedBuffer);
              Debug::log(
			     "Claimed {} bytes for {}-byte buffer", claimed, received);
              FreeRTOS_ReleaseUDPPayloadBuffer(unclaimedBuffer);
              if (claimed <= 0)
              {
                  return -ENOMEM;
              }
              Capability claimedBuffer{unclaimedBuffer};
              claimedBuffer.bounds() = received;
              if (heap_claim_fast(timeout, address, port) < 0)
              {
                  return -ETIMEDOUT;
              }
              if (address != nullptr)
              {
                  if (!check_pointer<PermissionSet{Permission::Store}>(address))
                  {
                      return -EPERM;
                  }
                  if (remoteAddress.sin_family == FREERTOS_AF_INET6)
                  {
                      address->kind = NetworkAddress::AddressKindIPv6;
                      memcpy(address->ipv6,
					          remoteAddress.sin_address.xIP_IPv6.ucBytes,
					          16);
                  }
                  else
                  {
                      address->kind = NetworkAddress::AddressKindIPv4;
                      address->ipv4 = remoteAddress.sin_address.ulIP_IPv4;
                  }
              }
              if (port != nullptr)
              {
                  if (!check_pointer<PermissionSet{Permission::Store}>(address))
                  {
                      return -EPERM;
                  }
                  *port = FreeRTOS_ntohs(remoteAddress.sin_port);
              }
              if (received > 0)
              {
                  buffer = claimedBuffer;
                  return received;
              }
          }
          else if (received < 0)
          {
              if (received == -pdFREERTOS_ERRNO_ENOTCONN)
              {
                  Debug::log("Connection closed, not receiving");
                  return -ENOTCONN;
              }
              if (received == -pdFREERTOS_ERRNO_EAGAIN)
              {
                  return -ETIMEDOUT;
              }
              // Something went wrong?
              Debug::log("Receive failed with unexpected error: {}", received);
              return -EINVAL;
          }
          return received;
	   },
	   socket);
	return {result, buffer};
}

int network_socket_receive_preallocated(Timeout *timeout,
                                        SObj     sealedSocket,
                                        void    *buffer,
                                        size_t   length)
{
	return network_socket_receive_internal(
	  timeout, sealedSocket, [&](int &available) -> void * {
		  int ret = heap_claim_fast(timeout, buffer);
		  if (ret != 0)
		  {
			  available = ret;
			  return nullptr;
		  }
		  if (!check_pointer<PermissionSet{Permission::Store}>(buffer, length))
		  {
			  available = -EPERM;
			  return nullptr;
		  }
		  available = length;
		  return buffer;
	  });
}

NetworkReceiveResult network_socket_receive(Timeout *timeout,
                                            SObj     mallocCapability,
                                            SObj     sealedSocket)
{
	uint8_t *buffer = nullptr;
	ssize_t  result = network_socket_receive_internal(
	   timeout, sealedSocket, [&](int &available) -> void  *{
          do
          {
              // Do the initial allocation without timeout: if the quota or the
              // heap is almost exhausted, we will block until timeout without
              // achieving anything.
              Timeout zeroTimeout{0};
              buffer = static_cast<uint8_t *>(
                heap_allocate(&zeroTimeout, mallocCapability, available));
              timeout->elapse(zeroTimeout.elapsed);
              if (buffer == nullptr)
              {
                  // If there's a lot of data, just try a small
                  // allocation and see if that works.
                  if (available > 128)
                  {
                      available = 128;
                      continue;
                  }
                  // If allocation failed and the timeout is zero, give
                  // up now.
                  if (!timeout->may_block())
                  {
                      available = -ETIMEDOUT;
                      return nullptr;
                  }
                  // If there's time left, let's try allocating a
                  // smaller buffer.
                  auto quota = heap_quota_remaining(mallocCapability);
                  // Subtract 16 bytes to account for the allocation
                  // header.
                  if ((quota < available) && (quota > 16))
                  {
                      available = quota - 16;
                      continue;
                  }
                  available = -ENOMEM;
                  return nullptr;
              }
          } while (buffer == nullptr);
          return buffer;
	   });
	return {result, buffer};
}

ssize_t
network_socket_send(Timeout *timeout, SObj socket, void *buffer, size_t length)
{
	if (!check_timeout_pointer(timeout))
	{
		return -EINVAL;
	}
	return with_sealed_socket(
	  timeout,
	  [&](SealedSocket *socket) {
		  // Ensure that the buffer is valid for the duration of the send.
		  Claim claim{MALLOC_CAPABILITY, buffer};
		  if (!claim)
		  {
			  Debug::log("Failed to claim buffer");
			  return -ENOMEM;
		  }
		  // At this point, we know that the buffer can't go away from under us,
		  // so it's safe to do the checks.
		  if (!CHERI::check_pointer<PermissionSet{Permission::Load}>(buffer,
		                                                             length))
		  {
			  return -EPERM;
		  }
		  Debug::log("Sending {}-byte TCP packet from {}", length, buffer);
		  int ret = heap_claim_fast(timeout, buffer);
		  if (ret < 0)
		  {
			  return ret;
		  }
		  if (!check_pointer<PermissionSet{Permission::Load}>(buffer, length))
		  {
			  return -EPERM;
		  }
		  ret = with_freertos_timeout(
		    timeout, socket->socket, FREERTOS_SO_SNDTIMEO, [&] {
			    return FreeRTOS_send(socket->socket, buffer, length, 0);
		    });
		  Debug::log("FreeRTOS_send returned {}", ret);
		  if (ret >= 0)
		  {
			  return ret;
		  }
		  if (ret == -pdFREERTOS_ERRNO_ENOTCONN)
		  {
			  return -ENOTCONN;
		  }
		  // Catchall
		  Debug::log("Send failed with unexpected error: {}", ret);
		  return -EINVAL;
	  },
	  socket);
}

ssize_t network_socket_send_to(Timeout              *timeout,
                               SObj                  socket,
                               const NetworkAddress *address,
                               uint16_t              port,
                               const void           *buffer,
                               size_t                length)
{
	if (!check_timeout_pointer(timeout))
	{
		return -EINVAL;
	}
	return with_sealed_socket(
	  timeout,
	  [&](SealedSocket *socket) {
		  struct freertos_sockaddr server;
		  memset(&server, 0, sizeof(server));
		  server.sin_len  = sizeof(server);
		  server.sin_port = FreeRTOS_htons(port);
		  if (heap_claim_fast(timeout, address) < 0)
		  {
			  Debug::log("Failed to claim address");
			  return -ETIMEDOUT;
		  }
		  if (!check_pointer<PermissionSet{Permission::Load}>(address))
		  {
			  Debug::log("Invalid address pointer");
			  return -EPERM;
		  }
		  if (address->kind == NetworkAddress::AddressKindIPv6)
		  {
			  server.sin_family = FREERTOS_AF_INET6;
			  memcpy(server.sin_address.xIP_IPv6.ucBytes, address->ipv6, 16);
		  }
		  else
		  {
			  server.sin_family            = FREERTOS_AF_INET;
			  server.sin_address.ulIP_IPv4 = address->ipv4;
		  }
		  // Ensure that the buffer is valid for the duration of the send.
		  Claim claim{MALLOC_CAPABILITY, buffer};
		  if (!claim)
		  {
			  Debug::log("Failed to claim buffer");
			  return -ENOMEM;
		  }
		  // At this point, we know that the buffer can't go away from under us,
		  // so it's safe to do the checks.
		  if (!CHERI::check_pointer<PermissionSet{Permission::Load}>(buffer,
		                                                             length))
		  {
			  Debug::log("Buffer is invalid: {}", buffer);
			  return -EPERM;
		  }
		  Debug::log("Sending {}-byte UDP packet", length);
		  // FIXME: This should use the socket options to set / update
		  // the timeout.
		  auto ret = with_freertos_timeout(
		    timeout, socket->socket, FREERTOS_SO_SNDTIMEO, [&] {
			    return FreeRTOS_sendto(
			      socket->socket, buffer, length, 0, &server, sizeof(server));
		    });
		  Debug::log("Send returned {}", ret);
		  if (ret >= 0)
		  {
			  return ret;
		  }
		  if (ret == -pdFREERTOS_ERRNO_ENOTCONN)
		  {
			  return -ENOTCONN;
		  }
		  // Catchall
		  Debug::log("Send failed with unexpected error: {}", ret);
		  return -EINVAL;
	  },
	  socket);
}

SocketKind network_socket_kind(SObj socket)
{
	SocketKind kind = {SocketKind::Invalid, 0};
	with_sealed_socket(
	  [&](SealedSocket *socket) {
		  if (socket->socket->ucProtocol == FREERTOS_IPPROTO_TCP)
		  {
			  kind.protocol = socket->socket->bits.bIsIPv6
			                    ? SocketKind::TCPIPv6
			                    : SocketKind::TCPIPv4;
		  }
		  else
		  {
			  kind.protocol = socket->socket->bits.bIsIPv6
			                    ? SocketKind::UDPIPv6
			                    : SocketKind::UDPIPv4;
		  }
		  kind.localPort = listGET_LIST_ITEM_VALUE(
		    (&((socket->socket)->xBoundSocketListItem)));
		  return 0;
	  },
	  socket);
	return kind;
}
