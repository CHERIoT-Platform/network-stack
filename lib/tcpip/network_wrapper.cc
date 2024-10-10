// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <FreeRTOS.h>
#include <FreeRTOS_IP.h>
#include <FreeRTOS_ND.h>
#include <tcpip_error_handler.h>

#include "network-internal.h"
#include "tcpip-internal.h"

#include <FreeRTOS_IP_Private.h>
#include <NetAPI.h>
#include <debug.hh>
#include <function_wrapper.hh>
#include <limits>
#include <locks.hh>
#include <platform-ethernet.hh>
#include <token.h>

using Debug = ConditionalDebug<false, "Network stack wrapper">;

#include "../firewall/firewall.hh"

/**
 * Statically match constants from the firewall which must stay in sync with
 * the TCP/IP stack.
 */
static_assert(FirewallMaximumNumberOfClients ==
              MAX_SIMULTANEOUS_TCP_CONNECTIONS);
static_assert(RestartStateDriverKickedBit == DriverKicked);

constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

// IP thread global lock. See comment in `FreeRTOS_IP_wrapper.c`.
extern struct FlagLockState ipThreadLockState;

/**
 * This function controls the FreeRTOS+TCP network thread event loop.
 *
 * Returning 0 will cause the event loop to return, which we want to do when a
 * reset of the network stack is triggered.
 */
extern "C" int ipFOREVER(void)
{
	// We must interrupt the loop if a reset is ongoing (`Restarting`).
	// However, we must still allow the loop to run during the early stages
	// of a reset (`IpThreadKicked`). Note that it is absolutely fine if
	// the state changes after the check, as we will detect that change in
	// the next loop iteration.
	uint8_t state = restartState.load();
	return (state == 0) || ((state & IpThreadKicked) != 0);
}

/**
 * Current socket epoch. This is used to detect sockets that belong to a
 * previous instance of the network stack.
 *
 * This should not be reset by the error handler and is reset-critical.
 */
std::atomic<uint32_t> currentSocketEpoch = 0;

// Network stack reset globals. See comments in `tcpip-internal.h`.
std::atomic<uint8_t>                      restartState    = 0;
std::atomic<uint8_t>                      userThreadCount = 0;
ds::linked_list::Sentinel<SocketRingLink> sealedSockets;
FlagLockPriorityInherited                 sealedSocketsListLock;

using CHERI::Capability;
using CHERI::check_pointer;
using CHERI::Permission;
using CHERI::PermissionSet;

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

	/**
	 * Returns the key with which SealedSocket instances are sealed.
	 */
	__always_inline SKey socket_key()
	{
		return STATIC_SEALING_TYPE(Socket);
	}

	/**
	 * Unseal `sealedSocket` and, if it is sealed with the correct type,
	 * pass it to `operation`. This is a helper function used for
	 * operations on sockets.
	 *
	 * This function will return a negative code on error:
	 *
	 * `-EINVAL` if the unsealing fails;
	 *
	 * `-EAGAIN` if the network stack is undergoing a reset;
	 *
	 * `-ENOTCONN` if the epoch of the socket does not match the current
	 * epoch of the network stack, and `operation` is not a close
	 * operation, as specified by `IsCloseOperation`. This will happen if
	 * the socket is coming from a previous instantiation of the network
	 * stack.
	 */
	template<bool IsCloseOperation = false>
	int with_sealed_socket(auto operation, Sealed<SealedSocket> sealedSocket)
	{
		return with_restarting_checks(
		  [&]() {
			  auto *socket = token_unseal(socket_key(), sealedSocket);
			  if (socket == nullptr)
			  {
				  Debug::log("Failed to unseal socket");
				  return -EINVAL;
			  }
			  if (socket->socketEpoch != currentSocketEpoch.load())
			  {
				  Debug::log(
				    "This socket "
				    "corresponds to a previous instance of the network stack "
				    "(epochs mismatch: socket = {}; current = {}).",
				    socket->socketEpoch,
				    currentSocketEpoch.load());
				  if constexpr (!IsCloseOperation)
				  {
					  // This should push the caller to free the socket.
					  return -ENOTCONN;
				  }
				  Debug::log("Permitting unsealing to destroy the socket.");
			  }

			  return operation(socket);
		  },
		  -EAGAIN /* return -EAGAIN if we are restarting */);
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
	struct AddrinfoHints
	{
		BaseType_t flags;
		BaseType_t family;
	};
	static_assert(offsetof(AddrinfoHints, family) ==
	              offsetof(freertos_addrinfo, ai_family));

	/**
	 * Resolve a hostname to an IP address.  If `useIPv6` is true, then this
	 * will favour IPv6 addresses, but can still return IPv4 addresses if no
	 * IPv6 address is available.
	 */
	int
	host_resolve(const char *hostname, bool useIPv6, NetworkAddress *address)
	{
		struct AddrinfoHints hints;
		hints.family = useIPv6 ? FREERTOS_AF_INET6 : FREERTOS_AF_INET;
		struct freertos_addrinfo *results = nullptr;
		auto                      ret =
		  FreeRTOS_getaddrinfo(hostname,
		                       nullptr,
		                       reinterpret_cast<freertos_addrinfo *>(&hints),
		                       &results);
		if (ret != 0)
		{
			// Try with IPv4 if the lookup failed with IPv6
			if (useIPv6)
			{
				return host_resolve(hostname, false, address);
			}
			Debug::log("DNS request returned: {}", ret);
			address->kind = NetworkAddress::AddressKindInvalid;
			address->ipv4 = 0;
			return ret;
		}

		bool isIPv6 = false;
		for (freertos_addrinfo *r = results; r != nullptr; r = r->ai_next)
		{
			Debug::log("Canonical name: {}", r->ai_canonname);
			if (r->ai_family == FREERTOS_AF_INET6)
			{
				memcpy(
				  address->ipv6, r->ai_addr->sin_address.xIP_IPv6.ucBytes, 16);
				address->kind = NetworkAddress::AddressKindIPv6;
				Debug::log("Got IPv6 address");
			}
			else
			{
				address->ipv4 = r->ai_addr->sin_address.ulIP_IPv4;
				address->kind = NetworkAddress::AddressKindIPv4;
				Debug::log(
				  "Got IPv4 address: {}.{}.{}.{}",
				  static_cast<int>(r->ai_addr->sin_address.ulIP_IPv4) & 0xff,
				  static_cast<int>(r->ai_addr->sin_address.ulIP_IPv4) >> 8 &
				    0xff,
				  static_cast<int>(r->ai_addr->sin_address.ulIP_IPv4) >> 16 &
				    0xff,
				  static_cast<int>(r->ai_addr->sin_address.ulIP_IPv4) >> 24 &
				    0xff);
			}
		}

		FreeRTOS_freeaddrinfo(results);
		return 0;
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
	  FunctionWrapper<void *(int &available)> prepareBuffer,
	  FunctionWrapper<void(void *buffer)>     freeBuffer)
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
					  // Although FreeRTOS_recv returned a
					  // positive `available` previously,
					  // we are not guaranteed that it will
					  // do so in the second call. Check
					  // the return value before returning.
					  int ret = FreeRTOS_recv(socket->socket,
					                          buffer,
					                          available,
					                          FREERTOS_MSG_DONTWAIT);
					  if (ret > 0)
					  {
						  return ret;
					  }

					  Debug::log("Second recv failed with {}.", ret);

					  freeBuffer(buffer);
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

	/**
	 * Helper to close a FreeRTOS socket with retries.
	 *
	 * Unlike the FreeRTOS API reference suggests, `FreeRTOS_closesocket`
	 * *can* fail. The return values of `FreeRTOS_closesocket` are 1
	 * (success), 0 (failure because the socket is invalid), or -1 (failure
	 * because the message could not be delivered to the IP-task).
	 *
	 * This helper re-runs `FreeRTOS_closesocket` as long as the return
	 * value is -1 and the timeout suffices.
	 */
	int close_socket_retry(Timeout *t, Socket_t socket)
	{
		int ret = 1;

		do
		{
			if (ret == -1)
			{
				Debug::log("Retrying to close the socket.");

				// This is a retry. Wake up the IP thread for
				// one tick to give it a chance to free up some
				// space in the message queue before re-running
				// `FreeRTOS_closesocket` .
				Timeout oneTick{1};
				if (flaglock_priority_inheriting_trylock(
				      &oneTick, &ipThreadLockState) == 0)
				{
					Debug::log(
					  "Acquired the IP thread lock, this should not succeed.");
				}
			}

			SystickReturn startTick = thread_systemtick_get();
			ret                     = FreeRTOS_closesocket(socket);
			SystickReturn endTick   = thread_systemtick_get();

			t->elapse(((uint64_t(endTick.hi) << 32) | endTick.lo) -
			          ((uint64_t(startTick.hi) << 32) | startTick.lo));
		} while (t->may_block() && ret == -1);

		if (ret == -1)
		{
			Debug::log("Failed to close socket.");
		}
		else if (ret == 0)
		{
			Debug::log("Failed to close socket (invalid socket).");
		}

		return ret;
	}
} // namespace

int network_host_resolve(const char     *hostname,
                         bool            useIPv6,
                         NetworkAddress *address)
{
	return with_restarting_checks(
	  [&]() { return host_resolve(hostname, useIPv6, address); },
	  -1 /* invalid if we are restarting */);
}

/**
 * Callback called by FreeRTOS+TCP when a TCP connection is created or
 * terminated.
 *
 * We use this callback to handle the case where a three-way TCP handshake
 * initiated by a peer on a listening socket fails.
 *
 * Rationale:
 * The firewall automatically opens a hole as soon as it sees a SYN sent by a
 * new peer to a server port. This hole is supposed to be closed by
 * `FreeRTOS_closesocket` when the connection is terminated. However, if the
 * three-way handshake does not succeed (e.g., the peer only sends a SYN), the
 * TCP connection will not be created and thus no socket will be created. This
 * means that `FreeRTOS_closesocket` will never be called. In that case we must
 * close the firewall hole ourselves. Fortunately, this callback is called when
 * an attempted three-way-handshake failed. We can use it to tell the firewall
 * to remove the hole.
 *
 * It is also worth noting that this will never be called if *we* close the
 * socket through `FreeRTOS_closesocket`.
 *
 * This is because FreeRTOS+TCP does not do a three-way handshake close when
 * the socket is closed through `FreeRTOS_socketclose()`. Instead, FreeRTOS+TCP
 * sends a FIN to the peer and destroys the socket immediately. Any further
 * packet from the peer is answered with a RST (as a spurious packet).  Because
 * the socket is destroyed in a state when the TCP connection has not been
 * properly closed (it is just in the "FIN sent" stage, i.e., FIN Wait-1), the
 * callback is not called.
 */
static void on_tcp_connect(Socket_t socket, BaseType_t isConnected)
{
	if (!isConnected)
	{
		/**
		 * A TCP connection was closed. Close the corresponding
		 * firewall hole.
		 *
		 * Note that this is called from the TCP/IP thread, i.e., it
		 * cannot possibly race with a free of the `socket`, even if
		 * `network_socket_close` is called concurrently.
		 */
		struct freertos_sockaddr address = {0};
		FreeRTOS_GetRemoteAddress(socket, &address);
		Debug::log("A connection was closed on port {} from remote port {}",
		           static_cast<int>(socket->usLocalPort),
		           static_cast<int>(ntohs(address.sin_port)));
		auto localPort = htons(socket->usLocalPort);
		if (socket->bits.bIsIPv6)
		{
			firewall_remove_tcpipv6_remote_endpoint(
			  address.sin_address.xIP_IPv6.ucBytes,
			  localPort,
			  address.sin_port);
		}
		else
		{
			firewall_remove_tcpipv4_remote_endpoint(
			  address.sin_address.ulIP_IPv4, localPort, address.sin_port);
		}
	}
}
F_TCP_UDP_Handler_t onTCPConnectCallback = {on_tcp_connect};

SObj network_socket_create_and_bind(Timeout       *timeout,
                                    SObj           mallocCapability,
                                    bool           isIPv6,
                                    ConnectionType type,
                                    uint16_t       localPort,
                                    bool           isListening)
{
	return with_restarting_checks(
	  [&]() -> SObj {
		  // TODO: This should have nice RAII wrappers!
		  // Add the socket lock to the linked list and make sure that the RAII
		  // wrapper removes it from there.
		  auto [socketWrapper, sealedSocket] = token_allocate<SealedSocket>(
		    timeout, mallocCapability, socket_key());
		  if (socketWrapper == nullptr)
		  {
			  Debug::log("Failed to allocate socket wrapper.");
			  return nullptr;
		  }

		  // Set the socket epoch
		  socketWrapper->socketEpoch = currentSocketEpoch.load();

		  const auto Family = isIPv6 ? FREERTOS_AF_INET6 : FREERTOS_AF_INET;
		  Socket_t   socket =
		    FreeRTOS_socket(Family,
		                    type == ConnectionTypeTCP ? FREERTOS_SOCK_STREAM
		                                              : FREERTOS_SOCK_DGRAM,
		                    type == ConnectionTypeTCP ? FREERTOS_IPPROTO_TCP
		                                              : FREERTOS_IPPROTO_UDP);
		  if (socket == nullptr)
		  {
			  Debug::log("Failed to create socket.");
			  // This cannot fail unless buggy - we know that we successfully
			  // allocated the token with this malloc capability. Same for
			  // other calls to `token_obj_destroy` in this function.
			  token_obj_destroy(mallocCapability, socket_key(), sealedSocket);
			  return nullptr;
		  }
		  socketWrapper->socket = socket;

		  // Claim the socket so that it counts towards the caller's quota.  The
		  // network stack also keeps a claim to it.  We will drop this claim on
		  // deallocation.
		  Claim c{mallocCapability, socket};
		  if (!c)
		  {
			  Debug::log("Failed to claim socket.");
			  // Note that `close_socket_retry` can fail, in which case we
			  // will leak the socket allocation. There is nothing we can do
			  // here.  Returning the half-baked sealed socket would be
			  // dangerous because the close() path isn't designed to handle
			  // it (and changing it to do so is non-trivial and likely not
			  // worth the trouble).
			  close_socket_retry(timeout, socket);
			  // Cannot fail, see above.
			  token_obj_destroy(mallocCapability, socket_key(), sealedSocket);
			  return nullptr;
		  }

		  // Acquire the lock until we complete the bind to ensure that
		  // we don't fail to acquire `sealedSocketsListLock` in the
		  // error handling of `FreeRTOS_bind`.
		  if (LockGuard g{sealedSocketsListLock, timeout})
		  {
			  // Add the socket to the sealed socket reset list.
			  socketWrapper->ring.cell_reset();
			  sealedSockets.append(&(socketWrapper->ring));

			  freertos_sockaddr localAddress;
			  memset(&localAddress, 0, sizeof(localAddress));
			  localAddress.sin_len = sizeof(localAddress);
			  // Note from the FreeRTOS API spec: 'Specifying a port number of 0
			  // or passing pxAddress as NULL will result in the socket being
			  // bound to a port number from the private range'. Here,
			  // `localPort` will be 0 if the caller wants to bind to any port.
			  localAddress.sin_port   = FreeRTOS_htons(localPort);
			  localAddress.sin_family = Family;
			  auto bindResult =
			    FreeRTOS_bind(socket, &localAddress, sizeof(localAddress));
			  if (bindResult != 0)
			  {
				  // See above comments.
				  Debug::log("Failed to bind socket.");
				  // No need to acquire the lock here since we still have it.
				  ds::linked_list::remove(&(socketWrapper->ring));
				  close_socket_retry(timeout, socket);
				  token_obj_destroy(
				    mallocCapability, socket_key(), sealedSocket);
				  return nullptr;
			  }

			  if (isListening)
			  {
				  auto listenResult =
				    FreeRTOS_listen(socket, MAX_SIMULTANEOUS_TCP_CONNECTIONS);
				  if (listenResult != 0)
				  {
					  // See above comments. Note that this
					  // failure case is not supposed to
					  // happen since we know that the
					  // socket is valid and bound.
					  Debug::log("Failed to set socket into listen mode.");
					  // No need to acquire the lock here
					  // since we still have it.
					  ds::linked_list::remove(&(socketWrapper->ring));
					  close_socket_retry(timeout, socket);
					  token_obj_destroy(
					    mallocCapability, socket_key(), sealedSocket);
					  return nullptr;
				  }

				  FreeRTOS_setsockopt(
				    socket,
				    0,
				    FREERTOS_SO_TCP_CONN_HANDLER,
				    static_cast<void *>(&onTCPConnectCallback),
				    sizeof(onTCPConnectCallback));
			  }
		  }
		  else
		  {
			  // See above comments.
			  Debug::log("Failed to add socket to the socket reset list.");
			  close_socket_retry(timeout, socket);
			  token_obj_destroy(mallocCapability, socket_key(), sealedSocket);
			  return nullptr;
		  }

		  c.release();
		  return sealedSocket;
	  },
	  static_cast<SObj>(nullptr) /* return nullptr if we are restarting */);
}

SObj network_socket_accept_tcp(Timeout        *timeout,
                               SObj            mallocCapability,
                               SObj            sealedListeningSocket,
                               NetworkAddress *address,
                               uint16_t       *port)
{
	SObj socket = nullptr;
	with_sealed_socket(
	  [&](SealedSocket *listeningSocket) {
		  if (!check_timeout_pointer(timeout))
		  {
			  return -EINVAL;
		  }

		  // Create a sealed socket wrapper for the accepted connection.
		  auto [socketWrapper, sealedSocket] = token_allocate<SealedSocket>(
		    timeout, mallocCapability, socket_key());
		  if (socketWrapper == nullptr)
		  {
			  Debug::log("Failed to allocate socket wrapper.");
			  return -EINVAL;
		  }

		  socketWrapper->socketEpoch = currentSocketEpoch.load();

		  struct freertos_sockaddr addressTmp;
		  uint32_t                 addressLength = sizeof(addressTmp);
		  auto                     rawSocket     = FreeRTOS_accept(
		                            listeningSocket->socket, &addressTmp, &addressLength);
		  if (rawSocket == nullptr)
		  {
			  Debug::log("Failed to create socket.");
			  // This cannot fail unless buggy - we know that we
			  // successfully allocated the token with this malloc
			  // capability. Same for other calls to `token_obj_destroy`
			  // in this function.
			  token_obj_destroy(mallocCapability, socket_key(), sealedSocket);
			  return -EINVAL;
		  }
		  socketWrapper->socket = rawSocket;

		  // Claim the socket so that it counts towards the caller's quota.  The
		  // network stack also keeps a claim to it.  We will drop this claim on
		  // deallocation.
		  Claim c{mallocCapability, rawSocket};
		  if (!c)
		  {
			  Debug::log("Failed to claim socket.");
			  // Note that `close_socket_retry` can fail, in which case we
			  // will leak the socket allocation. There is nothing we can do
			  // here.  Returning the half-baked sealed socket would be
			  // dangerous because the close() path isn't designed to handle
			  // it (and changing it to do so is non-trivial and likely not
			  // worth the trouble).
			  close_socket_retry(timeout, rawSocket);
			  // Cannot fail, see above.
			  token_obj_destroy(mallocCapability, socket_key(), sealedSocket);
			  return -EINVAL;
		  }

		  if (LockGuard g{sealedSocketsListLock, timeout})
		  {
			  // Add the socket to the sealed socket reset list.
			  socketWrapper->ring.cell_reset();
			  sealedSockets.append(&(socketWrapper->ring));
		  }
		  else
		  {
			  // See above comments.
			  Debug::log("Failed to add socket to the socket reset list.");
			  close_socket_retry(timeout, rawSocket);
			  token_obj_destroy(mallocCapability, socket_key(), sealedSocket);
			  return -EINVAL;
		  }

		  // Set `address`.
		  if ((heap_claim_fast(timeout, address) < 0) ||
		      (!check_pointer<PermissionSet{Permission::Store}>(address)))
		  {
			  // There is not much we can do if this happens. The
			  // caller passed an invalid `address` or freed it
			  // concurrently: we can simply ignore, they are
			  // shooting themselves in the foot by making
			  // `address` unusable. Returning nullptr at that
			  // stage would force us to close the socket, destroy
			  // the token, etc.
			  Debug::log("Invalid address pointer");
		  }
		  else
		  {
			  if (addressTmp.sin_family == FREERTOS_AF_INET6)
			  {
				  address->kind = NetworkAddress::AddressKindIPv6;
				  memcpy(
				    address->ipv6, addressTmp.sin_address.xIP_IPv6.ucBytes, 16);
			  }
			  else
			  {
				  address->kind = NetworkAddress::AddressKindIPv4;
				  address->ipv4 = addressTmp.sin_address.ulIP_IPv4;
			  }
		  }
		  // Set `port`.
		  if ((heap_claim_fast(timeout, port) < 0) ||
		      (!check_pointer<PermissionSet{Permission::Store}>(port)))
		  {
			  // Same comment as earlier for `address`.
			  Debug::log("Invalid port pointer");
		  }
		  else
		  {
			  *port = ntohs(addressTmp.sin_port);
		  }

		  c.release();
		  socket = sealedSocket;
		  return 0;
	  },
	  sealedListeningSocket);
	return socket;
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
			  case 0:                         // success
			  case -pdFREERTOS_ERRNO_EISCONN: // already connected
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
	return with_sealed_socket<true /* this is a close operation */>(
	  [=](SealedSocket *socket) {
		  // We will fail to lock if the socket is coming from
		  // a previous instance of the network stack as it set
		  // for destruction. Ignore the failure: we will not
		  // call the FreeRTOS API on it anyways.
		  LockGuard g{socket->socketLock, t};
		  if (g || (socket->socketEpoch != currentSocketEpoch.load()))
		  {
			  if (socket->socketEpoch != currentSocketEpoch.load())
			  {
				  Debug::log(
				    "Destroying a socket from a previous instance of the "
				    "network stack");
				  Debug::Assert(!g, "Acquired lock of remnant socket");
				  g.release();
			  }
			  // Since we free the socket and the token at the end after
			  // terminating the socket, ensure that the frees won't fail
			  if (heap_can_free(mallocCapability, socket->socket) != 0 ||
			      token_obj_can_destroy(
			        mallocCapability, socket_key(), sealedSocket) != 0)
			  {
				  Debug::log("Unable to free socket or token.");
				  // The main reason why this would fail is because we
				  // were called with the wrong malloc capability. We
				  // want to leave a chance to the caller to call us
				  // again with the right capability.
				  return -EINVAL;
			  }
			  bool isTCP = socket->socket->ucProtocol == FREERTOS_IPPROTO_TCP;
			  // Shut down the socket and close the firewall.
			  //
			  // Don't call `FreeRTOS_shutdown` if the socket is
			  // coming from a previous instance of the network
			  // stack (the socket is invalid anyways). Don't close
			  // the firewall either as this was already done
			  // during the reset.
			  if (socket->socketEpoch == currentSocketEpoch.load())
			  {
				  auto rawSocket = socket->socket;

				  // Do not bother with the return value:
				  // `FreeRTOS_shutdown` fails if the TCP
				  // connection is dead, which is likely to
				  // happen in practice and has no impact here.
				  FreeRTOS_shutdown(rawSocket, FREERTOS_SHUT_RDWR);

				  auto localPort = ntohs(rawSocket->usLocalPort);
				  if (rawSocket->bits.bIsIPv6)
				  {
					  if (isTCP)
					  {
						  // This only fails if the
						  // socket is not a TCP
						  // socket, which shouldn't
						  // happen here.
						  struct freertos_sockaddr address = {0};
						  FreeRTOS_GetRemoteAddress(rawSocket, &address);

						  // If the socket is in
						  // listening mode, remove the
						  // associated server port
						  // from the firewall.
						  // Otherwise close the
						  // corresponding firewall
						  // hole.
						  if (rawSocket->u.xTCP.eTCPState == eTCP_LISTEN)
						  {
							  firewall_remove_tcpipv6_server_port(localPort);
						  }
						  else
						  {
							  firewall_remove_tcpipv6_remote_endpoint(
							    address.sin_address.xIP_IPv6.ucBytes,
							    localPort,
							    address.sin_port);
						  }
					  }
					  else
					  {
						  firewall_remove_udpipv6_local_endpoint(localPort);
					  }
				  }
				  else
				  {
					  if (isTCP)
					  {
						  // This only fails if the
						  // socket is not a TCP
						  // socket, which shouldn't
						  // happen here.
						  struct freertos_sockaddr address = {0};
						  FreeRTOS_GetRemoteAddress(socket->socket, &address);

						  if (rawSocket->u.xTCP.eTCPState == eTCP_LISTEN)
						  {
							  firewall_remove_tcpipv4_server_port(localPort);
						  }
						  else
						  {
							  firewall_remove_tcpipv4_remote_endpoint(
							    address.sin_address.ulIP_IPv4,
							    localPort,
							    address.sin_port);
						  }
					  }
					  else
					  {
						  firewall_remove_udpipv4_local_endpoint(localPort);
					  }
				  }
			  }
			  int ret = 0;
			  if (socket->socketEpoch == currentSocketEpoch.load())
			  {
				  Debug::Assert(!ds::linked_list::is_singleton(&(socket->ring)),
				                "The socket should be present in the list.");
				  if (LockGuard g{sealedSocketsListLock, t})
				  {
					  ds::linked_list::remove(&(socket->ring));
				  }
				  else
				  {
					  return -ETIMEDOUT;
				  }

				  // Close the socket.  Another thread will actually
				  // clean up the memory. This returns 1 on success.
				  // Again, do not do this if the socket is from a
				  // previous instance of the network stack.
				  auto closeStatus = close_socket_retry(t, socket->socket);
				  if (closeStatus == 0)
				  {
					  // The only reason why this would fail is internal
					  // corruption (did someone already close the
					  // socket?). Nothing can be done by anyone at this
					  // stage. Don't return because we would leak
					  // everything.
					  ret = -ENOTRECOVERABLE;
				  }
				  else if (closeStatus != 1)
				  {
					  // The close couldn't be delivered to the IP
					  // task. With some luck, the socket can be
					  // freed next time we try.
					  return -ETIMEDOUT;
				  }

				  g.release();
				  socket->socketLock.upgrade_for_destruction();
			  }

			  // Drop the caller's claim on the socket.
			  if (heap_free(mallocCapability, socket->socket) != 0)
			  {
				  // This is not supposed to happen, since we did a
				  // `heap_can_free` earlier (unless we did not have
				  // enough stack, or a concurrent free happened). If
				  // it does, we may be leaking the socket.
				  Debug::log("Failed to free socket.");
				  // Don't return yet, try to at least free the token.
				  ret = -ENOTRECOVERABLE;
			  }
			  if (token_obj_destroy(
			        mallocCapability, socket_key(), sealedSocket) != 0)
			  {
				  // This is not supposed to happen, since we did a
				  // `token_obj_can_destroy` earlier (see comment
				  // above). If it does, we're leaking the token.
				  Debug::log("Failed to free token.");
				  ret = -ENOTRECOVERABLE;
			  }
			  return ret;
		  }
		  return -ETIMEDOUT;
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
            } /* with_freertos_timeout */);
          if (received > 0)
          {
              Claim c{mallocCapability, unclaimedBuffer};
              FreeRTOS_ReleaseUDPPayloadBuffer(unclaimedBuffer);
              if (!c)
              {
                  Debug::log("Failed to claim socket.");
                  return -ENOMEM;
              }

              Debug::log("Claimed {}-byte buffer", received);
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
                  if (!check_pointer<PermissionSet{Permission::Store}>(port))
                  {
                      return -EPERM;
                  }
                  *port = ntohs(remoteAddress.sin_port);
              }

              buffer = claimedBuffer;
              c.release();
              return received;
          }
          if (received < 0)
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
          return received; // We had `received` == 0.
	   } /* with_sealed_socket */,
	   socket);
	return {result, buffer};
}

int network_socket_receive_preallocated(Timeout *timeout,
                                        SObj     sealedSocket,
                                        void    *buffer,
                                        size_t   length)
{
	return network_socket_receive_internal(
	  timeout,
	  sealedSocket,
	  [&](int &available) -> void * {
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
	  },
	  [&](void *buffer) -> void { return; });
}

NetworkReceiveResult network_socket_receive(Timeout *timeout,
                                            SObj     mallocCapability,
                                            SObj     sealedSocket)
{
	uint8_t *buffer = nullptr;
	ssize_t  result = network_socket_receive_internal(
	   timeout,
	   sealedSocket,
	   [&](int &available) -> void  *{
          do
          {
              // Do the initial allocation without timeout: if the quota or the
              // heap is almost exhausted, we will block until timeout without
              // achieving anything.
              Timeout zeroTimeout{0};
              buffer = static_cast<uint8_t *>(
                heap_allocate(&zeroTimeout, mallocCapability, available));
              timeout->elapse(zeroTimeout.elapsed);
              if (!Capability{buffer}.is_valid())
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
          } while (!Capability{buffer}.is_valid());
          return buffer;
	   },
	   [&](void *buffer) -> void { heap_free(mallocCapability, buffer); });
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
		  int ret = with_freertos_timeout(
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
		  if (ret == -pdFREERTOS_ERRNO_ENOMEM)
		  {
			  return -ENOMEM;
		  }
		  if (ret == -pdFREERTOS_ERRNO_ENOSPC)
		  {
			  return -ETIMEDOUT;
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

int network_socket_kind(SObj socket, SocketKind *kind)
{
	return with_restarting_checks(
	  [&]() -> int {
		  kind->protocol  = SocketKind::Invalid;
		  kind->localPort = 0;
		  int ret         = with_sealed_socket(
		            [&](SealedSocket *socket) {
                if (socket->socket->ucProtocol == FREERTOS_IPPROTO_TCP)
                {
                    kind->protocol = socket->socket->bits.bIsIPv6
				                               ? SocketKind::TCPIPv6
				                               : SocketKind::TCPIPv4;
                }
                else
                {
                    kind->protocol = socket->socket->bits.bIsIPv6
				                               ? SocketKind::UDPIPv6
				                               : SocketKind::UDPIPv4;
                }
                kind->localPort = listGET_LIST_ITEM_VALUE(
			              (&((socket->socket)->xBoundSocketListItem)));
                return 0;
		            },
		            socket);
		  return ret;
	  },
	  -1 /* invalid if we are restarting */);
}
