// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

// Uncomment for useful debugging message on CHERI faults.
//#include <fail-simulator-on-error.h>

#include <FreeRTOS-Compat/FreeRTOS.h>
#include <NetAPI.h>
#include <algorithm>
#include <cheri.hh>
#include <core_sntp_client.h>
#include <core_sntp_config.h>
#include <core_sntp_serializer.h>
#include <debug.hh>
#include <locks.hh>
#include <sntp.h>
#include <stdlib.h>
#include <tick_macros.h>

using CHERI::Capability;

using Debug = ConditionalDebug<false, "NTP Client">;

#include <platform-entropy.hh>

/**
 * Capability for pool.ntp.org.
 *
 * Note: In real use, this should be an NTP server controlled by the user.
 */
DECLARE_AND_DEFINE_CONNECTION_CAPABILITY(NtpPool,
                                         "pool.ntp.org",
                                         123,
                                         ConnectionType::ConnectionTypeUDP);

/**
 * Out malloc capability.
 *
 * TODO: Figure out how big this actually needs to be.
 */
DEFINE_ALLOCATOR_CAPABILITY(__default_malloc_capability, 16 * 1024)

struct NetworkContext
{
	Timeout *timeout;
	SObj     socket;
};

namespace
{

	/// Returns a weak pseudo-random number.
	uint64_t rand()
	{
		EntropySource rng;
		return rng();
	}

	/**
	 * We do the DNS lookup on socket creation because the coreSNTP library
	 * does not provide a context to the callback for the DNS lookup.  The
	 * result is stored here so that it can be returned in `ntp_dns_resolve`.
	 */
	uint32_t nextAddress;

	/**
	 * Create a socket and authorise it to connect to the NTP pool.
	 */
	int socket_create(NetworkContext *context)
	{
		Debug::log("Creating socket with malloc capability: {}",
		           MALLOC_CAPABILITY);
		SObj socket =
		  network_socket_udp(context->timeout, MALLOC_CAPABILITY, false);
		Debug::log("Created socket {}", socket);
		if (!Capability{socket}.is_valid())
		{
			return -ETIMEDOUT;
		}
		auto address = network_socket_udp_authorise_host(
		  context->timeout, socket, STATIC_SEALED_VALUE(NtpPool));
		if (address.kind == NetworkAddress::AddressKindInvalid)
		{
			Timeout unlimited{UnlimitedTimeout};
			network_socket_close(&unlimited, MALLOC_CAPABILITY, socket);
			context->timeout->elapse(unlimited.elapsed);
			return -ENOTCONN;
		}
		Debug::log("Authorised UDP socket to connect to ntp.pool.org");
		nextAddress     = address.ipv4;
		context->socket = socket;
		return 0;
	}

	/**
	 * DNS resolutor callback.  Returns the value looked up during socket
	 * creation.
	 */
	bool ntp_dns_resolve(const SntpServerInfo_t *, uint32_t *outAddress)
	{
		*outAddress = nextAddress;
		return nextAddress != 0;
	}

	/**
	 * The cycle count at the start of the NTP request.
	 */
	uint64_t ntpRequestStart;

	/**
	 * Callback to send a UDP packet.
	 */
	int32_t ntp_udp_send(NetworkContext_t *pNetworkContext,
	                     uint32_t          serverAddr,
	                     uint16_t          serverPort,
	                     const void       *pBuffer,
	                     uint16_t          bytesToSend)
	{
		NetworkAddress address = {
		  .ipv4 = serverAddr,
		  .kind = NetworkAddress::AddressKindIPv4,
		};
		ntpRequestStart = rdcycle64();
		int ret         = network_socket_send_to(pNetworkContext->timeout,
		                                         pNetworkContext->socket,
		                                         &address,
		                                         serverPort,
		                                         pBuffer,
		                                         bytesToSend);
		if (ret < 0)
		{
			return 0;
		}
		return ret;
	}

	/**
	 * Callback to receive a UDP packet.  This should filter on sender address,
	 * but we rely on the firewall dropping all packets other than the ones
	 * from our authorised NTP server.
	 */
	int32_t ntp_udp_receive(NetworkContext_t *pNetworkContext,
	                        uint32_t,
	                        uint16_t,
	                        void    *pBuffer,
	                        uint16_t bytesToRecv)
	{
		NetworkAddress address;
		uint16_t       port;
		auto result = network_socket_receive_from(pNetworkContext->timeout,
		                                          MALLOC_CAPABILITY,
		                                          pNetworkContext->socket,
		                                          &address,
		                                          &port);
		if (result.bytesReceived > 0)
		{
			Debug::log("Received {} bytes, copying {} bytes from {} into "
			           "{}-byte buffer {}",
			           result.bytesReceived,
			           std::min<size_t>(result.bytesReceived, bytesToRecv),
			           result.buffer,
			           bytesToRecv,
			           pBuffer);
			// This copy is annoying but the API doesn't let us do the zero-copy
			// thing.
			size_t bytesReceived =
			  std::min<size_t>(result.bytesReceived, bytesToRecv);
			memcpy(pBuffer, result.buffer, bytesReceived);
			free(result.buffer);
			return bytesReceived;
		}
		return 0;
	}

	/**
	 * Compute the number of seconds since the epoch for the current year.  NTP
	 * requires our first guess at the time to be within a few decades of the
	 * actual time, so as long as the code is recompiled every couple of decades
	 * this should be fine.
	 */
	consteval uint64_t epoch_year_approximate(std::string_view date = __DATE__)
	{
		uint64_t    year      = 0;
		const char *yearStart = date.data() + date.length() - 4;
		// Compute the year
		for (int i = 0; i < 4; i++)
		{
			year = year * 10 + (yearStart[i] - '0');
		}
		// Subtract the start of the NTP epoch.
		year -= 1900;
		// Compute the number of seconds since the epoch
		// This ignores leap years and leap seconds, because we only need to be
		// within 68 years.
		year *= 365 * 24 * 60 * 60;
		return year;
	}

	// Sanity check the epoch year calculation.
	static_assert(epoch_year_approximate(" 2024") ==
	                124ULL * 365 * 24 * 60 * 60,
	              "Year is wrong");

	/**
	 * The current time in NTP format.
	 */
	SntpTimestamp_t currentTime = {epoch_year_approximate(), 0};

	/// NTP era, used to handle 32-bit overflow in NTP timestamps.
	uint32_t ntpEra = epoch_year_approximate() >> 32;

	/**
	 * Convert an NTP timestamp to a POSIX timeval.
	 */
	constexpr struct timeval ntp_date_to_timeval(SntpTimestamp_t currentNTPTime,
	                                             uint32_t        era)
	{
		timeval tv;
		// Seconds promoted to 64 bits, still relative to the NTP epoch.
		int64_t seconds = currentNTPTime.seconds;
		// Seconds now relative to UNIX epoch
		seconds -= SNTP_TIME_AT_UNIX_EPOCH_SECS;
		// NTP dates roll over every 136 years, so we need to add the era
		seconds += uint64_t(era) << 32;
		tv.tv_sec = seconds;
		tv.tv_usec =
		  currentNTPTime.fractions / SNTP_FRACTION_VALUE_PER_MICROSECOND;
		return tv;
	}

	/**
	 * The current time in UNIX format.  Initialised to match the initial NTP
	 * time.
	 */
	SynchronisedTime currentUNIXTime = {
	  0,
	  ntp_date_to_timeval({epoch_year_approximate(), 0},
	                      (epoch_year_approximate() >> 32)),
	  0};

	/**
	 * Update the current UNIX time to reflect the last cached NTP time.
	 */
	void unix_time_update(uint64_t cycles)
	{
		Debug::log("Updating UNIX time");
		Debug::log(
		  "Current time: {}.{}", currentTime.seconds, currentTime.fractions);
		currentUNIXTime.updatingEpoch++;
		currentUNIXTime.time   = ntp_date_to_timeval(currentTime, ntpEra);
		currentUNIXTime.cycles = cycles;
		currentUNIXTime.updatingEpoch++;
		Debug::log("Updated UNIX time");
		Debug::log("Current UNIX time: {}.{}",
		           (uint64_t)currentUNIXTime.time.tv_sec,
		           currentUNIXTime.time.tv_usec);
	}

	/**
	 * Callback to get the current NTP time.
	 */
	void ntp_time_get(SntpTimestamp_t *pCurrentTime)
	{
		pCurrentTime->seconds   = currentTime.seconds;
		pCurrentTime->fractions = currentTime.fractions;
	}

	/**
	 * Translate a coreSNTP error code to an errno.
	 */
	int ntp_error_to_errno(SntpStatus_t response)
	{
		switch (response)
		{
			case SntpSuccess:
				return 0;
			case SntpErrorBadParameter:
			case SntpZeroPollInterval:
			case SntpErrorTimeNotSupported:
			case SntpErrorContextNotInitialized:

				return -EINVAL;
			case SntpRejectedResponse:
			case SntpRejectedResponseChangeServer:
			case SntpRejectedResponseRetryWithBackoff:
			case SntpRejectedResponseOtherCode:
				return -ECONNREFUSED;
			case SntpInvalidResponse:
			case SntpErrorDnsFailure:
			case SntpErrorNetworkFailure:
			case SntpServerNotAuthenticated:
			case SntpErrorAuthFailure:
				return -ECONNABORTED;
			case SntpErrorBufferTooSmall:
				return -ENOMEM;
			case SntpErrorSendTimeout:
			case SntpErrorResponseTimeout:
			case SntpNoResponseReceived:
				return -ETIMEDOUT;
		}
		return -EINVAL;
	}

	/**
	 * Callback to set the current time after an NTP response.
	 */
	void ntp_time_set(const SntpServerInfo_t *pTimeServer,
	                  const SntpTimestamp_t  *pServerTime,
	                  int64_t                 clockOffsetMs,
	                  SntpLeapSecondInfo_t    leapSecondInfo)
	{
		auto ntpRequestEnd = rdcycle64();
		Debug::log("NTP request took {} cycles",
		           ntpRequestEnd - ntpRequestStart);
		Debug::log(
		  "Old time: {}.{}", currentTime.seconds, currentTime.fractions);
		Debug::log(
		  "Setting time: {}.{}", pServerTime->seconds, pServerTime->fractions);
		Debug::log("clockOffsetMs: {}", uint64_t(clockOffsetMs));
		// FIXME: This should update the era but I need to think more about the
		// heuristic to use.  We may see some jitter (including time moving
		// backwards) around the rollover point, so we need to handle the era
		// going down by one as well as up.

		currentTime.seconds = 0;
		// As a very rough approximation, assume that the server time is
		// accurate at the midway point of the request.
		uint64_t cycleTime =
		  ntpRequestStart + ((ntpRequestEnd - ntpRequestStart) / 2);
		currentTime = *pServerTime;
		unix_time_update(cycleTime);
	}

	/**
	 * Update the current cached time from NTP.
	 *
	 * FIXME: There should be a hook for integrators to use the authentication
	 * API and provide their own time server.
	 */
	int ntp_time_update(Timeout *timeout)
	{
		static FlagLockPriorityInherited lock;
		NetworkContext                   udpContext{timeout, nullptr};
		{
			if (LockGuard guard{lock, timeout})
			{
				// FIXME: Timeout on allocation
				std::unique_ptr<uint8_t> buffer{
				  new uint8_t[SNTP_PACKET_BASE_SIZE]};

				if (int ret = socket_create(&udpContext); ret != 0)
				{
					return ret;
				}
				Debug::log("Created NTP socket {}", udpContext.socket);

				/* Setup list of time servers. */
				SntpServerInfo_t timeServers[] = {
				  {.pServerName   = "pool.ntp.org",
				   .serverNameLen = strlen("pool.ntp.org"),
				   .port          = 123}};

				/* Set the UDP transport interface object. */
				UdpTransportInterface_t udpTransportIntf;

				udpTransportIntf.pUserContext = &udpContext;
				udpTransportIntf.sendTo       = ntp_udp_send;
				udpTransportIntf.recvFrom     = ntp_udp_receive;

				/* Context variable. */
				SntpContext_t context;

				/* Initialize context. */
				SntpStatus_t status =
				  Sntp_Init(&context,
				            timeServers,
				            sizeof(timeServers) / sizeof(SntpServerInfo_t),
				            2000 /* timeout in MS */,
				            buffer.get(),
				            SNTP_PACKET_BASE_SIZE,
				            ntp_dns_resolve,
				            ntp_time_get,
				            ntp_time_set,
				            &udpTransportIntf,
				            NULL);

				if (status != SntpSuccess)
				{
					Debug::log("Failed to initialize SNTP client: {}", status);
					Timeout t{UnlimitedTimeout};
					network_socket_close(
					  &t, MALLOC_CAPABILITY, udpContext.socket);
					timeout->elapse(t.elapsed);
					return ntp_error_to_errno(status);
				}

				/* Loop of SNTP client for period time synchronization. */
				/* @[code_example_sntp_send_receive] */
				status = Sntp_SendTimeRequest(&context, rand(), 1000);
				if (status != SntpSuccess)
				{
					Debug::log("Failed to send SNTP request: {}", status);
					Timeout t{UnlimitedTimeout};
					network_socket_close(
					  &t, MALLOC_CAPABILITY, udpContext.socket);
					timeout->elapse(t.elapsed);
					return ntp_error_to_errno(status);
				}

				SntpStatus_t lastStatus = SntpSuccess;
				do
				{
					status = Sntp_ReceiveTimeResponse(&context, 0);
					if (status != lastStatus)
					{
						Debug::log("SNTP receive status: {}", status);
						lastStatus = status;
					}
					if ((status == SntpNoResponseReceived) &&
					    timeout->may_block())
					{
						Timeout t{MS_TO_TICKS(100)};
						thread_sleep(&t);
						timeout->elapse(t.elapsed);
					}
				} while (status == SntpNoResponseReceived);
				Debug::log("Received new time fron NTP!");
			}
			else
			{
				return -ETIMEDOUT;
			}
		}
		Timeout t{UnlimitedTimeout};
		network_socket_close(&t, MALLOC_CAPABILITY, udpContext.socket);
		timeout->elapse(t.elapsed);
		Debug::log("Closed NTP socket {}", udpContext.socket);
		return 0;
	}

} // namespace

int sntp_update(Timeout *timeout)
{
	if (!check_timeout_pointer(timeout))
	{
		Debug::log("Invalid timeout pointer: {}", timeout);
		return -EINVAL;
	}
	return ntp_time_update(timeout);
}

struct SynchronisedTime *sntp_time_get()
{
	Capability<struct SynchronisedTime> result{&currentUNIXTime};
	// Strip everything except load and global permission.
	result.permissions() &=
	  CHERI::PermissionSet{CHERI::Permission::Load, CHERI::Permission::Global};
	Debug::log("Returning synchronised time {}", result);
	return result;
}
