// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <NetAPI.h>
#include <cheri.hh>
#include <core_mqtt.h>
#include <debug.hh>
#include <locks.hh>
#include <mqtt.h>
#include <platform-entropy.hh>
#include <stdlib.h>
#include <string_view>
#include <transport_interface.h>

using CHERI::Capability;

constexpr bool DebugMQTT =
#ifdef DEBUG_MQTT
  DEBUG_MQTT
#else
  false
#endif
  ;

using Debug = ConditionalDebug<DebugMQTT, "MQTT Client">;

struct NetworkContext
{
	TLSConnection tlsHandle;

	/**
	 * Pointer to the caller-supplied PUBLISH callback. This callback will
	 * be called on all PUBLISH notifications from the broker.
	 */
	MQTTPublishCallback publishCallback;

	/**
	 * Pointer to the caller-supplied ACK callback. This callback will be
	 * called on all ACKs from the broker (SUBACK, PUBACK, etc.).  Note
	 * that CONNACK does not trigger this callback since it is consumed by
	 * `MQTT_Init`.
	 */
	MQTTAckCallback ackCallback;

	/**
	 * Flag set when the connection is terminated.
	 */
	bool isDisconnected;
};

/**
 * The object for a sealed CHERIoT MQTT connection.
 */
struct CHERIoTMqttContext
{
	// The underlying TLS stream.
	TLSConnection tlsHandle;

	/**
	 * MQTT internal buffers. We must keep a link to them here for
	 * freeing.
	 */
	MQTTContext_t        coreMQTTContext;
	TransportInterface_t transportInterface;
	MQTTFixedBuffer_t    networkBuffer;
	NetworkContext_t     networkContext;

	/**
	 * Lock on which the whole public API synchronizes.  This is a
	 * recursive mutex so that you can publish during a callback.
	 * Arbitrary recursion is discouraged by coreMQTT, but at least this
	 * minimal case works.
	 *
	 * See: https://github.com/FreeRTOS/coreMQTT/issues/278
	 */
	RecursiveMutex lock;

	/**
	 * Constructor of the CHERIoT MQTT context object. We keep
	 * track of all allocated objects to free them later on.
	 */
	CHERIoTMqttContext(TLSConnection tlsHandle, AllocatorCapability allocator)
	  : tlsHandle{tlsHandle}
	{
	}

	/**
	 * Destructor of the CHERIoT MQTT context object. This takes
	 * care of closing the TLS link, and de-allocating all objects.
	 */
	~CHERIoTMqttContext()
	{
		Timeout t{UnlimitedTimeout};
		tls_connection_close(&t, tlsHandle);
	}

	/**
	 * Following this we allocate variable length data:
	 * - incoming publishes (array of MQTTPubAckInfo_t)
	 * - outgoing publishes (array of MQTTPubAckInfo_t)
	 * - the network buffer (array of uint8_t)
	 */
	alignas(MQTTPubAckInfo_t) uint8_t variableLengthData;
};

namespace
{

	/**
	 * Helper to return the unsealing key for CHERIoT MQTT objects.
	 */
	__always_inline SKey mqtt_key()

	{
		return STATIC_SEALING_TYPE(MQTTHandle);
	}

	/**
	 * Returns a weak pseudo-random number.
	 */
	uint64_t rand()
	{
		static EntropySource rng;
		return rng();
	}

	/**
	 * Helper to run a callback, accounting for its runtime in the timeout
	 * object.
	 */
	auto with_elapse_timeout(Timeout *t, auto callback)
	{
		SystickReturn timestampBefore = thread_systemtick_get();
		auto          ret             = callback();
		SystickReturn timestampAfter  = thread_systemtick_get();
		// Timeouts should not overflow a 32 bit value
		t->elapse(timestampAfter.lo - timestampBefore.lo);
		return ret;
	}

	/**
	 * Helper to retry an MQTT operation as long as it returns
	 * `MQTTSendFailed` and there is time left. This is useful to reduce
	 * code duplication, as `MQTT_Publish`, `MQTT_Subscribe`, and
	 * `MQTT_Unsubscribe` all require the same error handling logic.
	 */
	int with_sendfailed_retry(Timeout            *t,
	                          const char         *mqttOpName,
	                          CHERIoTMqttContext *connection,
	                          auto                callback)
	{
		MQTTStatus_t status;
		do
		{
			status = with_elapse_timeout(t, callback);

			if (status != MQTTSuccess)
			{
				if (status == MQTTNoMemory)
				{
					return -ENOMEM;
				}
				if (status == MQTTSendFailed)
				{
					// If the TLS link is still live, try
					// again until we are out of time.
					if (connection->networkContext.isDisconnected)
					{
						return -ECONNABORTED;
					}
				}
				else if (status == MQTTBadParameter)
				{
					Debug::log(
					  "{} gave -EINVAL, this may indicate a bug in this code.",
					  mqttOpName);
					return -EINVAL;
				}
				else
				{
					Debug::log("Unknown error returned by {}.", mqttOpName);
					return -EAGAIN;
				}
			}
		} while (t->remaining > 0 && status != MQTTSuccess);

		if (status != MQTTSuccess)
		{
			return -ETIMEDOUT;
		}

		return 0;
	}

	/**
	 * Helper to unseal the CHERIoT MQTT context, acquire the lock, and
	 * execute a given callback with the unsealed context.
	 *
	 * If the parameter `destructMode` is set to `true`, this will acquire
	 * the lock in destruct mode, and free the sealed CHERIoT MQTT handle.
	 */
	ssize_t with_sealed_mqtt_context(Timeout       *timeout,
	                                 MQTTConnection sealed,
	                                 auto           callback,
	                                 bool           destructMode = false)
	{
		Sealed<CHERIoTMqttContext> sealedContext{sealed};
		auto *unsealed = token_unseal(mqtt_key(), sealedContext);
		if (unsealed == nullptr)
		{
			Debug::log("Failed to unseal MQTT context {}", sealed);
			return -EINVAL;
		}

		if (destructMode)
		{
			// If destruction mode was passed, upgrade the lock for
			// destruction and destroy the sealed object after calling the
			// callback.
			if (!unsealed->lock.try_lock(timeout))
			{
				Debug::log(
				  "Failed to acquire lock on MQTT context during close");
				return -ETIMEDOUT;
			}
			unsealed->lock.upgrade_for_destruction();
			return callback(unsealed);
		}
		if (LockGuard g{unsealed->lock, timeout})
		{
			return callback(unsealed);
		}
		Debug::log("Failed to acquire lock on MQTT context");
		return -ETIMEDOUT;
	}

	/**
	 * Note from the MQTT 3.1.1 spec:
	 * The Server MUST allow ClientIds which are between 1 and 23 UTF-8 encoded
	 * bytes in length, and that contain only the characters
	 * "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	 *
	 * Note from us: UTF-8 encoding of 0-9, a-z, A-Z, is 1 Byte per
	 * character.
	 */
	constexpr const char ClientIdCharacters[] =
	  "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	constexpr const int MQTTMaximumClientIDSize = 23;

	/**
	 * Helper to check if a client ID is valid according to the MQTT
	 * specification.
	 */
	bool is_valid_client_id(std::string_view id)
	{
		if (id.size() > MQTTMaximumClientIDSize || id.size() == 0)
		{
			return false;
		}

		for (char c : id)
		{
			switch (c)
			{
				default:
					return false;
				case '0' ... '9':
				case 'a' ... 'z':
				case 'A' ... 'Z':
					continue;
			}
		}

		return true;
	}

	/**
	 * Helper to check if a buffer contains a \0 character.
	 */
	bool has_null_character(const char *buffer, size_t length)
	{
		// TODO use `memchr` (or a string view and `find`) when
		// available
		for (size_t i = 0; i < length; i++)
		{
			if (buffer[i] == '\0')
			{
				return true;
			}
		}
		return false;
	}

	/**
	 * Callback provided to coreMQTT.
	 *
	 * Provides transport interface for receiving data on the network.
	 *
	 * Returns the number of bytes received or a negative value to indicate
	 * error. (as specified in the coreMQTT documentation)
	 */
	int32_t transport_recv(NetworkContext_t *networkContext,
	                       void             *recvBuffer,
	                       size_t            bytesToRecv)
	{
		auto sealed = networkContext->tlsHandle;

		/**
		 * Note from the coreMQTT documentation: It is RECOMMENDED that the
		 * transport receive implementation does NOT block when requested to
		 * read a single byte. A single byte read request can be made by the
		 * caller to check whether there is a new frame available on the
		 * network for reading. However, the receive implementation MAY
		 * block for a timeout period when it is requested to read more than
		 * 1 byte. This is because once the caller is aware that a new frame
		 * is available to read on the network, then the likelihood of
		 * reading more than one byte over the network becomes high.
		 */
		// TODO Determine a good value for this timeout.
		Timeout t{MS_TO_TICKS(1000)};
		if (bytesToRecv == 1)
		{
			t = {0};
		}

		int32_t received = tls_connection_receive_preallocated(
		  &t, sealed, recvBuffer, bytesToRecv);

		Debug::log("Received {} bytes from the network", received);

		/**
		 * Note from the coreMQTT documentation on the return value: If no
		 * data is available on the network to read and no error has
		 * occurred, zero MUST be the return value. A zero return value
		 * SHOULD represent that the read operation can be retried by
		 * calling the API function. Zero MUST NOT be returned if a network
		 * disconnection has occurred.
		 */
		if (received == -ETIMEDOUT)
		{
			// In the case of timeout, this read operation can be
			// retried.
			received = 0;
		}
		else if (received == -ENOTCONN)
		{
			// The TCP/TLS link is dead
			networkContext->isDisconnected = true;
		}

		return received;
	}

	/**
	 * Callback provided to coreMQTT.
	 *
	 * Provides transport interface for sending data over the network.
	 *
	 * Returns the number of bytes sent or a negative value to indicate
	 * error. (as specified in the coreMQTT documentation)
	 */
	int32_t transport_send(NetworkContext_t *networkContext,
	                       const void       *sendBuffer,
	                       size_t            bytesToSend)
	{
		auto sealed = networkContext->tlsHandle;
		int  flags  = 0;

		// TODO Determine a good value for this timeout.
		Timeout t{MS_TO_TICKS(1000)};

		int32_t sent = tls_connection_send(
		  &t, sealed, const_cast<void *>(sendBuffer), bytesToSend, flags);

		if (sent > 0 && sent != bytesToSend)
		{
			Debug::log("Partial send: {} < {}", sent, bytesToSend);
		}

		/**
		 * Note from the coreMQTT documentation on the return value: If
		 * no data is transmitted over the network due to a full TX
		 * buffer and no network error has occurred, this MUST return
		 * zero as the return value. A zero return value SHOULD
		 * represent that the send operation can be retried by calling
		 * the API function. Zero MUST NOT be returned if a network
		 * disconnection has occurred.
		 */
		if (sent == -ETIMEDOUT)
		{
			// In the case of timeout, this send operation can be
			// retried.
			sent = 0;
		}
		else if (sent == -ENOTCONN)
		{
			// The TCP/TLS link is dead
			networkContext->isDisconnected = true;
		}

		return sent;
	}

	/**
	 * Callback provided to coreMQTT.
	 *
	 * Returns the time elapsed in milliseconds since an unspecified epoch.
	 *
	 * Note from the coreMQTT documentation: The timer should be a
	 * monotonic timer. It just needs to provide an incrementing count of
	 * milliseconds elapsed since a given epoch.
	 */
	uint32_t get_current_time()
	{
		// The return value is only a 32-bit integer, so we will
		// overflow after 4,294,967,295 ms (which should be about 7
		// weeks). The overflow is not a problem though, as wraparound
		// is defined and coreMQTT only uses this for additions and
		// substractions, not ordered comparisons. See:
		// https://github.com/FreeRTOS/coreMQTT/issues/277
		uint64_t currentCycle = rdcycle64();

		// Convert to milliseconds
		constexpr uint64_t MilliSecondsPerSecond = 1000;
		constexpr uint64_t CyclesPerMilliSecond =
		  CPU_TIMER_HZ / MilliSecondsPerSecond;
		static_assert(CyclesPerMilliSecond > 0,
		              "The CPU frequency is too low for the coreMQTT time "
		              "function, which provides time in milliseconds.");
		uint64_t currentTime = currentCycle / CyclesPerMilliSecond;

		// Truncate into 32 bit
		return currentTime & 0xFFFFFFFF;
	}

	/**
	 * Callback provided to coreMQTT.
	 *
	 * Note from the coreMQTT documentation: This callback will be called
	 * on all incoming publishes and incoming acks if deserialized with a
	 * result of `MQTTSuccess` or `MQTTServerRefused`. The latter can be
	 * obtained when deserializing a SUBACK, indicating a broker's
	 * rejection of a subscribe.
	 */
	void event_callback(MQTTContext_t          *coreMQTTContext,
	                    MQTTPacketInfo_t       *packetInfo,
	                    MQTTDeserializedInfo_t *deserializedInfo)
	{
		NetworkContext_t *networkContext =
		  coreMQTTContext->transportInterface.pNetworkContext;
		auto publishCallback = networkContext->publishCallback;
		auto ackCallback     = networkContext->ackCallback;
		auto publishInfo     = deserializedInfo->pPublishInfo;

		// The packet type field corresponds to the MQTT Control Packet
		// fixed header. In the MQTT Control Packet fixed header, only
		// the 4 most significant bits contain the packet type (hence
		// the & 0xF0U). The 4 least significant bits contain flags
		// specific to each packet type.
		uint8_t packetType = packetInfo->type & 0xF0U;

		Debug::log("User callback triggered for packet type {}.", packetType);

		if (packetType == MQTT_PACKET_TYPE_PUBLISH && publishCallback)
		{
			// This should never fail - if the packet is of type
			// PUBLISH, the topic and payload should always be set.
			Debug::Assert(publishInfo->pTopicName && publishInfo->pPayload,
			              "The packet is of type PUBLISH, but topic or payload "
			              "are not set.");

			// The payload and topic are only valid within the
			// context of the callback: make them read-only,
			// non-capturable, and limits to the length of the
			// topic and payload.
			Capability topic{publishInfo->pTopicName};
			Capability payload{publishInfo->pPayload};
			topic.permissions() &= CHERI::Permission::Load;
			topic.bounds() = publishInfo->topicNameLength;
			payload.permissions() &= CHERI::Permission::Load;
			payload.bounds() = publishInfo->payloadLength;

			publishCallback(topic,
			                publishInfo->topicNameLength,
			                payload,
			                publishInfo->payloadLength);
		}
		else if (ackCallback)
		{
			bool isReject = false;
			if (deserializedInfo->deserializationResult != MQTTSuccess)
			{
				// This should only ever happen for a SUBACK.
				Debug::Assert(packetType == MQTT_PACKET_TYPE_SUBACK,
				              "The packet deserialization status is "
				              "MQTTServerRefused but "
				              "the packet is not of type SUBACK (type {}).",
				              packetType);

				isReject = true;
			}

			ackCallback(deserializedInfo->packetIdentifier, isReject);
		}
	}
} // namespace

// Public CHERIoT MQTT API

MQTTConnection mqtt_connect(Timeout                    *t,
                            AllocatorCapability         allocator,
                            ConnectionCapability        hostCapability,
                            MQTTPublishCallback         publishCallback,
                            MQTTAckCallback             ackCallback,
                            const br_x509_trust_anchor *trustAnchors,
                            size_t                      trustAnchorsCount,
                            size_t                      networkBufferSize,
                            size_t                      incomingPublishCount,
                            size_t                      outgoingPublishCount,
                            const char                 *clientID,
                            size_t                      clientIDLength,
                            bool                        newSession)
{
	// Note: do not check trustAnchors because we don't use technically use
	// it. We only pass it on to the TLS compartment which we assume will
	// check the pointer.
	//
	// Similarly, no need to check the two callbacks, because the trusted
	// switcher will do that for us. The only thing callers will achieve by
	// passing invalid callbacks is not getting ACKs or PUBLISHEs.

	if (!check_timeout_pointer(t))
	{
		return nullptr;
	}

	if (!CHERI::check_pointer(clientID, clientIDLength))
	{
		return nullptr;
	}

	if constexpr (DebugMQTT)
	{
		if (!is_valid_client_id({clientID, clientIDLength}))
		{
			Debug::log("Passed invalid client ID.");
			return nullptr;
		}
	}

	// Allocate MQTT internal buffers as part of the sealed allocation.
	// Note: no explicit zero-ing needed here (unlike suggested by
	// coreMQTT), we can assume that the allocator zeroes out for us.
	size_t handleSize =
	  sizeof(CHERIoTMqttContext) -
	  sizeof(CHERIoTMqttContext::variableLengthData) + networkBufferSize +
	  sizeof(MQTTPubAckInfo_t) * (incomingPublishCount + outgoingPublishCount);

	// Create a sealed MQTT handle.
	void *unsealedMQTTHandle;
	auto  sealedMQTTHandle = token_sealed_unsealed_alloc(
      t, allocator, mqtt_key(), handleSize, &unsealedMQTTHandle);
	if (sealedMQTTHandle == nullptr)
	{
		Debug::log("Failed to allocate CHERIoT MQTT context.");
		return nullptr;
	}

	Debug::log("Created CHERIoT MQTT context sealed with {}.", mqtt_key());

	// Set up a TLS stream with the broker.
	auto tlsHandle = tls_connection_create(
	  t, allocator, hostCapability, trustAnchors, trustAnchorsCount);
	if (!Capability{tlsHandle}.is_valid())
	{
		Debug::log("Failed to open TLS stream.");

		// Manually destroy the handle, as we have not yet wrapped it
		// into a smart pointer.
		token_obj_destroy(allocator, mqtt_key(), sealedMQTTHandle);

		return nullptr;
	}

	Debug::log("Created TLS stream.");

	// Initialize the sealed MQTT handle.
	CHERIoTMqttContext *context =
	  new (unsealedMQTTHandle) CHERIoTMqttContext{tlsHandle, allocator};

	// We allocated variable-size data structures at the end of the CHERIoT
	// MQTT context. Get pointers to them.
	MQTTPubAckInfo_t *incomingPublishes =
	  reinterpret_cast<MQTTPubAckInfo_t *>(&context->variableLengthData);
	MQTTPubAckInfo_t *outgoingPublishes =
	  incomingPublishes + incomingPublishCount;
	uint8_t *networkBuffer = reinterpret_cast<uint8_t *>(outgoingPublishes) +
	                         sizeof(MQTTPubAckInfo_t) * outgoingPublishCount;

	// Initialize context nested structures.
	context->networkContext.tlsHandle       = tlsHandle;
	context->networkContext.publishCallback = publishCallback;
	context->networkContext.ackCallback     = ackCallback;
	context->networkBuffer.pBuffer          = networkBuffer;
	context->networkBuffer.size             = networkBufferSize;
	context->transportInterface.recv        = transport_recv;
	context->transportInterface.send        = transport_send;
	// TODO we do not support writev yet, which is optional.
	context->transportInterface.writev          = NULL;
	context->transportInterface.pNetworkContext = &context->networkContext;

	auto cleanup = [&](void *) {
		// `token_obj_destroy` will free the `CHERIoTMqttContext`
		// object through `heap_free`, but not call its destructor. We
		// must do that manually.
		context->~CHERIoTMqttContext();
		token_obj_destroy(allocator,
		                  mqtt_key(),
		                  static_cast<CHERI_SEALED(void *)>(sealedMQTTHandle));
	};
	std::unique_ptr<void, decltype(cleanup)> sealedContext{sealedMQTTHandle,
	                                                       cleanup};

	Debug::log("Initializing coreMQTT.");
	MQTTStatus_t ret = MQTT_Init(&context->coreMQTTContext,
	                             &context->transportInterface,
	                             get_current_time,
	                             event_callback,
	                             &context->networkBuffer);

	if (ret != MQTTSuccess)
	{
		Debug::log("Failed to initialize MQTT, error {}.", ret);

		// Note: the sealed context `sealedContext` cleans up after
		// itself, closing the TLS link in the process, no need to do
		// so explicitly.
		return nullptr;
	}

	Debug::log("Initializing coreMQTT QoS.");
	// Note from the coreMQTT documentation: This function must be called
	// on an `MQTTContext_t` after `MQTT_Init` and before any other
	// function to initialize an MQTT context for QoS > 0.
	//
	// We *could* take a qos argument to this function and spare the call
	// to `MQTT_InitStatefulQoS` when passed 0, but this would make it
	// possible for users to mismatch this function's qos argument and that
	// of subsequent API calls. It's safer to call it in any case.
	ret = MQTT_InitStatefulQoS(&context->coreMQTTContext,
	                           outgoingPublishes,
	                           outgoingPublishCount,
	                           incomingPublishes,
	                           incomingPublishCount);

	if (ret != MQTTSuccess)
	{
		Debug::log("Failed to initialize MQTT QoS, error {}.", ret);
		return nullptr;
	}

	// Prepare the low-level MQTT API connect call.
	MQTTConnectInfo_t connectInfo = {0};

	connectInfo.cleanSession           = newSession;
	connectInfo.pClientIdentifier      = clientID;
	connectInfo.clientIdentifierLength = clientIDLength;

	Debug::log("Using client ID {}",
	           std::string_view(clientID, clientIDLength));

	// Note: there are a number of optional fields in connectInfo to
	// specify a keepalive (`connectInfo.keepAliveSeconds`), a username
	// (`pUserName`, `userNameLength`), a password (`pPassword`,
	// `passwordLength`), and others. We don't support these for now.

	Debug::log("Connecting to the broker.");

	// `sessionPresent` will be set to true by `MQTT_Connect` if a previous
	// session was present; otherwise it will be set to false. It is only
	// relevant if not establishing a clean session.
	bool sessionPresent;

	do
	{
		// `remaining` is in milliseconds
		uint32_t remaining = (t->remaining * MS_PER_TICK) / 1000;
		ret                = with_elapse_timeout(t, [&]() {
            return MQTT_Connect(&context->coreMQTTContext,
                                &connectInfo,
                                nullptr,
                                remaining,
                                &sessionPresent);
        });

		if (ret == MQTTNoMemory || ret == MQTTBadParameter)
		{
			// If we run OOM, or pass invalid parameters (which is
			// likely a bug in this code), retrying won't help.
			break;
		}

		if (context->networkContext.isDisconnected)
		{
			// If the link died, retrying won't help.
			Debug::log("Connection aborted while connecting.");
			break;
		}
	} while (t->remaining > 0 && ret != MQTTSuccess);

	if (ret != MQTTSuccess)
	{
		Debug::log("Failed to perform MQTT connect, error {}.", ret);
		return nullptr;
	}

	if (newSession)
	{
		Debug::Assert(sessionPresent == false,
		              "Successfully connected, but a previous session was "
		              "unexpectedly present (client ID re-used?).");
	}
	else
	{
		Debug::Assert(
		  sessionPresent == true,
		  "Successfully connected, but there was no previous session.");
	}

	Debug::log("Connected to the broker {}.", hostCapability);

	return static_cast<MQTTConnection>(sealedContext.release());
}

int mqtt_disconnect(Timeout            *t,
                    AllocatorCapability allocator,
                    MQTTConnection      mqttHandle)
{
	if (!check_timeout_pointer(t))
	{
		return -EINVAL;
	}

	// Proceed in two parts. First attempt to disconnect from the broker
	// (through `MQTT_Disconnect`). If that fails, e.g., because we are out
	// of time or memory, we must consider the connection still open. In
	// that case, we return an error. If this succeeds, we proceed to
	// terminate the TLS link and free all the memory we allocated.
	//
	// Note: do not use `with_sendfailed_retry` here, as we need more
	// thorough error handling.
	int ret = with_sealed_mqtt_context(
	  t, mqttHandle, [&](CHERIoTMqttContext *connection) {
		  MQTTContext_t *coreMQTTContext = &connection->coreMQTTContext;
		  MQTTStatus_t   status;
		  do
		  {
			  if (connection->networkContext.isDisconnected)
			  {
				  // If the connection is dropped, nothing to
				  // do here other than tear it down.
				  return 0;
			  }

			  status = with_elapse_timeout(t, [&]() {
				  // `MQTT_ProcessLoop` handles keepalive.
				  return MQTT_Disconnect(coreMQTTContext);
			  });

			  if (status != MQTTSuccess)
			  {
				  Debug::log("MQTT Disconnect failed, error: {}", status);

				  if (status == MQTTNoMemory)
				  {
					  return -ENOMEM;
				  }
				  if (status == MQTTBadParameter)
				  {
					  // This shouldn't happen and possibly
					  // indicates a bug in our code.
					  Debug::log("MQTT_Disconnect gave -EINVAL, this "
					             "may indicate a bug in this code.");
					  return -EINVAL;
				  }

				  Debug::log("MQTT_Disconnect gave unknown error.");
				  return -EAGAIN;
			  }
		  } while (t->remaining > 0 && status != MQTTSuccess);

		  if (status != MQTTSuccess)
		  {
			  return -ETIMEDOUT;
		  }

		  return 0;
	  });

	if (ret < 0)
	{
		// Disconnecting failed. Leave the TLS link open and return an
		// error.
		return ret;
	}

	// Now terminate the TLS connection and free our resources. This cannot
	// fail.
	return with_sealed_mqtt_context(
	  t,
	  mqttHandle,
	  [&](CHERIoTMqttContext *connection) {
		  connection->~CHERIoTMqttContext();
		  token_obj_destroy(allocator, mqtt_key(), mqttHandle);
		  return 0;
	  },
	  true /* grab the context in destruct mode */);
}

int mqtt_publish(Timeout       *t,
                 MQTTConnection mqttHandle,
                 uint8_t        qos,
                 const char    *topic,
                 size_t         topicLength,
                 const void    *payload,
                 size_t         payloadLength,
                 bool           retain)
{
	if (!CHERI::check_pointer(topic, topicLength))
	{
		return -EINVAL;
	}

	if (!CHERI::check_pointer(payload, payloadLength))
	{
		return -EINVAL;
	}

	if (!check_timeout_pointer(t))
	{
		return -EINVAL;
	}

	if (qos > MQTTQoS2)
	{
		return -EINVAL;
	}

	/**
	 * Validate the topic (done similarly with the filter in
	 * `mqtt_subscribe` and `mqtt_unsubscribe`). Without these checks, we
	 * would send an invalid PUBLISH to the broker, causing our connection
	 * to be terminated. Since these are only there for convenience / not
	 * security-relevant, only enable in debug mode.
	 */

	if constexpr (DebugMQTT)
	{
		// Note from the MQTT 3.1.1 spec: 'All Topic Names and Topic Filters
		// MUST be at least one character long'
		if (topicLength < 1)
		{
			return -EINVAL;
		}

		// Note from the MQTT 3.1.1 spec: 'Topic Names and Topic Filters MUST
		// NOT include the null character'
		if (has_null_character(topic, topicLength))
		{
			return -EINVAL;
		}
	}

	return with_sealed_mqtt_context(
	  t, mqttHandle, [&](CHERIoTMqttContext *connection) {
		  MQTTContext_t    *coreMQTTContext = &connection->coreMQTTContext;
		  MQTTPublishInfo_t publishInfo;

		  publishInfo.qos             = static_cast<MQTTQoS>(qos);
		  publishInfo.pTopicName      = topic;
		  publishInfo.topicNameLength = topicLength;
		  publishInfo.pPayload        = payload;
		  publishInfo.payloadLength   = payloadLength;
		  publishInfo.retain          = retain;

		  // Packet ID is needed for QoS > 0.
		  int packetId = MQTT_GetPacketId(coreMQTTContext);

		  int ret = with_sendfailed_retry(t, "MQTT_Publish", connection, [&]() {
			  return MQTT_Publish(coreMQTTContext, &publishInfo, packetId);
		  });

		  if (ret == 0)
		  {
			  return packetId;
		  }

		  return ret;
	  });
}

int mqtt_subscribe(Timeout       *t,
                   MQTTConnection mqttHandle,
                   uint8_t        qos,
                   const char    *filter,
                   size_t         filterLength)
{
	if (!CHERI::check_pointer(filter, filterLength))
	{
		return -EINVAL;
	}

	if (!check_timeout_pointer(t))
	{
		return -EINVAL;
	}

	if (qos > MQTTQoS2)
	{
		return -EINVAL;
	}

	if constexpr (DebugMQTT)
	{
		if (filterLength < 1)
		{
			return -EINVAL;
		}

		if (has_null_character(filter, filterLength))
		{
			return -EINVAL;
		}
	}

	return with_sealed_mqtt_context(
	  t, mqttHandle, [&](CHERIoTMqttContext *connection) {
		  MQTTContext_t *coreMQTTContext = &connection->coreMQTTContext;

		  MQTTSubscribeInfo_t subscription;
		  subscription.qos               = static_cast<MQTTQoS>(qos);
		  subscription.pTopicFilter      = filter;
		  subscription.topicFilterLength = filterLength;

		  // Obtain a new packet id for the subscription.
		  int packetId = MQTT_GetPacketId(coreMQTTContext);

		  int ret =
		    with_sendfailed_retry(t, "MQTT_Subscribe", connection, [&]() {
			    return MQTT_Subscribe(
			      coreMQTTContext, &subscription, 1, packetId);
		    });

		  if (ret == 0)
		  {
			  return packetId;
		  }

		  return ret;
	  });
}

int mqtt_unsubscribe(Timeout       *t,
                     MQTTConnection mqttHandle,
                     uint8_t        qos,
                     const char    *filter,
                     size_t         filterLength)
{
	if (!CHERI::check_pointer(filter, filterLength))
	{
		return -EINVAL;
	}

	if (!check_timeout_pointer(t))
	{
		return -EINVAL;
	}

	if (qos > MQTTQoS2)
	{
		return -EINVAL;
	}

	if constexpr (DebugMQTT)
	{
		if (filterLength < 1)
		{
			return -EINVAL;
		}

		if (has_null_character(filter, filterLength))
		{
			return -EINVAL;
		}
	}

	return with_sealed_mqtt_context(
	  t, mqttHandle, [&](CHERIoTMqttContext *connection) {
		  MQTTContext_t *coreMQTTContext = &connection->coreMQTTContext;

		  MQTTSubscribeInfo_t unsubscribe;
		  unsubscribe.qos               = static_cast<MQTTQoS>(qos);
		  unsubscribe.pTopicFilter      = filter;
		  unsubscribe.topicFilterLength = filterLength;

		  // Obtain a new packet id for the unsubscribe request.
		  int packetId = MQTT_GetPacketId(coreMQTTContext);

		  int ret =
		    with_sendfailed_retry(t, "MQTT_Unsubscribe", connection, [&]() {
			    return MQTT_Unsubscribe(
			      coreMQTTContext, &unsubscribe, 1, packetId);
		    });

		  if (ret == 0)
		  {
			  return packetId;
		  }

		  return ret;
	  });
}

int mqtt_run(Timeout *t, MQTTConnection mqttHandle)
{
	if (!check_timeout_pointer(t))
	{
		return -EINVAL;
	}

	return with_sealed_mqtt_context(
	  t, mqttHandle, [&](CHERIoTMqttContext *connection) {
		  MQTTContext_t *coreMQTTContext = &connection->coreMQTTContext;
		  MQTTStatus_t   status;

		  // Note: do not use `with_sendfailed_retry` here, as we need
		  // more thorough error handling.
		  do
		  {
			  status = with_elapse_timeout(t, [&]() {
				  // `MQTT_ProcessLoop` handles keepalive.
				  return MQTT_ProcessLoop(coreMQTTContext);
			  });

			  if (status != MQTTSuccess)
			  {
				  Debug::log("MQTT ProcessLoop failed, error: {}", status);

				  if (status == MQTTNoMemory)
				  {
					  return -ENOMEM;
				  }
				  if (status == MQTTSendFailed || status == MQTTRecvFailed ||
				      status == MQTTNeedMoreBytes)
				  {
					  // If the TLS link is still live, try
					  // again until we are out of time.
					  if (connection->networkContext.isDisconnected)
					  {
						  return -ECONNABORTED;
					  }
				  }
				  else if (status == MQTTBadResponse ||
				           status == MQTTIllegalState ||
				           status == MQTTKeepAliveTimeout)
				  {
					  // Something is broken in the
					  // coreMQTT client, or in the broker.
					  // Consider this connection dead.
					  return -ECONNABORTED;
				  }
				  else if (status == MQTTBadParameter)
				  {
					  // This one shouldn't happen and would
					  // possibly indicate a bug in our code.
					  Debug::log("MQTT_ProcessLoop gave -EINVAL, this "
					             "may indicate a bug in this code.");
					  return -EINVAL;
				  }
				  else
				  {
					  Debug::log("MQTT_ProcessLoop gave unknown error.");
					  return -EAGAIN;
				  }
			  }
		  } while (t->remaining > 0 && status != MQTTSuccess);

		  if (status != MQTTSuccess)
		  {
			  return -ETIMEDOUT;
		  }

		  return 0;
	  });
}

int mqtt_generate_client_id(char *buffer, size_t length)
{
	auto characters =
	  std::string_view(ClientIdCharacters, sizeof(ClientIdCharacters) - 1);

	if ((length > MQTTMaximumClientIDSize) || (length == 0))
	{
		return -EINVAL;
	}

	if (!CHERI::check_pointer(buffer, length))
	{
		return -EINVAL;
	}

	for (size_t i = 0; i < length; i++)
	{
		// Select a character at random.
		// Note: biased because of the modulo, see API documentation
		buffer[i] = characters[rand() % characters.size()];
	}

	Debug::Assert(is_valid_client_id({buffer, length}),
	              "`mqtt_generate_client_id` generated an invalid client ID.");

	return 0;
}
