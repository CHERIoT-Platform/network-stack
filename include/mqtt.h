// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include <timeout.h>
#include <tls.h>
#include <token.h>

/**
 * Type of the PUBLISH callback. This user callback, passed to `mqtt_connect`,
 * will be called on all PUBLISH notifications from the broker.
 *
 * `topicName` and `payload` (and their respective size arguments) indicate the
 * topic of the PUBLISH, and the corresponding payload.
 */
typedef void __cheri_callback (*MQTTPublishCallback)(const char *topicName,
                                                     size_t topicNameLength,
                                                     const void *payload,
                                                     size_t      payloadLength);

/**
 * Type of the ACK callback. This user callback, passed to `mqtt_connect`, will
 * be called on all ACKs from the broker (SUBACK, PUBACK, etc.).  Note that
 * CONNACK does not trigger this callback since it is consumed by internal
 * coreMQTT functions.
 *
 * `packetID` indicates the packet ID of the packet ACK-ed, which can be
 * compared to the ID of packets the clients sent.
 *
 * `isReject` is set to `true` for a SUBACK where the server rejected the
 * SUBSCRIBE request, otherwise `false`.
 */
typedef void __cheri_callback (*MQTTAckCallback)(uint16_t packetID,
                                                 bool     isReject);

/**
 * Creates a new unauthenticated TLS-tunneled MQTT connection. Returns null on
 * failure, or a sealed MQTT connection object on success.
 *
 * The state for the MQTT and TLS connections will be allocated with
 * `allocator`.  The connection will be made to the broker identified by
 * `hostCapability`, which must authorise a TCP connection.  Once the
 * connection is made, the certificates will be validated against the trust
 * anchors provided via the `trustAnchors` parameter, which contains a pointer
 * to an array of `trustAnchorsCount` trust anchors.
 *
 * The client will be identified by the broker as `clientID` (of length
 * `clientIDLength`), which must be unique for the broker. `clientID` must be a
 * valid MQTT 3.1.1 client ID (no null terminator, only characters of a-z, A-Z,
 * 0-9, length <= 23). Do not launch multiple clients with the same client ID,
 * as the broker will terminate the connection with the client which previously
 * using this ID.
 *
 * `networkBufferSize` represents the total size of send and receive buffers.
 *
 * `incomingPublishCount` and `outgoingPublishCount` are relevant for QoS
 * levels > 0 and represent the number of records which can be kept in memory
 * at any point in time. All should be sized to match the needs of the client.
 *
 * The client ID must remain valid during the execution of function. Freeing
 * the buffer concurrently may result in caller data being leaked to the broker
 * through the client ID. The client ID does not need to be valid across calls
 * to this API and can therefore be freed after `mqtt_connect` returned.
 *
 * This function can fail if, among others:
 *
 *  - The connection capability is not a valid TCP connection capability.
 *  - The allocator capability does not have enough quota to satisfy the
 *    allocations.
 *  - The remote broker is not accessible.
 *  - The remote broker's certificate is not trusted by the trust anchors.
 *  - A timeout was hit, which would be indicated by an empty `t->remaining`.
 *
 * Known problems with this API (inherited from the TLS API):
 *
 *  - This function assumes that the trust anchors are valid and will not be
 *    freed during the call.
 *  - The BearSSL types are leaked into the API.
 *  - The reason for the failure is not reported.
 */
SObj __cheri_compartment("MQTT")
  mqtt_connect(Timeout                    *t,
               SObj                        allocator,
               SObj                        hostCapability,
               MQTTPublishCallback         publishCallback,
               MQTTAckCallback             ackCallback,
               const br_x509_trust_anchor *trustAnchors,
               size_t                      trustAnchorsCount,
               size_t                      networkBufferSize,
               size_t                      incomingPublishCount,
               size_t                      outgoingPublishCount,
               const char                 *clientID,
               size_t                      clientIDLength);

// TODO add an API to connect to a broker with a client certificate.

/**
 * Close a TLS-tunneled MQTT connection.
 *
 * The state for the MQTT connection will be deallocated with `allocator`.
 *
 * The return value is zero if the connection was successfully terminated, or a
 * negative error code.
 *
 * The negative values will be errno values:
 *
 *  - `-EINVAL`: The timeout or MQTT handle is not valid.
 *  - `-ETIMEDOUT`: The timeout was reached before the connection could be
 *                  terminated.
 *  - `-ENOMEM`: The send/receive buffer is too small to hold the disconnect
 *               packet. The buffer sizes passed to `mqtt_connect` likely need
 *               to be increased.
 *  - `-EAGAIN`: An unspecified error happened in the underlying coreMQTT
 *               library. Try again.
 *
 * Note that, in the case of a negative error return value, the connection has
 * *not* been terminated, and the resources *not* freed.
 */
int __cheri_compartment("MQTT")
  mqtt_disconnect(Timeout *t, SObj allocator, SObj mqttHandle);

/**
 * Publish on a given MQTT connection.
 *
 * The parameters `topic` and `payload` (and related lengths `topicLength` and
 * `payloadLength`) indicate the topic and payload.
 *
 * `qos` indicates the level of QoS (0, 1, or 2).
 *
 * Both the topic and payload buffers must remain valid during the execution of
 * this function. If the caller frees them during the execution of this
 * function, the publish may leak application data to the broker through the
 * topic and payload.
 *
 * The return value is the packet ID of the publish packet if the publish was
 * successfully sent, or a negative error code. The packet ID can then be used
 * to match an ACK callback call (`MQTTAckCallback`) with this publish
 * operation (if QoS > 0).
 *
 * The negative values will be errno values:
 *
 *  - `-EINVAL`: A parameter is not valid.
 *  - `-ETIMEDOUT`: The timeout was reached before the publish could be
 *                  performed.
 *  - `-ENOMEM`: The send/receive buffer is too small to hold the publish
 *               packet. The buffer sizes passed to `mqtt_connect` likely need
 *               to be increased.
 *  - `-ECONNABORTED`: The connection to the broker was lost. The client should
 *                     now call `mqtt_disconnect` to free resources associated
 *                     with this handle.
 *  - `-EAGAIN`: An unspecified error happened in the underlying coreMQTT
 *               library. Try again.
 *
 * If a publish is successful and QoS > 0, an ACK must be fetched through
 * `mqtt_run`.
 */
int __cheri_compartment("MQTT") mqtt_publish(Timeout    *t,
                                             SObj        mqttHandle,
                                             uint8_t     qos,
                                             const char *topic,
                                             size_t      topicLength,
                                             const void *payload,
                                             size_t      payloadLength);

/**
 * Subscribe on a given MQTT connection.
 *
 * The parameters `filter` indicates on which topic to subscribe.
 *
 * `qos` indicates the level of QoS (0, 1, or 2).
 *
 * The filter buffer must remain valid during the execution of this function.
 * If the caller frees it during the execution of this function, the subscribe
 * may leak application data to the broker through the filter.
 *
 * The return value is the packet ID of the subscribe packet if the subscribe
 * was successfully sent, or a negative error code. The packet ID
 * can then be used to match an ACK callback call (`MQTTAckCallback`) with this
 * subscribe operation.
 *
 * The negative values will be errno values:
 *
 *  - `-EINVAL`: A parameter is not valid.
 *  - `-ETIMEDOUT`: The timeout was reached before the subscribe could be
 *                  performed.
 *  - `-ENOMEM`: The allocator capability does not have enough quota to satisfy
 *               the allocations.
 *  - `-ECONNABORTED`: The connection to the broker was lost. The client should
 *                     now call `mqtt_disconnect` to free resources associated
 *                     with this handle.
 *  - `-EAGAIN`: An unspecified error happened in the underlying coreMQTT
 *               library. Try again.
 *
 * If this is successful, the user must call `mqtt_run` to receive the SUBACK.
 * If the broker accepts the subscription, we will now receive publishes on the
 * requested topics.
 */
int __cheri_compartment("MQTT") mqtt_subscribe(Timeout    *t,
                                               SObj        mqttHandle,
                                               uint8_t     qos,
                                               const char *filter,
                                               size_t      filterLength);

/**
 * Unsubscribe on a given MQTT connection.
 *
 * The parameters `filter` indicates on which topic to unsubscribe.
 *
 * `qos` indicates the level of QoS (0, 1, or 2).
 *
 * The filter buffer must remain valid during the execution of this function.
 * If the caller frees it during the execution of this function, the
 * unsubscribe may leak application data to the broker through the filter.
 *
 * The return value is the packet ID of the unsubscribe packet if the
 * unsubscribe was successfully sent, or a negative error code.  The packet ID
 * can then be used to match an ACK callback call (`MQTTAckCallback`) with this
 * unsubscribe operation.
 *
 * The negative values will be errno values:
 *
 *  - `-EINVAL`: A parameter is not valid.
 *  - `-ETIMEDOUT`: The timeout was reached before the unsubscribe could be
 *                  performed.
 *  - `-ENOMEM`: The send/receive buffer is too small to hold the unsubscribe
 *               packet. The buffer sizes passed to `mqtt_connect` likely need
 *               to be increased.
 *  - `-ECONNABORTED`: The connection to the broker was lost. The client should
 *                     now call `mqtt_disconnect` to free resources associated
 *                     with this handle.
 *  - `-EAGAIN`: An unspecified error happened in the underlying coreMQTT
 *               library. Try again.
 *
 * If this is successful, the user must call `mqtt_run` to receive the
 * UNSUBACK. After this the broker will no longer send publishes for this
 * topic.
 */
int __cheri_compartment("MQTT") mqtt_unsubscribe(Timeout    *t,
                                                 SObj        mqttHandle,
                                                 uint8_t     qos,
                                                 const char *filter,
                                                 size_t      filterLength);

/**
 * Fetch ACK and PUBLISH notifications on a given MQTT connection, and keep
 * the connection alive.
 *
 * The return value is zero if notifications were successfully fetched, or a
 * negative error code.
 *
 * The negative values will be errno values:
 *
 *  - `-EINVAL`: A parameter is not valid.
 *  - `-ETIMEDOUT`: The timeout was reached before notifications could be
 *                  fetched.
 *  - `-ECONNABORTED`: The connection to the broker was lost. The client should
 *                     now call `mqtt_disconnect` to free resources associated
 *                     with this handle.
 *  - `-EAGAIN`: An unspecified error happened in the underlying coreMQTT
 *               library. Try again.
 */
int __cheri_compartment("MQTT") mqtt_run(Timeout *t, SObj mqttHandle);

/**
 * Generate a valid, random MQTT 3.1.1 client ID of length `length` into
 * `buffer`, for passing to `mqtt_connect`.
 *
 * `length` must be > 0 and <= 23. Note that the smaller `length` is, the
 * higher the risk of client ID collisions, which, depending on the broker
 * implementation of MQTT, may result in arbitrary termination of clients.
 *
 * Note that the random output of this function may not be evenly distributed
 * over the allowed character set of client IDs.
 *
 * Note that client IDs are NOT zero-terminated, following the MQTT 3.1.1
 * specification.
 *
 * The return value is zero if the client ID was successfully generated, or a
 * negative error code.
 *
 * The negative values will be errno values:
 *
 *  - `-EINVAL`: A parameter is not valid.
 */
int __cheri_compartment("MQTT")
  mqtt_generate_client_id(char *buffer, size_t length);
