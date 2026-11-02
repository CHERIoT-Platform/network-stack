// Copyright The Good Penguin Ltd
// SPDX-License-Identifier: MITP

#pragma once
#include <timeout.h>
#include <tls_wolfssl.h>
#include <token.h>

struct CHERIoTWolfSSLMqttContext;

typedef CHERI_SEALED(struct CHERIoTWolfSSLMqttContext *) WolfSSLMQTTConnection;

/**
 * Type of the PUBLISH callback. This user callback, passed to
 * `mqtt_wolfssl_connect`, will be called on all PUBLISH notifications from
 * the broker.
 *
 * `topicName` and `payload` (and their respective size arguments) indicate the
 * topic of the PUBLISH, and the corresponding payload. Both are only valid
 * within the context of the callback and thus passed as a read-only,
 * non-capturable capabilities.
 */
typedef void __cheri_callback (*WolfSSLMQTTPublishCallback)(
  const char *topicName,
  size_t      topicNameLength,
  const void *payload,
  size_t      payloadLength);

/**
 * Type of the ACK callback. This user callback, passed to
 * `mqtt_wolfssl_connect`, will be called on all ACKs from the broker
 * (SUBACK, PUBACK, etc.).
 */
typedef void __cheri_callback (*WolfSSLMQTTAckCallback)(uint16_t packetID,
                                                        bool     isReject);

/**
 * Creates a new unauthenticated TLS-tunneled MQTT connection using wolfSSL.
 * Returns null on failure, or a sealed MQTT connection object on success.
 *
 * This is the wolfSSL equivalent of `mqtt_connect`. See `mqtt.h` for full
 * parameter documentation.
 */
WolfSSLMQTTConnection __cheri_compartment("WolfSSLMQTT")
  mqtt_wolfssl_connect(Timeout                    *t,
                       AllocatorCapability         allocator,
                       ConnectionCapability        hostCapability,
                       WolfSSLMQTTPublishCallback  publishCallback,
                       WolfSSLMQTTAckCallback      ackCallback,
                       const WolfSSLTrustAnchor   *trustAnchors,
                       size_t                      trustAnchorsCount,
                       size_t                      networkBufferSize,
                       size_t                      incomingPublishCount,
                       size_t                      outgoingPublishCount,
                       const char                 *clientID,
                       size_t                      clientIDLength,
                       bool newSession              __if_cxx(= true));

/**
 * Close a TLS-tunneled MQTT connection (wolfSSL variant).
 * See `mqtt.h` for full documentation.
 */
int __cheri_compartment("WolfSSLMQTT")
  mqtt_wolfssl_disconnect(Timeout                *t,
                          AllocatorCapability     allocator,
                          WolfSSLMQTTConnection   mqttHandle);

/**
 * Publish on a given wolfSSL MQTT connection.
 * See `mqtt.h` for full documentation.
 */
int __cheri_compartment("WolfSSLMQTT")
  mqtt_wolfssl_publish(Timeout               *t,
                       WolfSSLMQTTConnection  mqttHandle,
                       uint8_t                qos,
                       const char            *topic,
                       size_t                 topicLength,
                       const void            *payload,
                       size_t                 payloadLength,
                       bool                   retain __if_cxx(= false));

/**
 * Subscribe on a given wolfSSL MQTT connection.
 * See `mqtt.h` for full documentation.
 */
int __cheri_compartment("WolfSSLMQTT")
  mqtt_wolfssl_subscribe(Timeout               *t,
                         WolfSSLMQTTConnection  mqttHandle,
                         uint8_t                qos,
                         const char            *filter,
                         size_t                 filterLength);

/**
 * Unsubscribe on a given wolfSSL MQTT connection.
 * See `mqtt.h` for full documentation.
 */
int __cheri_compartment("WolfSSLMQTT")
  mqtt_wolfssl_unsubscribe(Timeout               *t,
                           WolfSSLMQTTConnection  mqttHandle,
                           uint8_t                qos,
                           const char            *filter,
                           size_t                 filterLength);

/**
 * Fetch ACK and PUBLISH notifications on a given wolfSSL MQTT connection.
 * See `mqtt.h` for full documentation.
 */
int __cheri_compartment("WolfSSLMQTT")
  mqtt_wolfssl_run(Timeout *t, WolfSSLMQTTConnection mqttHandle);

/**
 * Generate a valid, random MQTT 3.1.1 client ID.
 * See `mqtt.h` for full documentation.
 */
int __cheri_compartment("WolfSSLMQTT")
  mqtt_wolfssl_generate_client_id(char *buffer, size_t length);
