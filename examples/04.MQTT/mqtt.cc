// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <NetAPI.h>
#include <cstdlib>
#include <debug.hh>
#include <errno.h>
#include <fail-simulator-on-error.h>
#include <mqtt.h>
#include <sntp.h>
#include <tick_macros.h>

#include "mosquitto.org.h"

using CHERI::Capability;

using Debug            = ConditionalDebug<true, "MQTT example">;
constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

// The client ID is used by the broker to identify the client. It should be
// unique per client. Since this is hard-coded, this means we cannot launch
// multiple concurrent instances of this example on a same test server.
// TODO it would be nice to generate automatically.
constexpr const char  *clientID       = "anoncheri42";
constexpr const size_t clientIDLength = sizeof(clientID);

// MQTT network buffer sizes
constexpr const size_t networkBufferSize    = 1024;
constexpr const size_t incomingPublishCount = 20;
constexpr const size_t outgoingPublishCount = 20;

// MQTT test broker: https://test.mosquitto.org/
// Note: port 8883 is encrypted and unautenticated
DECLARE_AND_DEFINE_CONNECTION_CAPABILITY(MosquittoOrgMQTT,
                                         "test.mosquitto.org",
                                         8883,
                                         ConnectionTypeTCP);

DECLARE_AND_DEFINE_ALLOCATOR_CAPABILITY(mqttTestMalloc, 32 * 1024);

const char *testTopic   = "cherries";
const int   testPayload = 42;

static int ackReceived     = 0;
static int publishReceived = 0;

void __cheri_callback publishCallback(const char *topicName,
                                      size_t      topicNameLength,
                                      const void *payload,
                                      size_t      payloadLength)
{
	// Check input pointers (can be skipped if the MQTT library is trusted)
	Timeout t{MS_TO_TICKS(5000)};
	if (heap_claim_fast(&t, topicName) != 0 ||
	    !CHERI::check_pointer(topicName, topicNameLength))
	{
		Debug::log(
		  "Cannot claim or verify PUBLISH callback topic name pointer.");
		return;
	}

	if (heap_claim_fast(&t, payload) != 0 ||
	    !CHERI::check_pointer(payload, payloadLength))
	{
		Debug::log("Cannot claim or verify PUBLISH callback payload pointer.");
		return;
	}

	Debug::log("Got a PUBLISH for topic {}", topicName);
	publishReceived++;
}

void __cheri_callback ackCallback(uint16_t packetID, bool isReject)
{
	Debug::log("Got an ACK for packet {}", packetID);

	if (isReject)
	{
		Debug::log("However the ACK is a SUBSCRIBE REJECT notification");
	}

	ackReceived++;
}

void __cheri_compartment("mqtt_example") example()
{
	int     ret;
	Timeout t{MS_TO_TICKS(5000)};

	network_start();

	// SNTP must be run for the TLS stack to be able to check certificate dates.
	while (sntp_update(&t) != 0)
	{
		Debug::log("Failed to update NTP time");
		Timeout oneSecond{MS_TO_TICKS(1000)};
	}
	Debug::log("Updating NTP took {} ticks", t.elapsed);
	t = UnlimitedTimeout;
	{
		timeval tv;
		int     ret = gettimeofday(&tv, nullptr);
		if (ret != 0)
		{
			Debug::log("Failed to get time of day: {}", ret);
		}
		else
		{
			// Truncate the epoch time to 32 bits for printing.
			Debug::log("Current UNIX epoch time: {}", (int32_t)tv.tv_sec);
		}
	}

	auto heapAtStart =
	  heap_quota_remaining(STATIC_SEALED_VALUE(mqttTestMalloc));

	Debug::log("Connecting to MQTT broker...");

	SObj handle = mqtt_connect(&t,
	                           STATIC_SEALED_VALUE(mqttTestMalloc),
	                           STATIC_SEALED_VALUE(MosquittoOrgMQTT),
	                           publishCallback,
	                           ackCallback,
	                           TAs,
	                           TAs_NUM,
	                           networkBufferSize,
	                           incomingPublishCount,
	                           outgoingPublishCount,
	                           clientID,
	                           clientIDLength);

	if (!Capability{handle}.is_valid())
	{
		Debug::log("Failed to connect.");
		return;
	}

	Debug::log("Connected to MQTT broker!");

	Debug::log("Subscribing to test topic '{}'.", testTopic);

	ret = mqtt_subscribe(&t,
	                     handle,
	                     1, // QoS 1 = delivered at least once
	                     testTopic,
	                     sizeof(testTopic));

	if (ret < 0)
	{
		Debug::log("Failed to subscribe, error {}.", ret);
		return;
	}

	Debug::log("Now fetching the SUBACK.");

	while (ackReceived == 0)
	{
		t   = Timeout{MS_TO_TICKS(100)};
		ret = mqtt_run(&t, handle);

		if (ret < 0)
		{
			Debug::log("Failed to wait for the SUBACK, error {}.", ret);
			return;
		}
	}

	Debug::log("Publishing a value to test topic '{}'.", testTopic);

	t   = Timeout{MS_TO_TICKS(5000)};
	ret = mqtt_publish(&t,
	                   handle,
	                   1, // QoS 1 = delivered at least once
	                   testTopic,
	                   sizeof(testTopic),
	                   static_cast<const void *>(&testPayload),
	                   sizeof(testPayload));

	if (ret < 0)
	{
		Debug::log("Failed to publish, error {}.", ret);
		return;
	}

	Debug::log(
	  "Now fetching the PUBACK and waiting for the publish notification.");

	while (ackReceived == 1 || publishReceived == 0)
	{
		t   = Timeout{MS_TO_TICKS(100)};
		ret = mqtt_run(&t, handle);

		if (ret < 0)
		{
			Debug::log("Failed to wait for the PUBACK/PUBLISH, error {}.", ret);
			return;
		}
	}

	Debug::log("Unsubscribing from topic '{}'.", testTopic);

	t   = Timeout{MS_TO_TICKS(5000)};
	ret = mqtt_unsubscribe(&t,
	                       handle,
	                       1, // QoS 1 = delivered at least once
	                       testTopic,
	                       sizeof(testTopic));

	if (ret < 0)
	{
		Debug::log("Failed to unsubscribe, error {}.", ret);
		return;
	}

	while (ackReceived == 2)
	{
		t   = Timeout{MS_TO_TICKS(100)};
		ret = mqtt_run(&t, handle);

		if (ret < 0)
		{
			Debug::log("Failed to wait for the UNSUBACK, error {}.", ret);
			return;
		}
	}

	Debug::log("Disconnecting from the broker.", testTopic);

	t   = Timeout{MS_TO_TICKS(5000)};
	ret = mqtt_disconnect(&t, STATIC_SEALED_VALUE(mqttTestMalloc), handle);

	if (ret < 0)
	{
		Debug::log("Failed to disconnect, error {}.", ret);
		return;
	}

	Debug::log("Now checking for leaks.");

	// Check for leaks.
	auto heapAtEnd = heap_quota_remaining(STATIC_SEALED_VALUE(mqttTestMalloc));
	if (heapAtStart != heapAtEnd)
	{
		Debug::log("Warning: The implementation leaked {} bytes ({} vs. {}).",
		           heapAtEnd - heapAtStart,
		           heapAtStart,
		           heapAtEnd);
	}
	else
	{
		Debug::log("No leaks detected.");
	}

	Debug::log("Done testing MQTT.");
}
