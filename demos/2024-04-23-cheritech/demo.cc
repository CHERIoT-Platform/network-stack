// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#include <NetAPI.h>
#include <cstdlib>
#include <debug.hh>
#include <errno.h>
#include <fail-simulator-on-error.h>
#include <locks.hh>
#include <mqtt.h>
#include <platform-entropy.hh>
#include <platform-gpio.hh>
#include <sntp.h>
#include <string_view>
#include <tick_macros.h>
#include <vector>

#include "host.cert.h"
#include "javascript.hh"

using CHERI::Capability;

using Debug            = ConditionalDebug<true, "MQTT demo">;
constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

// MQTT network buffer sizes
constexpr const size_t networkBufferSize    = 2048;
constexpr const size_t incomingPublishCount = 100;
constexpr const size_t outgoingPublishCount = 100;

namespace
{

	DECLARE_AND_DEFINE_CONNECTION_CAPABILITY(DemoHost,
	                                         "cheriot.demo",
	                                         8883,
	                                         ConnectionTypeTCP);

	DECLARE_AND_DEFINE_ALLOCATOR_CAPABILITY(mqttTestMalloc, 32 * 1024);

	constexpr std::string_view CodeTopic{"cheri-code"};
	int32_t                    codeSubscribePacketId = -1;
	bool                       codeAckReceived       = false;

	constexpr const char *buttonTopic   = "cheri-button";
	int                   buttonCounter = 0;

	/**
	 * Note from the MQTT 3.1.1 spec:
	 * The Server MUST allow ClientIds which are between 1 and 23 UTF-8 encoded
	 * bytes in length, and that contain only the characters
	 * "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	 *
	 * Note from us:
	 * UTF-8 encoding of 0-9, a-z, A-Z, is 1 Byte per character, so we should be
	 * able to do up to a length of 22 characters + zero byte.
	 */
	constexpr const int clientIDlength           = 23;
	constexpr const int clientIDPrefixLength     = 8;
	char                clientID[clientIDlength] = "cheriot-XXXXXXXXXXXXXX";

	/// Callbacks

	void __cheri_callback ackCallback(uint16_t packetID, bool isReject)
	{
		if (packetID == codeSubscribePacketId)
		{
			codeAckReceived = true;
		}
	}

	void __cheri_callback publishCallback(const char *topicName,
	                                      size_t      topicNameLength,
	                                      const void *payloadData,
	                                      size_t      payloadLength)
	{
		std::string_view topic{topicName, topicNameLength};
		// FIXME: This is a work around for a compiler bug.  __builtin_memcmp
		// is being expanded to a call to memcmp with the wrong calling
		// convention and so we get linker errors.
		// if (topic == CodeTopic)
		if ((CodeTopic.size() == topic.size()) &&
		    (memcmp(topic.data(), CodeTopic.data(), CodeTopic.size()) == 0))
		{
			load_javascript(payloadData, payloadLength);
			return;
		}

		std::string_view payload{static_cast<const char *>(payloadData),
		                         payloadLength};
		publish(topic, payload);
	}

	/// Handle to the MQTT connection.
	SObj handle;

} // namespace

bool mqtt_publish(std::string_view topic, std::string_view message)
{
	Timeout t{UnlimitedTimeout};
	auto ret = mqtt_publish(&t,
	                        handle,
	                        0, // Don't want acks for this one
	                        topic.data(),
	                        topic.size(),
	                        message.data(),
	                        message.size());
	return ret != 0;
}

bool mqtt_subscribe(std::string_view topic)
{
	Timeout t{MS_TO_TICKS(100)};
	auto    ret = mqtt_subscribe(&t, handle, 1, topic.data(), topic.size());
	return ret >= 0;
}

/// Main demo

void __cheri_compartment("mqtt_demo") demo()
{
	int     ret;
	Timeout t{MS_TO_TICKS(5000)};

	MMIO_CAPABILITY(GPIO, gpio_led0)->enable_all();

	Debug::log("Starting MQTT demo...");
	network_start();
	Debug::log("Network is ready...");

	// systemd decides to restart the ntp server when it detects a new
	// interface.  If we try to get NTP time too quickly, the server isn't
	// ready.  Wait one second to give it time to stabilise.
	{
		Timeout oneSecond(MS_TO_TICKS(1000));
		thread_sleep(&oneSecond);
	}

	// SNTP must be run for the TLS stack to be able to check certificate dates.
	Debug::log("Fetching NTP time...");
	t = Timeout{MS_TO_TICKS(1000)};
	while (sntp_update(&t) != 0)
	{
		Debug::log("Failed to update NTP time");
		t = Timeout{MS_TO_TICKS(1000)};
	}

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

	while (true)
	{
		load_javascript(nullptr, 0);
		Debug::log("Generating client ID...");
		mqtt_generate_client_id(clientID + clientIDPrefixLength,
		                        clientIDlength - clientIDPrefixLength - 1);

		Debug::log("Connecting to MQTT broker...");
		Debug::log("Quota left: {}", heap_quota_remaining(MALLOC_CAPABILITY));
		t      = UnlimitedTimeout;
		handle = mqtt_connect(&t,
		                      STATIC_SEALED_VALUE(mqttTestMalloc),
		                      STATIC_SEALED_VALUE(DemoHost),
		                      publishCallback,
		                      ackCallback,
		                      TAs,
		                      TAs_NUM,
		                      networkBufferSize,
		                      incomingPublishCount,
		                      outgoingPublishCount,
		                      clientID,
		                      strlen(clientID));

		if (!Capability{handle}.is_valid())
		{
			Debug::log("Failed to connect, retrying...");
			Timeout pause{MS_TO_TICKS(1000)};
			thread_sleep(&pause);
			continue;
		}

		Debug::log("Connected to MQTT broker!");

		Debug::log("Subscribing to JavaScript code topic '{}'.", CodeTopic);

		ret = mqtt_subscribe(&t,
		                     handle,
		                     1, // QoS 1 = delivered at least once
		                     CodeTopic.data(),
		                     CodeTopic.size());

		if (ret < 0)
		{
			Debug::log("Failed to subscribe, error {}.", ret);
			mqtt_disconnect(&t, STATIC_SEALED_VALUE(mqttTestMalloc), handle);
			continue;
		}

		codeSubscribePacketId = ret;

		Debug::log("Now fetching the SUBACKs.");

		while (!codeAckReceived)
		{
			t   = Timeout{MS_TO_TICKS(1000)};
			ret = mqtt_run(&t, handle);

			if (ret < 0)
			{
				Debug::log(
				  "Failed to wait for the SUBACK for the code node, error {}.",
				  ret);
				mqtt_disconnect(
				  &t, STATIC_SEALED_VALUE(mqttTestMalloc), handle);
				continue;
			}
		}

		Debug::log("Now entering the main loop.");
		while (true)
		{
			// Check for PUBLISHes
			t = Timeout{MS_TO_TICKS(100)};
			// Debug::log("{} bytes of heap free", heap_available());
			ret = mqtt_run(&t, handle);

			if ((ret < 0) && (ret != -ETIMEDOUT))
			{
				Debug::log("Failed to wait for PUBLISHes, error {}.", ret);
				break;
			}
			tick();
		}
		Debug::log("Exiting main loop, cleaning up.");
		mqtt_disconnect(&t, STATIC_SEALED_VALUE(mqttTestMalloc), handle);
		// Sleep for a second to allow the network stack to clean up any
		// outstanding allocations
		Timeout oneSecond{MS_TO_TICKS(1000)};
		thread_sleep(&oneSecond);
	}
}
