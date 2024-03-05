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
#include <tick_macros.h>

#include "host.cert.h"
#include "thread.h"
#include "timeout.h"
//#include "mosquitto.org.h"

using CHERI::Capability;

using Debug            = ConditionalDebug<true, "MQTT demo">;
constexpr bool UseIPv6 = CHERIOT_RTOS_OPTION_IPv6;

// MQTT network buffer sizes
constexpr const size_t networkBufferSize    = 1024;
constexpr const size_t incomingPublishCount = 100;
constexpr const size_t outgoingPublishCount = 100;

namespace
{

	DECLARE_AND_DEFINE_CONNECTION_CAPABILITY(DemoHost,
	                                         "demo.cheriot",
	                                         8883,
	                                         ConnectionTypeTCP);

	DECLARE_AND_DEFINE_CONNECTION_CAPABILITY(MosquittoOrgMQTT,
	                                         "test.mosquitto.org",
	                                         8883,
	                                         ConnectionTypeTCP);

	DECLARE_AND_DEFINE_ALLOCATOR_CAPABILITY(mqttTestMalloc, 32 * 1024);

	constexpr const char *ledTopic             = "cheri-led";
	int32_t               ledSubscribePacketId = -1;
	bool                  ledAckReceived       = false;

	constexpr const char *buttonTopic   = "cheri-button";
	int                   buttonCounter = 0;

	/// Helpers

	/// Returns a weak pseudo-random number.
	uint64_t rand()
	{
		EntropySource rng;
		return rng();
	}

	/// Maximum permitted MQTT client identifier length (from the MQTT
	/// specification)
	constexpr size_t MQTTMaximumClientLength = 23;
	/// Prefix for MQTT client identifier
	constexpr std::string_view clientIDPrefix{"cherIoTdemo"};
	/// Space for the random client ID.
	std::array<char, MQTTMaximumClientLength> clientID;
	static_assert(clientIDPrefix.size() < clientID.size());

	/**
	 * Turn an LED on.
	 */
	void gpios_on()
	{
		MMIO_CAPABILITY(GPIO, gpio_led0)->enable_all();
	}

	/**
	 * Turn an LED on.
	 */
	void led_on(int32_t index)
	{
		MMIO_CAPABILITY(GPIO, gpio_led0)->led_on(index);
	}

	/**
	 * Turn an LED off.
	 */
	void led_off(int32_t index)
	{
		MMIO_CAPABILITY(GPIO, gpio_led0)->led_off(index);
	}

	/**
	 * Read a single button.
	 */
	int32_t read_button(int32_t index)
	{
		return MMIO_CAPABILITY(GPIO, gpio_led0)->button(index);
	}

	uint32_t read_switches()
	{
		return MMIO_CAPABILITY(GPIO, gpio_led0)->switches();
	}

	/// Callbacks

	void __cheri_callback ackCallback(uint16_t packetID, bool isReject)
	{
		if (packetID == ledSubscribePacketId)
		{
			ledAckReceived = true;
		}
	}

	void __cheri_callback publishCallback(const char *topicName,
	                                      size_t      topicNameLength,
	                                      const void *payload,
	                                      size_t      payloadLength)
	{
		// TODO check input pointers

		const char *payloadStr = static_cast<const char *>(payload);
		size_t      length     = std::min(strlen(ledTopic), topicNameLength);
		if (strncmp(topicName, ledTopic, length) == 0)
		{
			if (payloadLength >= 1)
			{
				switch (static_cast<const char *>(payload)[0])
				{
					case '0':
						led_off(0);
						led_off(1);
						return;
					case '1':
						led_on(0);
						led_off(1);
						return;
					case '2':
						led_off(0);
						led_on(1);
						return;
					case '3':
						led_on(0);
						led_on(1);
						return;
				}
			}
		}

		Debug::log("Received PUBLISH notification with invalid topic ({}) or "
		           "payload ({}).",
		           std::string_view{topicName, topicNameLength},
		           std::string_view{payloadStr, payloadLength});
	}

	uint32_t switches;

} // namespace

/// Main demo

void __cheri_compartment("mqtt_demo") demo()
{
	int     ret;
	Timeout t{MS_TO_TICKS(5000)};

	gpios_on();

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

	// Prefix client ID with something recognizable, for convenience.
	memcpy(clientID.data(), clientIDPrefix.data(), clientIDPrefix.size());

	while (true)
	{
		Debug::log("Generating client ID...");
		// Suffix with random character chain.
		mqtt_generate_client_id(clientID.data() + clientIDPrefix.size(),
		                        clientID.size() - clientIDPrefix.size());

		Debug::log("Connecting to MQTT broker...");
		Debug::log("Quota left: {}", heap_quota_remaining(MALLOC_CAPABILITY));
		t           = UnlimitedTimeout;
		SObj handle = mqtt_connect(&t,
		                           STATIC_SEALED_VALUE(mqttTestMalloc),
		                           STATIC_SEALED_VALUE(DemoHost),
		                           publishCallback,
		                           ackCallback,
		                           TAs,
		                           TAs_NUM,
		                           networkBufferSize,
		                           incomingPublishCount,
		                           outgoingPublishCount,
		                           clientID.data(),
		                           clientID.size());

		if (!Capability{handle}.is_valid())
		{
			Debug::log("Failed to connect, retrying...");
			Timeout pause{MS_TO_TICKS(1000)};
			thread_sleep(&pause);
			continue;
		}

		Debug::log("Connected to MQTT broker!");

		Debug::log("Subscribing to LED topic '{}'.", ledTopic);

		ret = mqtt_subscribe(&t,
		                     handle,
		                     1, // QoS 1 = delivered at least once
		                     ledTopic,
		                     strlen(ledTopic));

		if (ret < 0)
		{
			Debug::log("Failed to subscribe, error {}.", ret);
			mqtt_disconnect(&t, STATIC_SEALED_VALUE(mqttTestMalloc), handle);
			continue;
		}

		ledSubscribePacketId = ret;

		Debug::log("Now fetching the SUBACKs.");

		while (!ledAckReceived)
		{
			t   = Timeout{MS_TO_TICKS(100)};
			ret = mqtt_run(&t, handle);

			if (ret < 0)
			{
				Debug::log("Failed to wait for the SUBACK, error {}.", ret);
				mqtt_disconnect(
				  &t, STATIC_SEALED_VALUE(mqttTestMalloc), handle);
				continue;
			}
		}

		Timeout coolDown{0};
		Debug::log("Now entering the main loop.");
		while (true)
		{
			SystickReturn timestampBefore = thread_systemtick_get();

			// Check for PUBLISHes
			do
			{
				t = Timeout{MS_TO_TICKS(10)};
				ret = mqtt_run(&t, handle);
			}
			while (ret == -EAGAIN || ret == -ETIMEDOUT);

			if (ret < 0)
			{
				Debug::log("Failed to wait for PUBLISHes, error {}.", ret);
				break;
			}

			uint32_t newSwitches = read_switches();
			if (newSwitches != switches)
			{
				for (int i = 0; i < 8; i++)
				{
					bool newSwitch = (newSwitches & (1 << i)) != 0;
					bool oldSwitch = (switches & (1 << i)) != 0;
					if (newSwitch != oldSwitch)
					{
						char topic[]             = "cheri-switch/X";
						topic[sizeof(topic) - 2] = '0' + i;
						t                        = Timeout{MS_TO_TICKS(5000)};
						ret                      = mqtt_publish(&t,
						                                        handle,
						                                        0, // Don't want acks for this one
						                                        topic,
						                                        sizeof(topic) - 1,
                                           newSwitch ? "ON" : "OFF",
                                           newSwitch ? 2 : 3);
						if (ret < 0)
						{
							Debug::log(
							  "Failed to publish button change, error {}.",
							  ret);
							break;
						}
					}
				}
				switches = newSwitches;
			}

			// Check the button
			if (read_button(0) && !coolDown.remaining)
			{
				Debug::log("Publishing {} to button topic '{}'.",
				           buttonCounter,
				           buttonTopic);

				char num_char[20] = {0};
				snprintf(num_char, 20, "%lu", buttonCounter);

				t   = Timeout{MS_TO_TICKS(5000)};
				ret = mqtt_publish(&t,
				                   handle,
				                   0, // Don't want acks for this one
				                   buttonTopic,
				                   strlen(buttonTopic),
				                   static_cast<const void *>(num_char),
				                   strlen(num_char));

				if (ret < 0)
				{
					Debug::log("Failed to publish, error {}.", ret);
					break;
				}

				buttonCounter++;

				// Set cool down timer
				coolDown = Timeout{MS_TO_TICKS(500)};
				continue;
			}

			SystickReturn timestampAfter = thread_systemtick_get();
			// Timeouts should not overflow a 32 bit value
			coolDown.elapse(timestampAfter.lo - timestampBefore.lo);
		}
		Debug::log("Exiting main loop, cleaning up.");
		mqtt_disconnect(&t, STATIC_SEALED_VALUE(mqttTestMalloc), handle);
		// Sleep for a second to allow the network stack to clean up any
		// outstanding allocations
		Timeout oneSecond{MS_TO_TICKS(1000)};
		thread_sleep(&oneSecond);
	}
}
