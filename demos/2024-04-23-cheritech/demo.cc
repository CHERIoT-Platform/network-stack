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
#include "microvium-ffi.h"

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

	std::unique_ptr<mvm_VM, MVMDeleter> vm;
	std::vector<uint8_t>                bytecode;

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
	                                      const void *payload,
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
			Debug::log("Received new JavaScript code.");
			vm.reset();
			bytecode.clear();
			bytecode.reserve(payloadLength);
			bytecode.insert(bytecode.end(),
			                static_cast<const uint8_t *>(payload),
			                static_cast<const uint8_t *>(payload) +
			                  payloadLength);
			Debug::log("Copied JavaScript bytecode");
			mvm_VM *rawVm;
			auto    err = mvm_restore(
			     &rawVm,            /* Out pointer to the VM */
			     bytecode.data(),   /* Bytecode data */
			     bytecode.size(),   /* Bytecode length */
			     MALLOC_CAPABILITY, /* Capability used to allocate memory */
			     ::resolve_import); /* Callback used to resolve FFI imports */
			if (err == MVM_E_SUCCESS)
			{
				Debug::log("Successfully loaded bytecode.");
				vm.reset(rawVm);
			}
			else
			{
				// If this is not valid bytecode, give up.
				Debug::log("Failed to parse bytecode: {}", err);
			}
			// Don't try to handle the new-code message in JavaScript.
			return;
		}

		if (!vm)
		{
			return;
		}

		mvm_Value callback;
		if (mvm_resolveExports(vm.get(), &ExportPublished, &callback, 1) ==
		    MVM_E_SUCCESS)
		{
			mvm_Value args[2];
			args[0] = mvm_newString(vm.get(), topicName, topicNameLength);
			args[1] = mvm_newString(
			  vm.get(), static_cast<const char *>(payload), payloadLength);
			// Set a limit of bytecodes to execute, to prevent infinite loops.
			mvm_stopAfterNInstructions(vm.get(), 20000);
			// Call the function:
			int err = mvm_call(vm.get(), callback, nullptr, args, 2);
			if (err != MVM_E_SUCCESS)
			{
				Debug::log("Failed to call publish callback function: {}", err);
			}
		}
	}

	/// Handle to the MQTT connection.
	SObj handle;

	bool export_mqtt_publish(std::string_view topic, std::string_view message)
	{
		Timeout t{UnlimitedTimeout};
		Debug::log("Publishing message to topic '{}' ({}): '{}' ({})",
		           topic,
		           topic.size(),
		           message,
		           message.size());
		auto ret = mqtt_publish(&t,
		                        handle,
		                        0, // Don't want acks for this one
		                        topic.data(),
		                        topic.size(),
		                        message.data(),
		                        message.size());
		Debug::log("Publish returned {}", ret);
		return ret == 0;
	}

	bool export_mqtt_subscribe(std::string_view topic)
	{
		Timeout t{MS_TO_TICKS(100)};
		auto    ret = mqtt_subscribe(&t, handle, 1, topic.data(), topic.size());
		return ret >= 0;
	}

} // namespace

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
		vm.reset();
		bytecode.clear();
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

		Timeout coolDown{0};
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

			if (!vm)
			{
				continue;
			}

			mvm_Value callback;
			if (mvm_resolveExports(vm.get(), &ExportTick, &callback, 1) ==
			    MVM_E_SUCCESS)
			{
				// Set a limit of bytecodes to execute, to prevent infinite
				// loops.
				mvm_stopAfterNInstructions(vm.get(), 20000);
				// Call the function:
				int err = mvm_call(vm.get(), callback, nullptr, nullptr, 0);
				if (err != MVM_E_SUCCESS)
				{
					Debug::log("Failed to call tick callback function: {}",
					           err);
				}
			}
		}
		Debug::log("Exiting main loop, cleaning up.");
		mqtt_disconnect(&t, STATIC_SEALED_VALUE(mqttTestMalloc), handle);
		// Sleep for a second to allow the network stack to clean up any
		// outstanding allocations
		Timeout oneSecond{MS_TO_TICKS(1000)};
		thread_sleep(&oneSecond);
	}
}
