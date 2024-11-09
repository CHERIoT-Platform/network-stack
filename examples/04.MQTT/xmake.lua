-- Copyright SCI Semiconductor and CHERIoT Contributors.
-- SPDX-License-Identifier: MIT

-- Update this to point to the location of the CHERIoT SDK
sdkdir = path.absolute("../../../cheriot-rtos/sdk")

set_project("CHERIoT MQTT Example")

includes(sdkdir)

set_toolchains("cheriot-clang")

includes(path.join(sdkdir, "lib"))
includes("../../lib")

option("board")
  set_default("ibex-arty-a7-100")

compartment("mqtt_example")
  add_includedirs("../../include")
  add_deps("freestanding", "DNS", "TCPIP", "NetAPI", "TLS", "Firewall", "SNTP", "MQTT", "time_helpers", "debug")
  -- stdio only needed for debug prints in MQTT, can be removed with --debug-mqtt=n
  add_deps("stdio")
  add_files("mqtt.cc")
  on_load(function(target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
  end)

firmware("04.mqtt_example")
  set_policy("build.warning", true)
  add_deps("mqtt_example")
  add_options("tls-rsa")
  on_load(function(target)
    target:values_set("board", "$(board)")
    target:values_set("threads", {
      {
        compartment = "mqtt_example",
        priority = 1,
        entry_point = "example",
        -- TLS requires *huge* stacks!
        stack_size = 8160,
        trusted_stack_frames = 6
      },
      {
        -- TCP/IP stack thread.
        compartment = "TCPIP",
        priority = 1,
        entry_point = "ip_thread_entry",
        stack_size = 0xe00,
        trusted_stack_frames = 5
      },
      {
        -- Firewall thread, handles incoming packets as they arrive.
        compartment = "Firewall",
        -- Higher priority, this will be back-pressured by the message
        -- queue if the network stack can't keep up, but we want
        -- packets to arrive immediately.
        priority = 2,
        entry_point = "ethernet_run_driver",
        stack_size = 0x1000,
        trusted_stack_frames = 5
      }
    }, {expand = false})
  end)

