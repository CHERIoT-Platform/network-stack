-- Copyright CHERIoT Contributors.
-- SPDX-License-Identifier: MIT

-- Update this to point to the location of the CHERIoT SDK
sdkdir = path.absolute("../../../cheriot-rtos/sdk")

set_project("CHERIoT HTTP Example")

includes(sdkdir)

set_toolchains("cheriot-clang")

includes(path.join(sdkdir, "lib"))
includes("../../lib")

option("board")
  set_default("ibex-arty-a7-100")

compartment("https_example")
  add_includedirs("../../include")
  add_deps("freestanding", "DNS", "TCPIP", "NetAPI", "TLS", "Firewall", "SNTP", "time_helpers", "debug")
  add_files("https.cc")
  on_load(function(target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
  end)

firmware("03.https_example")
  set_policy("build.warning", true)
  add_deps("https_example")
  on_load(function(target)
    target:values_set("board", "$(board)")
    target:values_set("threads", {
      {
        compartment = "https_example",
        priority = 1,
        entry_point = "example",
        -- TLS requires *huge* stacks!
        stack_size = 8160,
        trusted_stack_frames = 6
      },
      {
        compartment = "TCPIP",
        priority = 1,
        entry_point = "ip_thread_entry",
        stack_size = 0xe00,
        trusted_stack_frames = 5
      },
      {
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

