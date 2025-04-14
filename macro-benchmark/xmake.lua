-- Copyright SCI Semiconductor and CHERIoT Contributors.
-- SPDX-License-Identifier: MIT

-- Update this to point to the location of the CHERIoT SDK
sdkdir = path.absolute("../../cheriot-rtos/sdk")

set_project("CHERIoT macrobenchmark")

includes(sdkdir)

set_toolchains("cheriot-clang")

includes(path.join(sdkdir, "lib"))
includes("../lib")

option("board")
  set_default("ibex-arty-a7-100")

compartment("macrobenchmark")
  set_default(false)
  add_includedirs("../include")
  add_deps("freestanding", "TCPIP", "NetAPI", "TLS", "Firewall", "SNTP", "MQTT", "time_helpers", "debug", "microvium")
  add_files("macrobenchmark.cc")
  on_load(function(target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    -- IPv6 disabled in the macrobenchmark.
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=n")
  end)

firmware("macrobenchmark-firmware")
  set_policy("build.warning", true)
  add_deps("macrobenchmark")
  add_options("tls-rsa")
  on_load(function(target)
    target:values_set("board", "$(board)")
    target:values_set("threads", {
      {
        compartment = "macrobenchmark",
        priority = 1,
        entry_point = "macrobenchmark",
        -- TLS requires *huge* stacks!
        stack_size = 8160,
        trusted_stack_frames = 7
      },
      {
        compartment = "macrobenchmark",
        priority = 1,
        entry_point = "cpu_clock",
        stack_size = 0x200,
        trusted_stack_frames = 2
      },
      {
        -- TCP/IP stack thread.
        compartment = "TCPIP",
        priority = 1,
        entry_point = "ip_thread_entry",
        stack_size = 0x1000,
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
