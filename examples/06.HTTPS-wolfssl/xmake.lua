-- Copyright The Good Penguin Ltd
-- SPDX-License-Identifier: MIT

sdkdir = path.absolute("../../../cheriot-rtos/sdk")

set_project("CHERIoT wolfSSL HTTPS Example")

includes(sdkdir)
set_toolchains("cheriot-clang")
includes(path.join(sdkdir, "lib"))
includes("../../lib")

option("board")
  set_default("sonata-1.3")

compartment("https_wolfssl_example")
  add_includedirs("../../include")
  add_deps("freestanding", "DNS", "TCPIP", "NetAPI", "WolfSSLTLS", "Firewall", "SNTP", "time_helpers", "debug")
  add_files("https_wolfssl.cc")
  add_rules("cheriot.network-stack.ipv6")

firmware("06.https_wolfssl_example")
  set_policy("build.warning", true)
  add_deps("https_wolfssl_example")
  on_load(function(target)
    target:values_set("board", "$(board)")
    target:values_set("threads", {
      {
        compartment = "https_wolfssl_example",
        priority = 1,
        entry_point = "example",
        stack_size = 0x2000,
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
        priority = 2,
        entry_point = "ethernet_run_driver",
        stack_size = 0x1000,
        trusted_stack_frames = 5
      }
    }, {expand = false})
  end)
