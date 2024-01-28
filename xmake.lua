-- Copyright Microsoft and CHERIoT Contributors.
-- SPDX-License-Identifier: MIT

sdkdir = "../cheriot-rtos/sdk"

set_project("CHERIoT Network Stack Example")
includes(sdkdir)
set_toolchains("cheriot-clang")

option("board")
    set_default("ibex-arty-a7-100")

option("IPv6")
    set_default(true)
    set_showmenu(true)

function include_lib(lib)
	includes(path.join(sdkdir, "lib/" .. lib))
end

includes(path.join(sdkdir, "lib"))

library("time_helpers")
  add_files("time-helpers.cc")

compartment("Firewall")
  add_includedirs(".", "third_party/freertos-plus-tcp/source/include")
  add_includedirs("third_party/freertos")
  add_includedirs(path.join(sdkdir, "include/FreeRTOS-Compat"))
  --FIXME: The FreeRTOS compat headers need to work with this mode!
  --add_defines("CHERIOT_NO_AMBIENT_MALLOC", "CHERIOT_NO_NEW_DELETE")
  add_files("firewall.cc")

compartment("TCPIP")
  set_default(false)
  add_deps("freestanding", "string", "message_queue_library", "event_group", "stdio", "cxxrt")
  add_cflags("-Wno-error=int-conversion", "-Wno-error=cheri-provenance", "-Wno-error=pointer-integer-compare", { force = true})
  add_defines("CHERIOT_CUSTOM_DEFAULT_MALLOC_CAPABILITY")
  add_defines("CHERIOT_EXPOSE_FREERTOS_SEMAPHORE")
  on_load(function(target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
    target:add("files", {
            "third_party/freertos-plus-tcp/source/FreeRTOS_DHCPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_State_Handling_IPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_IP_IPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv6_Sockets.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv6_Utils.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Transmission_IPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Utils_IPv6.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_UDP_IPv6.c"
    })
  end)
  add_includedirs(".", "third_party/freertos-plus-tcp/source/include")
  add_includedirs("third_party/freertos")
  add_includedirs(path.join(sdkdir, "include/FreeRTOS-Compat"))
  add_files("third_party/freertos/list.c")
  add_files("externs.c")
  add_files("FreeRTOS_IP_wrapper.c")
  add_files("BufferManagement.cc")
  add_files("driver_adaptor.cc")
  add_files("network_wrapper.cc")
  add_files("startup.cc")
  add_files(
            "third_party/freertos-plus-tcp/source/FreeRTOS_ARP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_BitConfig.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DHCP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DNS.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Cache.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Callback.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Networking.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Parser.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_ICMP.c",
            -- Included via a wrapper that statically creates the thread.
            --"third_party/freertos-plus-tcp/source/FreeRTOS_IP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IP_Timers.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IP_Utils.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv4.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv4_Sockets.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_IPv4_Utils.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_ND.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_RA.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_Routing.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_Sockets.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_Stream_Buffer.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_IP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_IP_IPv4.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Reception.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_State_Handling.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_State_Handling_IPv4.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Transmission.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Transmission_IPv4.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Utils.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Utils_IPv4.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_TCP_WIN.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_Tiny_TCP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_UDP_IP.c",
            "third_party/freertos-plus-tcp/source/FreeRTOS_UDP_IPv4.c"
            )

compartment("NetAPI")
  set_default(false)
  add_deps("freestanding", "TCPIP")
  add_files("NetAPI.cc")
  on_load(function(target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
  end)

compartment("SNTP")
  set_default(false)
  add_deps("freestanding", "NetAPI")
  add_files("sntp.cc")
  add_includedirs(".", "third_party/coreSNTP/source/include")
  add_defines("CHERIOT_CUSTOM_DEFAULT_MALLOC_CAPABILITY")
  add_files("third_party/coreSNTP/source/core_sntp_client.c",
            "third_party/coreSNTP/source/core_sntp_serializer.c")

compartment("test")
  set_default(false)
  add_deps("freestanding", "TCPIP", "NetAPI")
  add_files("test.cc")
  on_load(function(target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
  end)

firmware("toy_network")
    set_policy("build.warning", true)
    add_deps("TCPIP", "Firewall", "NetAPI", "SNTP", "test", "atomic8", "time_helpers", "debug")
    on_load(function(target)
        target:values_set("board", "$(board)")
        target:values_set("threads", {
            {
                compartment = "test",
                priority = 1,
                entry_point = "test_network",
                stack_size = 0xe00,
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

