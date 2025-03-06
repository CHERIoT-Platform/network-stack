debugOption("TCPIP")

option("network-inject-faults")
  set_default(false)
  set_showmenu(true)
  set_description("Inject network faults for testing")

compartment("TCPIP")
  add_rules("cheriot.component-debug")
  set_default(false)
  add_deps("freestanding", "string", "message_queue_library", "event_group", "cxxrt", "unwind_error_handler", "DNS")
  add_cflags("-Wno-error=int-conversion", "-Wno-error=cheri-provenance", "-Wno-error=pointer-integer-compare", { force = true})
  add_defines("CHERIOT_CUSTOM_DEFAULT_MALLOC_CAPABILITY")
  add_defines("CHERIOT_EXPOSE_FREERTOS_SEMAPHORE")
  add_defines("NDEBUG")
  on_load(function(target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
    target:add('options', "network-inject-faults")
    local injectFaults = get_config("network-inject-faults")
    target:add("defines", "CHERIOT_RTOS_OPTION_NETWORK_INJECT_FAULTS=" .. tostring(injectFaults))
    if (IPv6) then
      -- xmake's behaviour is inconsistent between add_files(...) and
      -- target:add("files", ...).  Fix the paths to behave as if they were added with add_files.
      function fix_path(p)
        return path.relative(path.absolute(path.join(os.scriptdir(), p)), os.projectdir())
      end
      target:add("files", {
              fix_path("../../third_party/freertos-plus-tcp/source/FreeRTOS_DHCPv6.c"),
              fix_path("../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_State_Handling_IPv6.c"),
              fix_path("../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_IP_IPv6.c"),
              fix_path("../../third_party/freertos-plus-tcp/source/FreeRTOS_IPv6.c"),
              fix_path("../../third_party/freertos-plus-tcp/source/FreeRTOS_IPv6_Sockets.c"),
              fix_path("../../third_party/freertos-plus-tcp/source/FreeRTOS_IPv6_Utils.c"),
              fix_path("../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Transmission_IPv6.c"),
              fix_path("../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Utils_IPv6.c"),
              fix_path("../../third_party/freertos-plus-tcp/source/FreeRTOS_UDP_IPv6.c")
      })
    end
  end)
  add_includedirs("../../include", ".", "../../third_party/freertos-plus-tcp/source/include")
  add_includedirs("../../third_party/freertos")
  -- If the SDK path is relative, it's relative to the working directory, not
  -- the script directory.  We need to adjust it to make sure that it points in
  -- the right place.
  if path.is_absolute(sdkdir) then
    add_includedirs(path.join(sdkdir, "include/FreeRTOS-Compat"))
  else
    add_includedirs(path.join("$(curdir)", sdkdir, "include/FreeRTOS-Compat"))
  end
  add_files("../../third_party/freertos/list.c")
  add_files("externs.c")
  add_files("FreeRTOS_IP_wrapper.c")
  add_files("BufferManagement.cc")
  add_files("driver_adaptor.cc")
  add_files("network_wrapper.cc")
  add_files("startup.cc")
  add_files(
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_BitConfig.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_DNS.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Callback.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Networking.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Parser.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_ICMP.c",
            -- Included via a wrapper that statically creates the thread.
            --"../../third_party/freertos-plus-tcp/source/FreeRTOS_DNS_Cache.c",
            --"../../third_party/freertos-plus-tcp/source/FreeRTOS_ARP.c",
            --"../../third_party/freertos-plus-tcp/source/FreeRTOS_DHCP.c",
            --"../../third_party/freertos-plus-tcp/source/FreeRTOS_IP.c",
            --"../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_IP.c",
            --"../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_WIN.c",
            --"../../third_party/freertos-plus-tcp/source/FreeRTOS_IP_Timers.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_IP_Utils.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_IPv4.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_IPv4_Sockets.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_IPv4_Utils.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_ND.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_RA.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_Routing.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_Sockets.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_Stream_Buffer.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_IP_IPv4.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Reception.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_State_Handling.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_State_Handling_IPv4.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Transmission.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Transmission_IPv4.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Utils.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_TCP_Utils_IPv4.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_Tiny_TCP.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_UDP_IP.c",
            "../../third_party/freertos-plus-tcp/source/FreeRTOS_UDP_IPv4.c"
            )
