library("time_helpers")
  set_default(false)
  add_includedirs("../../include")
  add_files("time-helpers.cc")

debugOption("SNTP")

compartment("SNTP")
  add_rules("cheriot.component-debug")
  set_default(false)
  add_deps("freestanding", "NetAPI")
  add_files("sntp.cc")
  add_includedirs(".", "../../include", "../../third_party/coreSNTP/source/include")
  add_cflags("-DCHERIOT_CUSTOM_DEFAULT_MALLOC_CAPABILITY")
  add_files("../../third_party/coreSNTP/source/core_sntp_client.c",
            "../../third_party/coreSNTP/source/core_sntp_serializer.c")
  on_load(function(target)
    target:values_set("shared_objects", { sntp_time_at_last_sync = 24 }, {expand = false})
  end)

