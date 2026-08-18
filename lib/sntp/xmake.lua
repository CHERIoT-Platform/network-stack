library("time_helpers")
  set_default(false)
  add_includedirs("../../include")
  -- If this is a version of the RTOS that has the clock_helpers target, just
  -- use that instead of our versions.
  -- FIXME: This is transitional code and this library can be removed once all
  -- users have upgraded the RTOS version.
  after_load(function(target)
	  import("core.project.project")
	  local clock_helpers = project.target("clock_helpers")
	  if (clock_helpers) then
		  print("Adding dependency on clock_helpers compartment");
		  target:add("deps", "clock_helpers")
	  else
		  print("Did not find clock_helpers compartment")
	  end
  end)
  add_files("time-helpers.cc")

debugOption("SNTP")

compartment("SNTP")
  add_rules("cheriot.component-debug")
  set_default(false)
  add_deps("freestanding", "NetAPI", "randombytes")
  add_files("sntp.cc")
  add_includedirs(".", "../../include", "../../third_party/coreSNTP/source/include")
  add_cflags("-DCHERIOT_CUSTOM_DEFAULT_MALLOC_CAPABILITY")
  add_files("../../third_party/coreSNTP/source/core_sntp_client.c",
            "../../third_party/coreSNTP/source/core_sntp_serializer.c")
  -- If this is a version of the RTOS that has the wall_clock target, we want
  -- to add our interface to that and not expose the other interfaces.
  -- FIXME: This is transitional code and not required once all users have
  -- upgraded the RTOS version.
  after_load(function(target)
	  import("core.project.project")
	  local wall_clock = project.target("wall_clock")
	  if (wall_clock) then
		  print("Adding dependency on wall-clock compartment");
		  target:add("deps", "wall_clock")
		  wall_clock:add("includedirs", path.join(target:scriptdir(), "include"))
		  wall_clock:add("cheriot.clock_source_includes", "sntp_rtc.hh")
		  wall_clock:add("cheriot.clock_source_types", "SNTPWallClockSource")
	  else
		  print("Did not find wall-clock compartment")
	  end
  end)
  on_load(function(target)
    target:values_set("shared_objects", { sntp_time_at_last_sync = 24 }, {expand = false})
  end)

