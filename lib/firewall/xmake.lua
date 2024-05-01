
compartment("Firewall")
  add_includedirs("../../include")
  on_load(function(target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
  end)
  --FIXME: The FreeRTOS compat headers need to work with this mode!
  --add_defines("CHERIOT_NO_AMBIENT_MALLOC", "CHERIOT_NO_NEW_DELETE")
  add_files("firewall.cc")

