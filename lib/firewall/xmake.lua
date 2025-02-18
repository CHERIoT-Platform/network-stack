option("network-force-non-unique-mac")
  set_default(false)
  set_showmenu(true)
  set_description("Use a static MAC address, even if it is not unique")

compartment("Firewall")
  add_includedirs("../../include")
  add_rules("cheriot.network-stack.ipv6")
  on_load(function(target)
    target:add('options', "network-force-non-unique-mac")
    local forceMAC = get_config("network-force-non-unique-mac")
    target:add("defines", "CHERIOT_RTOS_OPTION_FORCE_NON_UNIQUE_MAC=" .. tostring(forceMAC))
  end)
  --FIXME: The FreeRTOS compat headers need to work with this mode!
  --add_defines("CHERIOT_NO_AMBIENT_MALLOC", "CHERIOT_NO_NEW_DELETE")
  add_files("firewall.cc")

