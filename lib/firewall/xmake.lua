
compartment("Firewall")
  add_includedirs("../../include")
  --FIXME: The FreeRTOS compat headers need to work with this mode!
  --add_defines("CHERIOT_NO_AMBIENT_MALLOC", "CHERIOT_NO_NEW_DELETE")
  add_files("firewall.cc")

