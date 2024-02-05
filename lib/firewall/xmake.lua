
compartment("Firewall")
  add_includedirs("../../include", "third_party/freertos-plus-tcp/source/include")
  add_includedirs("third_party/freertos")
  add_includedirs(path.join(sdkdir, "include/FreeRTOS-Compat"))
  --FIXME: The FreeRTOS compat headers need to work with this mode!
  --add_defines("CHERIOT_NO_AMBIENT_MALLOC", "CHERIOT_NO_NEW_DELETE")
  add_files("firewall.cc")

