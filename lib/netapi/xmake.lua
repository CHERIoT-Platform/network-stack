compartment("NetAPI")
  set_default(false)
  add_includedirs("../../include")
  add_deps("freestanding", "TCPIP")
  add_files("NetAPI.cc")
  add_defines("CHERIOT_NO_AMBIENT_MALLOC")
  add_rules("cheriot.network-stack.ipv6")

