debugOption("DNS")
compartment("DNS")
  add_rules("cheriot.component-debug")
  add_deps("unwind_error_handler", "randombytes")
  add_includedirs("../../include")
  add_rules("cheriot.network-stack.ipv6")
  add_files("dns.cc")

