compartment("DNS")
  add_deps("unwind_error_handler")
  add_includedirs("../../include")
  add_rules("cheriot.network-stack.ipv6")
  add_files("dns.cc")

