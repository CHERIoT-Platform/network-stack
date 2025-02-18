option("IPv6")
    set_default(true)
    set_showmenu(true)

rule("cheriot.network-stack.ipv6")
  on_load(function (target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
  end)

includes("tcpip",
         "netapi",
         "sntp",
         "mqtt",
         "tls",
         "dns",
         "firewall")

