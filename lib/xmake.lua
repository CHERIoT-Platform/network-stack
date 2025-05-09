local netstackdir = os.scriptdir()

option("IPv6")
    set_default(true)
    set_showmenu(true)

rule("cheriot.network-stack.ipv6")
  on_load(function (target)
    target:add('options', "IPv6")
    local IPv6 = get_config("IPv6")
    target:add("defines", "CHERIOT_RTOS_OPTION_IPv6=" .. tostring(IPv6))
  end)

-- Rule for making network stack git revision information available to a build target.
--
-- See the RTOS's cheriot.define-rtos-git-description rule for details.
local netstack_git_description = nil
rule("cheriot.define-network-git-description")
	before_build_file(function(target, sourcefile, opt)
		netstack_git_description = netstack_git_description or try {
			function()
				return os.iorunv("git", {"-C", netstackdir, "describe", "--always", "--dirty"}):gsub("[\r\n]", "")
			end
		}
		netstack_git_description = netstack_git_description or "unknown"

		local fileconfig = target:fileconfig(sourcefile) or {}
		fileconfig.defines = fileconfig.defines or {}
		table.insert(fileconfig.defines, ("CHERIOT_NETWORK_GIT_DESCRIPTION=%q"):format(netstack_git_description))
		target:fileconfig_set(sourcefile, fileconfig)
	end)

includes("tcpip",
         "netapi",
         "sntp",
         "mqtt",
         "tls",
         "dns",
         "firewall")

