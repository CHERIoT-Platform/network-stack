# Copyright SCI Semiconductor and CHERIoT Contributors.
# SPDX-License-Identifier: MIT

package network_stack

import future.keywords.every

connection_types = ["TCP", "UDP"]

# Evaluates to true if this is a connection capability.  This does not check
# whether it is a *valid* connection capability, only that it is a sealed
# object of the correct kind.
is_connection_capability(connection) {
	connection.kind == "SealedObject"
	connection.sealing_type.compartment == "NetAPI"
	connection.sealing_type.key == "NetworkConnectionKey"
}

# Check that this is a valid connection capability and, if so, decode its
# contents.  Returns an object with the connection type ("TCP" or "UDP"), the
# port, and the host.
decode_connection_capability(connection) = decoded {
	is_connection_capability(connection)
	#some port
	port = integer_from_hex_string(connection.contents, 2, 2)
	is_number(port)
	some connectionType
	connectionType = integer_from_hex_string(connection.contents, 0, 1)
	is_number(connectionType)
	connectionType < 2
	connectionType >= 0
	# Padding byte must be zero 
	integer_from_hex_string(connection.contents, 1, 1) == 0

	some hostLength
	hostLength = integer_from_hex_string(connection.contents, 4, 4)
	some host
	host = string_from_hex_string(connection.contents, 8)
	count(host)+1 == hostLength

	decoded = {
		"port": port,
		"connection_type":  connection_types[connectionType],
		"host": host
	}
}

# Predicate that checks that every connection capability held by any
# compartment or library is valid.
all_sealed_connection_capabilities_are_valid {
	some connections
	connections = [ c | c = input.compartments[_].imports[_] ; is_connection_capability(c) ]
	every c in connections {
		decode_connection_capability(c)
	}
}

is_firewall_thread(thread) {
	thread.entry_point.compartment_name == "Firewall"
	thread.entry_point.function == "ethernet_run_driver()"
}

firewall_thread_is_valid {
	some thread
	thread = [ t | t=input.threads[_] ; is_firewall_thread(t) ]
	count(thread) == 1
	# FIXME: Work out what the minimum requirement actually is for these:
	thread[0].stack.length >= 1024
	thread[0].trusted_stack.length >= 312
}

is_network_thread(thread) {
	thread.entry_point.compartment_name == "TCPIP"
	thread.entry_point.function == "ip_thread_entry()"
}

network_thread_is_valid {
	some thread
	thread = [ t | t=input.threads[_] ; is_network_thread(t) ]
	count(thread) == 1
	# FIXME: Work out what the minimum requirement actually is for these:
	thread[0].stack.length >= 1024
	thread[0].trusted_stack.length >= 312
}

# Helper to dump all connection capabilities and the compartment that owns them
all_connection_capabilities = [ { "owner": owner, "capability": decode_connection_capability(c) } | c = input.compartments[owner].imports[_] ; is_connection_capability(c) ]

# The internal configuration for the network interface is valid.  The parameter
# is the name of the network device.  For example, "kunyan_ethernet" on the
# Arty A7.
valid(ethernetDevice) {
	all_sealed_connection_capabilities_are_valid
	firewall_thread_is_valid
	network_thread_is_valid
	data.compartment.compartment_call_allow_list("TCPIP", "network_host_resolve.*", {"NetAPI"})
	data.compartment.compartment_call_allow_list("TCPIP", "network_socket_create_and_bind.*", {"NetAPI"})
	data.compartment.compartment_call_allow_list("TCPIP", "network_socket_connect_tcp_internal.*", {"NetAPI"})
	data.compartment.compartment_call_allow_list("TCPIP", "ethernet_receive_frame.*", {"Firewall"})
	data.compartment.compartment_call_allow_list("TCPIP", "ip_thread_entry.*", set())
	data.compartment.compartment_call_allow_list("Firewall", "ethernet_send_frame.*", {"TCPIP"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_dns_server_ip_set.*", {"TCPIP"})
	data.compartment.compartment_call_allow_list("Firewall", "ethernet_driver_start.*", {"TCPIP"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_permit_dns.*", {"NetAPI"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_add_tcpipv4_endpoint.*", {"NetAPI"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_add_udpipv4_endpoint.*", {"NetAPI"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_remove_tcpipv4_endpoint.*", {"NetAPI", "TCPIP"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_remove_udpipv4_local_endpoint.*", {"NetAPI", "TCPIP"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_remove_udpipv4_remote_endpoint.*", {"NetAPI"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_add_tcpipv6_endpoint.*", {"NetAPI"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_add_udpipv6_endpoint.*", {"NetAPI"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_remove_tcpipv6_endpoint.*", {"NetAPI", "TCPIP"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_remove_udpipv6_local_endpoint.*", {"NetAPI", "TCPIP"})
	data.compartment.compartment_call_allow_list("Firewall", "firewall_remove_udpipv6_remote_endpoint.*", {"NetAPI"})
	data.compartment.compartment_call_allow_list("Firewall", "ethernet_run_driver.*", set())
	data.compartment.mmio_allow_list(ethernetDevice, {"Firewall"})
	# SNTP cache is the right size and is writeable only by the sntp compartment
	data.compartment.shared_object_writeable_allow_list("sntp_time_at_last_sync", {"SNTP"})
	some sntpCache
	sntpCache = data.compartment.shared_object("sntp_time_at_last_sync")
	sntpCache.end - sntpCache.start = 24
}


