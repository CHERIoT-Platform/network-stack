#!/bin/sh

if [ $# -eq 0 ] ; then
	echo Query required.  Try one of the following:
	echo Print all connection capabilities:
	echo -e \\tdata.network_stack.all_connection_capabilities
	echo Is the network stack configuration valid?
	echo -e "\\t'data.network_stack.valid(kunyan_ethernet)'"
	echo Print all allocator capabilities and their owners:
	echo -e "\\t'[ { \"owner\": owner, \"capability\": data.rtos.decode_allocator_capability(c) } | c = input.compartments[owner].imports[_] ; data.rtos.is_allocator_capability(c) ]'"
	echo Print all compartments that invoke functions in the JavaScript compartment:
	echo -e "\\t'data.compartment.compartments_calling(\"javascript\")'"
	echo Print all compartments that invoke functions in the allocator:
	echo -e "\\t'data.compartment.compartments_calling(\"allocator\")'"
	echo Print all compartments that have direct access to the LEDs / switches:
	echo -e "\\t'data.compartment.compartments_with_mmio_import(data.board.devices.gpio_led0)'"
else
	echo "cheriot-audit --board ibex-arty-a7-100.json --firmware-report cheritech-demo.json --module network_stack.rego --query \"$1\""
	cheriot-audit --board ibex-arty-a7-100.json --firmware-report cheritech-demo.json --module network_stack.rego --query "$1" | jq
fi

