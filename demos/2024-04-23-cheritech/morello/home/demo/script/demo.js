import * as host from "./cheri.js"

var ticks = 0
var switches = 0

/**
 * Subscribe to a topic, print to the UART whether the subscription was
 * successful.
 */
function subscribe(topic)
{
	var ret = host.mqtt_subscribe(topic)
	host.print("Subscribe ", topic, " returned: ", ret)
	if (ret)
	{
		host.print("Subscribed to", topic)
	}
	else
	{
		host.print("Failed to subscribe to ", topic)
	}
}

/**
 * On first run, subscribe to the switch topics.
 */
function first_run()
{
	subscribe("cheri-switch-0")
	subscribe("cheri-switch-1")
}

/**
 * Tick function, called every 100ms (roughly).
 */
function tick()
{
	if (ticks === 0)
	{
		first_run();
	}
	ticks++
	// If we're not a lightswitch, don't do anything else.
	if (host.switch_read(3))
	{
		return;
	}
	// If we're not a lightbulb, make sure the lights are out
	host.led_off(0)
	host.led_off(1)
	// Uncomment the next block to validate that the tick callback is being called.
	/*
	if (ticks % 5 === 0)
	{
		host.print("tick: ", ticks)
	}
	*/
	var new_switches = host.switches_read()
	if (new_switches !== switches)
	{
		for (var i = 0 ; i < 2 ; i++)
		{
			if ((new_switches & (1 << i)) !== (switches & (1 << i)))
			{
				host.print("Switch ", i, " changed to ", (new_switches & (1 << i)) ? "on" : "off")
				host.mqtt_publish("cheri-switch-" + i, (new_switches & (1 << i)) ? "on" : "off")
			}
		}
		switches = new_switches
	}
}

/**
 * Publish notification callback, called whenever a new publish message is
 * received from the MQTT broker.
 */
function message(topic, message)
{
	host.print("Received message on topic: ", topic, " message: ", message)
	var switchNumber = -1
	// If we're not a lightbulb, don't do anything else.
	if (!host.switch_read(3))
	{
		return;
	}
	if (topic === "cheri-switch-0")
	{
		switchNumber = 0
	}
	else if (topic === "cheri-switch-1")
	{
		switchNumber = 1
	}
	else
	{
		return
	}
	if (message === "on")
	{
		host.led_on(switchNumber)
	}
	else
	{
		host.led_off(switchNumber)
	}
}

vmExport(1234, tick);
vmExport(1235, message);
