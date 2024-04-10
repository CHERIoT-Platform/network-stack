// FFI Imports
// Each function imported from the host environment needs to be assigned to a
// global like this and identified by a constant that the resolver in the C/C++
// code will understand.
// These constants are defined in the `Exports` enumeration.


var FFINumber = 1;

/**
 * Log function, writes all arguments to the UART.
 */
export const print = vmImport(FFINumber++);

/**
 * led_on(index).
 *
 * Turns on the LED at the specified index.
 */
export const led_on = vmImport(FFINumber++);

/**
 * led_off(index).
 *
 * Turns off the LED at the specified index.
 */
export const led_off = vmImport(FFINumber++);

/**
 * buttons_read().
 *
 * Reads the value of all of the buttons, returning a 4-bit value indicating
 * the states of all of them.
 */
export const buttons_read = vmImport(FFINumber++);

/**
 * switches_read().
 *
 * Reads the value of all of the switches, returning a 4-bit value indicating
 * the states of all of them.
 */
export const switches_read = vmImport(FFINumber++);


export const mqtt_publish = vmImport(FFINumber++);
export const mqtt_subscribe = vmImport(FFINumber++);

/**
 * led_set(index, state).
 *
 * Turns the LED at the specified index on or off depending on whether state is
 * true or false.
 */
export function led_set(index, state)
{
	if (state)
	{
		led_on(index);
	}
	else
	{
		led_off(index);
	}
}

/**
 * button_read(index).
 *
 * Reads the value of the button at the specified index.
 */
export function button_read(index)
{
	return (buttons_read() & (1 << index)) !== 0;
}


/**
 * switch_read(index).
 *
 * Reads the value of the switch at the specified index.
 */
export function switch_read(index)
{
	return (switches_read() & (1 << index)) !== 0;
}

