// FFI Imports
// Each function imported from the host environment needs to be assigned to a
// global like this and identified by a constant that the resolver in the C/C++
// code will understand.
// These constants are defined in the `Exports` enumeration.
var FFINumber = 1;

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

function callback()
{
	led_on();
}

// FFI exports.  Each function that we export needs to be assigned a unique
// number that can be used to look it up.
vmExport(1234, callback);
