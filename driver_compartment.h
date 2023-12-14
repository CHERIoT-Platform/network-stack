#include <compartment.h>

/**
 * Send a frame through the on-device firewall.  This returns true if the
 * packet is successfully sent, false otherwise.
 */
bool __cheri_compartment("Ethernet")
  ethernet_send_frame(uint8_t *packet, size_t length);

/**
 * Start the Ethernet driver.  This returns true if the driver is successfully
 * started, false otherwise.  This should fail only if the driver is already
 * initialised.
 */
bool __cheri_compartment("Ethernet") ethernet_driver_start(void);

/**
 * Query the link status of the Ethernet driver.  This returns true if the link
 * is up, false otherwise.
 */
bool __cheri_compartment("Ethernet") ethernet_link_is_up(void);

/**
 * Receive a frame from the Ethernet device via the on-device firewall.
 */
bool __cheri_compartment("TCPIP")
  ethernet_receive_frame(uint8_t *packet, size_t length);
