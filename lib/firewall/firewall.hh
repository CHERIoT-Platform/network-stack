// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include <atomic>
#include <compartment.h>

/**
 * Send a frame through the on-device firewall.  This returns true if the
 * packet is successfully sent, false otherwise.
 */
bool __cheri_compartment("Firewall")
  ethernet_send_frame(uint8_t *packet, size_t length);

/**
 * Start the Firewall driver.
 *
 * `state` should point to the reset state of the TCP/IP stack.
 *
 * This returns true if the driver is successfully started, false otherwise.
 * This should fail only if the driver is already initialised (outside of a
 * reset), or if `state` is invalid.
 */
bool __cheri_compartment("Firewall")
  ethernet_driver_start(std::atomic<uint8_t> *state);

/**
 * Bit of the `state` atomic variable passed to `ethernet_driver_start` which
 * indicates that the driver may send packets to the network stack.
 *
 * This must match the `DriverKicked` bit of enum `RestartState` (see
 * `tcpip-internal.h`). This is statically asserted in the TCP/IP stack.
 */
static constexpr uint32_t RestartStateDriverKickedBit = 0x4;

/**
 * Query the link status of the Firewall driver.  This returns true if the link
 * is up, false otherwise.
 */
bool __cheri_compartment("Firewall") ethernet_link_is_up();

/**
 * Receive a frame from the Firewall device via the on-device firewall.
 */
bool __cheri_compartment("TCPIP")
  ethernet_receive_frame(uint8_t *packet, size_t length);

/**
 * Set the IP address of the DNS server to use.  Packets to and from this
 * address will be permitted by the firewall while DNS queries are in progress.
 */
void __cheri_compartment("Firewall") firewall_dns_server_ip_set(uint32_t ip);

/**
 * Toggle whether DNS is permitted.  This is used to open a hole in the
 * firewall to the DNS server for the duration of name lookup.
 *
 * This should be called only by the NetAPI compartment.
 */
void __cheri_compartment("Firewall")
  firewall_permit_dns(bool dnsIsPermitted = true);

/**
 * Open a hole in the firewall for TCP packets to and from the given endpoint.
 * This permits inbound packets to, and outbound packets from, the specified
 * local port, if the remote endpoint is the given remote address and port.
 *
 * This should be called only by the NetAPI compartment.
 */
void __cheri_compartment("Firewall")
  firewall_add_tcpipv4_endpoint(uint32_t remoteAddress,
                                uint16_t localPort,
                                uint16_t remotePort);

/**
 * Open a hole in the firewall for UDP packets to and from the given endpoint.
 * This permits inbound packets to, and outbound packets from, the specified
 * local port, if the remote endpoint is the given remote address and port.
 *
 * This should be called only by the NetAPI compartment.
 */
void __cheri_compartment("Firewall")
  firewall_add_udpipv4_endpoint(uint32_t remoteAddress,
                                uint16_t localPort,
                                uint16_t remotePort);

/**
 * Close a hole in the firewall for TCP packets to and from the given endpoint.
 *
 * This is called from the TCP/IP compartment when a TCP connection is closed.
 * This is not a security risk, the worst that the TCP/IP compartment can do by
 * calling it is DoS itself.  There is limited risk that it would fail to call
 * it when a connection should be closed.
 */
void __cheri_compartment("Firewall")
  firewall_remove_tcpipv4_endpoint(uint16_t localPort);

/**
 * Close a hole in the firewall for UDP packets to and from the given endpoint.
 *
 * This is called from the TCP/IP compartment when a TCP connection is closed.
 * This is not a security risk, the worst that the TCP/IP compartment can do by
 * calling it is DoS itself.  There is limited risk that it would fail to call
 * it when a connection should be closed.
 */
void __cheri_compartment("Firewall")
  firewall_remove_udpipv4_local_endpoint(uint16_t endpoint);

/**
 * Remove a specific remote UDP endpoint from the firewall.
 */
void __cheri_compartment("Firewall")
  firewall_remove_udpipv4_remote_endpoint(uint32_t remoteAddress,
                                          uint16_t localPort,
                                          uint16_t remotePort);

#if CHERIOT_RTOS_OPTION_IPv6
/**
 * Open a hole in the firewall for TCP packets to and from the given endpoint.
 * This permits inbound packets to, and outbound packets from, the specified
 * local port, if the remote endpoint is the given remote address and port.
 *
 * This should be called only by the NetAPI compartment.
 */
void __cheri_compartment("Firewall")
  firewall_add_tcpipv6_endpoint(uint8_t *remoteAddress,
                                uint16_t localPort,
                                uint16_t remotePort);

/**
 * Open a hole in the firewall for UDP packets to and from the given endpoint.
 * This permits inbound packets to, and outbound packets from, the specified
 * local port, if the remote endpoint is the given remote address and port.
 *
 * This should be called only by the NetAPI compartment.
 */
void __cheri_compartment("Firewall")
  firewall_add_udpipv6_endpoint(uint8_t *remoteAddress,
                                uint16_t localPort,
                                uint16_t remotePort);

/**
 * Close a hole in the firewall for TCP packets to and from the given endpoint.
 *
 * This is called from the TCP/IP compartment when a TCP connection is closed.
 * This is not a security risk, the worst that the TCP/IP compartment can do by
 * calling it is DoS itself.  There is limited risk that it would fail to call
 * it when a connection should be closed.
 */
void __cheri_compartment("Firewall")
  firewall_remove_tcpipv6_endpoint(uint16_t localPort);

/**
 * Close a hole in the firewall for UDP packets to and from the given endpoint.
 *
 * This is called from the TCP/IP compartment when a TCP connection is closed.
 * This is not a security risk, the worst that the TCP/IP compartment can do by
 * calling it is DoS itself.  There is limited risk that it would fail to call
 * it when a connection should be closed.
 */
void __cheri_compartment("Firewall")
  firewall_remove_udpipv6_local_endpoint(uint16_t endpoint);

/**
 * Remove a specific remote UDP endpoint from the firewall.
 */
void __cheri_compartment("Firewall")
  firewall_remove_udpipv6_remote_endpoint(uint8_t *remoteAddress,
                                          uint16_t localPort,
                                          uint16_t remotePort);
#else
__always_inline static inline void
firewall_add_tcpipv6_endpoint(uint8_t *remoteAddress,
                              uint16_t localPort,
                              uint16_t remotePort)
{
	Debug::Assert(
	  false, "{} not supported with IPv6 disabled", __PRETTY_FUNCTION__);
}
__always_inline static inline void
firewall_add_udpipv6_endpoint(uint8_t *remoteAddress,
                              uint16_t localPort,
                              uint16_t remotePort)
{
	Debug::Assert(
	  false, "{} not supported with IPv6 disabled", __PRETTY_FUNCTION__);
}

__always_inline static inline void
firewall_remove_tcpipv6_endpoint(uint16_t localPort)
{
	Debug::Assert(
	  false, "{} not supported with IPv6 disabled", __PRETTY_FUNCTION__);
}
__always_inline static inline void
firewall_remove_udpipv6_local_endpoint(uint16_t endpoint)
{
	Debug::Assert(
	  false, "{} not supported with IPv6 disabled", __PRETTY_FUNCTION__);
}

__always_inline static inline void
firewall_remove_udpipv6_remote_endpoint(uint8_t *remoteAddress,
                                        uint16_t localPort,
                                        uint16_t remotePort)
{
	Debug::Assert(
	  false, "{} not supported with IPv6 disabled", __PRETTY_FUNCTION__);
}
#endif

/**
 * Get the MAC address of the ethernet device.
 *
 * Returns a read-only capability to the MAC address.
 */
uint8_t *__cheri_compartment("Firewall") firewall_mac_address_get();
