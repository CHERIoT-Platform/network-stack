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
 * Each new TCP connection to a local server port causes the creation of a
 * firewall entry.  To prevent this mechanism from being abused by remote
 * attackers to DoS the system (the creation of firewall hole may cause an
 * allocation to enlarge the table), the maximum number of concurrent TCP
 * connections is limited to `MaxClientCount`.
 *
 * When this maximum is reached, new incoming TCP connections are dropped.
 */
static constexpr const uint8_t FirewallMaximumNumberOfClients = 6;

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
 *
 * `localPort` must not be a server port, as server port can be connected to
 * many remote endpoints.
 */
void __cheri_compartment("Firewall")
  firewall_remove_tcpipv4_local_endpoint(uint16_t localPort);

/**
 * Remove a specific remote TCP endpoint from the firewall.
 */
void __cheri_compartment("Firewall")
  firewall_remove_tcpipv4_remote_endpoint(uint32_t remoteAddress,
                                          uint16_t localPort,
                                          uint16_t remotePort);

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

/**
 * Register a local TCP port as server port into the firewall.
 *
 * Any new incoming TCP connection to that port will trigger the creation of a
 * hole in the firewall for TCP packets from that endpoint and port to the
 * local TCP server port.
 *
 * New TCP client connections are identified by incoming TCP SYN packets.
 *
 * To prevent this mechanism from being used as a vector for DoS (since the
 * creation of firewall hole may cause an allocation to enlarge the table), the
 * maximum number of concurrent TCP connections is limited (see
 * `MaxClientCount` in `firewall.cc`). Past that point, new incoming TCP
 * connections will be dropped until a slot is freed (through a connection
 * being terminated).
 *
 * This should be called only by the NetAPI compartment.
 */
void __cheri_compartment("Firewall")
  firewall_add_tcpipv4_server_port(uint16_t localPort);

/**
 * Remove a server port from the firewall.
 *
 * This is called from the TCP/IP compartment when a TCP connection is closed.
 * Similarly to `firewall_remove_tcpipv4_local_endpoint`, this is not a
 * security risk: the worst that the TCP/IP compartment can do by calling it is
 * DoS itself.
 */
void __cheri_compartment("Firewall")
  firewall_remove_tcpipv4_server_port(uint16_t localPort);

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
 *
 * `localPort` must not be a server port, as server port can be connected to
 * many remote endpoints.
 */
void __cheri_compartment("Firewall")
  firewall_remove_tcpipv6_local_endpoint(uint16_t localPort);

/**
 * Remove a specific remote TCP endpoint from the firewall.
 */
void __cheri_compartment("Firewall")
  firewall_remove_tcpipv6_remote_endpoint(uint8_t *remoteAddress,
                                          uint16_t localPort,
                                          uint16_t remotePort);

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

/**
 * Register a local TCP port as server port.
 *
 * Any new incoming TCP connection to that port will trigger the creation of a
 * hole in the firewall for TCP packets from that endpoint and port to the
 * local TCP server port.
 *
 * See `firewall_add_tcpipv4_server_port` for more information.
 *
 * This should be called only by the NetAPI compartment.
 */
void __cheri_compartment("Firewall")
  firewall_add_tcpipv6_server_port(uint16_t localPort);

/**
 * Remove a server port from the firewall.
 */
void __cheri_compartment("Firewall")
  firewall_remove_tcpipv6_server_port(uint16_t localPort);

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
firewall_remove_tcpipv6_local_endpoint(uint16_t localPort)
{
	Debug::Assert(
	  false, "{} not supported with IPv6 disabled", __PRETTY_FUNCTION__);
}
__always_inline static inline void
firewall_remove_tcpipv6_remote_endpoint(uint8_t *remoteAddress,
                                        uint16_t localPort,
                                        uint16_t remotePort)
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

__always_inline static inline void
firewall_add_tcpipv6_server_port(uint16_t localPort)
{
	Debug::Assert(
	  false, "{} not supported with IPv6 disabled", __PRETTY_FUNCTION__);
}

__always_inline static inline void
firewall_remove_tcpipv6_server_port(uint16_t localPort)
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
