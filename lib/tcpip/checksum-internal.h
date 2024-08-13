// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once
#include <compartment-macros.h>
#include <stddef.h>
#include <stdint.h>
/**
 * Internal APIs that the TCP/IP compartment exposes for the firewall to use.
 *
 * These should be called only from the firewall compartment (validated by
 * checking the compartment linkage report).  These APIs trust the caller and
 * do *not* check arguments.
 */

/**
 * Returns the IPv4 checksum for passed packet.
 *
 * This function is stateless and can be called at any point of the lifetime of
 * the TCP/IP stack.
 *
 * The IPv4 header (only) should be passed in `ipv4Header`, along with its
 * length in `headerLength`.
 *
 * The returned checksum is in network byte order and can be used as-is for
 * transmission in the IPv4 header.
 */
uint16_t __cheri_compartment("TCPIP")
  network_calculate_ipv4_checksum(const uint8_t *ipv4Header,
                                  size_t         headerLength);

/**
 * Returns the TCP checksum for passed packet.
 *
 * This function is stateless and can be called at any point of the lifetime of
 * the TCP/IP stack.
 *
 * Unlike `network_calculate_ipv4_checksum`, this takes the entire Ethernet
 * frame into `frame`, along with its length in `frameLength`.
 *
 * The offset of the TCP checksum in the `frame` buffer must be passed in
 * `tcpChecksumOffset`.
 *
 * The returned checksum is in network byte order and can be used as-is for
 * transmission in the TCP header.
 */
uint16_t __cheri_compartment("TCPIP")
  network_calculate_tcp_checksum(const uint8_t *frame,
                                 size_t         frameLength,
                                 size_t         tcpChecksumOffset);
