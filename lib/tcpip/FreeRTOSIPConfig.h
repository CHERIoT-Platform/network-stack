// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

#pragma once

#ifndef FREERTOS_CONFIG_H
/**
 * This macro would usually be defined in FreeRTOSConfig.h, which we do not
 * implement here because we do not use the FreeRTOS core. We define it here
 * because FreeRTOS+TCP refuses to compile without.
 */
#define FREERTOS_CONFIG_H
#endif

/**
 * FreeRTOS+TCP errno codes. See the header documentation.
 */
#include <FreeRTOS_errno.h>

/**
 * `INCLUDE_*` macros have no effect here since we do not use the FreeRTOS
 * core, however FreeRTOS+TCP refuses to compile without defining these.
 */
#define INCLUDE_vTaskDelay 1
#define INCLUDE_xTaskGetCurrentTaskHandle 1

/**
 * Scheduling-related settings have no impact since we do not use the FreeRTOS
 * core, however FreeRTOS+TCP refuses to compile without defining these.
 */
#define ipconfigIP_TASK_PRIORITY 0
#define configMAX_PRIORITIES 1
#define configMINIMAL_STACK_SIZE 128

/**
 * FreeRTOS+TCP uses descriptors to track information about the packets in a
 * window. A pool of descriptors is allocated when the first TCP connection is
 * made. This configuration entry sets the size of the pool.
 *
 * In the worst case, each TCP connection will have an Rx and Tx window of at
 * most 8 segments (according to the FreeRTOS+TCP documentation), requiring 16
 * descriptors in total per TCP connection. This configuration entry should
 * thus be set to `(expected maximum number of TCP connections) x 16`.
 *
 * If we assume at most 6 TCP connections, this results in 96 segments.
 *
 * Each descriptor is 104 bytes, i.e., set to 96 this results in a memory
 * footprint of 9,984 bytes.
 *
 * Note that the pool of descriptors is reallocated at every network stack
 * reset. Setting the number of segments to a large value (e.g., 256, the
 * FreeRTOS+TCP default) is known to cause reset failures due to fragmentation
 * preventing us from reallocating the pool.
 */
#define MAX_SIMULTANEOUS_TCP_CONNECTIONS 6
#define ipconfigTCP_WIN_SEG_COUNT (MAX_SIMULTANEOUS_TCP_CONNECTIONS * 16)

/**
 * Enable counting semaphore functionality in the build, as this is necessary
 * to build FreeRTOS+TCP.
 */
#define configUSE_COUNTING_SEMAPHORES 1

/**
 * Macro defined to flag that this file has been included.
 */
#define FREERTOS_IP_CONFIG_H 1

/**
 * We don't want to have a callback for DHCP responses
 */
#define ipconfigUSE_DHCP_HOOK 0

/**
 * Enable IPv4.
 */
#define ipconfigUSE_IPv4 1
/**
 * Enable IPv6.
 */
#define ipconfigUSE_IPv6 CHERIOT_RTOS_OPTION_IPv6
#define ipconfigUSE_RA 1
#define ipconfigUSE_DHCPv6 0

#define ipconfigREPLY_TO_INCOMING_PINGS 1

#define ipconfigNUM_NETWORK_BUFFER_DESCRIPTORS 8

#define ipconfigTCP_RX_BUFFER_LENGTH ( 1280 )
#define ipconfigTCP_TX_BUFFER_LENGTH ( 1280 )

#define ipconfigBYTE_ORDER pdFREERTOS_LITTLE_ENDIAN
#define pvPortMalloc(x) malloc(x)
#define vPortFree(x) free(x)

//#define DEBUG_FREERTOS_TCP
#ifdef DEBUG_FREERTOS_TCP
#	define ipconfigHAS_DEBUG_PRINTF 1
#	define FreeRTOS_debug_printf(x) printf x
#	define ipconfigHAS_PRINTF 1
#	define FreeRTOS_printf(x) printf x
#else
#	define ipconfigHAS_DEBUG_PRINTF 0
#	define ipconfigHAS_PRINTF 0
#endif

#define xPortGetMinimumEverFreeHeapSize() 0
#define xPortGetFreeHeapSize() 0

// Use dynamic allocation
#define configSUPPORT_DYNAMIC_ALLOCATION 1

// We don't support static allocation
#define configSUPPORT_STATIC_ALLOCATION 0

// Padding needs to be 14 bytes on platforms where pointers are 64 bits.  This
// is fixed upstream but after the release that we're currently using.
#define ipconfigBUFFER_PADDING 14

#define ipconfigALLOW_SOCKET_SEND_WITHOUT_BIND 0
#define ipconfigUSE_NETWORK_EVENT_HOOK 1

// Necessary to have FreeRTOS+TCP invoke our own `ipFOREVER` function.  As of
// FreeRTOS+TCP 3.1.0 this only enables external `ipFOREVER`. It would be nice
// to upstream a patch to have this variable renamed into something specific to
// `ipFOREVER` to ensure that we do not enable additional undesired options in
// future releases.
#define TEST
