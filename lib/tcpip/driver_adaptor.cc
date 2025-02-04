// Copyright SCI Semiconductor and CHERIoT Contributors.
// SPDX-License-Identifier: MIT

// Native APIs
#include <atomic>
#include <cheri-builtins.h>
#include <compartment-macros.h>
#include <debug.hh>
// #include <fail-simulator-on-error.h>
#include <futex.h>
#include <locks.hh>
#include <platform-ethernet.hh>
#include <timeout.h>

#include "tcpip-internal.h"

// FreeRTOS APIs
#include <FreeRTOS.h>
#include <FreeRTOS_DHCP.h>
#include <FreeRTOS_IP.h>
#include <FreeRTOS_ND.h>
#include <NetworkBufferManagement.h>

using Debug = ConditionalDebug<false, "Ethernet Adaptor">;

#include "../firewall/firewall.hh"

namespace
{
	/**
	 * Pointer to the interface descriptor for this interface.  FreeRTOS+TCP has
	 * an undocumented requirement that each incoming descriptor is tagged with
	 * the interface it came from, so we need to capture this here.
	 */
	NetworkInterface_t *thisInterface = nullptr;

	/**
	 * Is the TCP/IP stack compiled with support for fault injection?
	 */
	constexpr bool InjectFaults = CHERIOT_RTOS_OPTION_NETWORK_INJECT_FAULTS;

	/**
	 * Has a fault been requested?
	 */
	bool faultInjected = false;

	/**
	 * Callback to initialise the network interface.  Starts the driver thread.
	 */
	BaseType_t initialise(struct xNetworkInterface *pxDescriptor)
	{
		CHERI::Capability stateCap{&restartState};
		// We trust the firewall, but restricting permissions is still
		// nice to catch bugs.
		stateCap.permissions() &=
		  {CHERI::Permission::Load, CHERI::Permission::Global};
		ethernet_driver_start(stateCap);
		if (restartState.load() != 0)
		{
			restartState |= DriverKicked;
		}
		return pdPASS;
	}

	/**
	 * Frame output callback.  Passes the frame to the firewall layer.
	 */
	BaseType_t output_frame(struct xNetworkInterface *,
	                        NetworkBufferDescriptor_t *const pxNetworkBuffer,
	                        BaseType_t                       xReleaseAfterSend)
	{
		bool sent = ethernet_send_frame(pxNetworkBuffer->pucEthernetBuffer,
		                                pxNetworkBuffer->xDataLength);
		if (xReleaseAfterSend)
		{
			vReleaseNetworkBufferAndDescriptor(pxNetworkBuffer);
		}
		return sent ? pdPASS : pdFAIL;
	}

	/**
	 * Callback to query the link status.
	 */
	BaseType_t phy_link_status(struct xNetworkInterface *pxInterface)
	{
		return ethernet_link_is_up() ? pdPASS : pdFAIL;
	}
} // namespace

bool __cheri_compartment("TCPIP")
  network_stack_receive_frame(uint8_t *frame, size_t length)
{
	return with_restarting_checks_driver(
	  [&]() {
		  // We do not check the frame pointer and length because this function
		  // can only be called by the firewall and we trust the firewall. See
		  // the compartment call allow list entry of `ethernet_send_frame` in
		  // the policy file (`network_stack.rego`).
		  if (eConsiderFrameForProcessing(frame) != eProcessBuffer)
		  {
			  // Debug::log("Frame not for us");
			  return false;
		  }
		  NetworkBufferDescriptor_t *descriptor =
		    pxGetNetworkBufferWithDescriptor(length, 10);
		  if (descriptor == nullptr)
		  {
			  Debug::log(
			    "Failed to allocate network buffer for {}-byte frame\n",
			    length);
			  return false;
		  }
		  memcpy(descriptor->pucEthernetBuffer, frame, length);
		  descriptor->xDataLength = length;
		  descriptor->pxInterface = thisInterface;
		  if constexpr (InjectFaults)
		  {
			  if (faultInjected)
			  {
				  ConditionalDebug<true, "Ethernet Adaptor">::log(
				    "Triggering crash");
				  faultInjected = false;
				  // Inject a fault by giving the frame an incorrect length.
				  // This will cause the TCP/IP stack to read beyond the end.
				  CHERI::Capability buffer = descriptor->pucEthernetBuffer;
				  buffer.bounds().set_inexact(16);
				  descriptor->pucEthernetBuffer = buffer;
			  }
		  }
		  // This is an annoying waste of an allocation, we should be able to
		  // drop this but FreeRTOS_MatchingEndpoint requires a different
		  // alignment.  This will matter less when we are doing our own
		  // filtering.
		  descriptor->pxEndPoint = FreeRTOS_MatchingEndpoint(
		    thisInterface, descriptor->pucEthernetBuffer);
		  if (descriptor->pxEndPoint == nullptr)
		  {
			  // Debug::log("Failed to find endpoint for frame\n");
			  vReleaseNetworkBufferAndDescriptor(descriptor);
			  return false;
		  }

		  Debug::log("Sending frame to IP task");

		  IPStackEvent_t event;
		  event.eEventType = eNetworkRxEvent;
		  event.pvData     = descriptor;
		  // Allow a one-tick sleep so that the IP task can wake up if
		  // necessary.
		  if (xSendEventStructToIPTask(&event, 1) == pdFALSE)
		  {
			  Debug::log("Failed to send event to IP task\n");
			  vReleaseNetworkBufferAndDescriptor(descriptor);
			  return false;
		  }
		  return true;
	  },
	  false /* cannot receive frame if we are restarting */);
}

NetworkInterface_t *fill_interface_descriptor(BaseType_t          xEMACIndex,
                                              NetworkInterface_t *pxInterface)
{
	memset(pxInterface, '\0', sizeof(*pxInterface));
	// Name. Used only for debugging.
	pxInterface->pcName = "CHERIoTAdaptor";
	// Additional state.  Unused.
	pxInterface->pvArgument = nullptr;
	// Callback to initialise the interface.
	pxInterface->pfInitialise = initialise;
	// Callback to write output
	pxInterface->pfOutput = output_frame;
	// Callback to query the link status.
	pxInterface->pfGetPhyLinkStatus = phy_link_status;
	// Capture this.  We need to set this in descriptors.  This is totally
	// undocumented as a requirement, but things crash if we don't.
	thisInterface = pxInterface;

	FreeRTOS_AddNetworkInterface(pxInterface);
	return pxInterface;
}

#if CHERIOT_RTOS_OPTION_NETWORK_INJECT_FAULTS
void __cheri_compartment("TCPIP") network_inject_fault(void)
{
	faultInjected = true;
}
#endif
