CHERIoT Experimental Network Stack
==================================

This repository contains the code for the experimental CHERIoT network stack.
This is an early work-in-progress implementation that has been made public to facilitate easier collaboration.

WARNING: This is not fully hardened against our desired threat model.
It should not be used in production.
Note especially that there is no strong entropy source on the Arty A7 FPGA prototyping platform and so any TLS connection is moderately easy to compromise.
It is expected to approach production quality in 2024H2.

Third-party code reuse
----------------------

The network stack includes components from a variety of third parties:

 - [FreeRTOS-Plus-TCP](https://github.com/FreeRTOS/FreeRTOS-Plus-TCP) provides the TCP/IP implementation.
 - [FreeRTOS coreSNTP](https://github.com/FreeRTOS/coreSNTP) provides the SNTP client.
 - [FreeRTOS coreMQTT](https://github.com/FreeRTOS/coreMQTT) provides the MQTT client.
 - [BearSSL](https://www.bearssl.org) provides the TLS 1.2 stack.

This demonstrates the CHERIoT platform's ability to adopt existing codebases.
We are building around 100 KLoC of third-party code into this stack.
This is mature and well-tested code that we have no desire to rewrite.
A side-channel-resistant TLS implementation, for example, would be a huge undertaking.

Our additions add security boundaries around these existing components and less-general APIs that are tailored for our expected use cases.
The new code in this repository is around 3% of the size of the large components that we are reusing *with no code changes*.

Compartmentalisation
--------------------

The initial implementation has five compartments.
Three are mostly existing third-party code with thin wrappers:

 - The TCP/IP stack is in a compartment.
   The FreeRTOS code was originally written on the assumption of a single security domain and separating it would require refactoring that would be hard to keep up to date.
 - The SNTP compartment is mostly just another consumer of the network stack, but it provides a real-time clock that is used by the TLS stack.
 - The TLS stack is, again, mostly unmodified BearSSL code, with just some thin wrappers added around the edges.
 - The MQTT compartment, like the SNTP compartment, is just another consumer of the network stack (the TLS layer, specifically) and provides a simple interface for connecting to MQTT servers, publishing messages and receiving notifications of publish events.

These are joined by two new compartments:

 - The firewall compartment is the only thing that talks directly to the network device.
   It filters inbound and outbound frames.
 - The NetAPI compartment provides the control plane.

The communication is (roughly) summarised below:

```mermaid
graph TD
  Network
  subgraph Firewall["On-device firewall"]
    DeviceDriver["Device Driver"]
  end
  TCPIP["TCP/IP"]:::ThirdParty
  User["User Code "]
  NetAPI["Network API"]
  SNTP:::ThirdParty
  TLS:::ThirdParty
  MQTT:::ThirdParty
  DeviceDriver <-- "Network traffic" --> Network
  TCPIP <-- "Send and receive Ethernet frames" --> Firewall
  NetAPI -- "Add and remove rules" --> Firewall
  TLS -- "Request network connections" --> NetAPI
  TLS -- "Send and receive" --> TCPIP
  NetAPI -- "Create connections and perform DNS requests" --> TCPIP
  MQTT -- "Create TLS connections and exchange data" --> TLS
  User -- "Create connections to MQTT server and publish / subscribe" --> MQTT
  MQTT -- "Callbacks for acknowledgements and subscription notifications" --> User
  SNTP -- "Create UDP socket, authorise endpoints" --> NetAPI
  SNTP -- "Send and receive SNTP (UDP) packets" --> TCPIP
  TLS -- "Request wall-clock time for certificate checks" --> SNTP
  style User fill: #5b5
  classDef ThirdParty fill: #e44
```

The TCP/IP stack has a lot of state and cannot yet recover gracefully in case of failure, but failure is at least isolated in the caller.
In contrast, the TLS compartment is almost completely stateless.
This gives strong flow isolation properties: Even if an attacker compromises the TLS compartment by sending malicious data over one connection that triggers a bug in BearSSL (unlikely), it is extraordinarily difficult for them to interfere with any other TLS connection.

Similarly, the firewall is controlled by the Network API compartment.
The TCP/IP stack has no access to the control-plane interface for the compartment.
A compromise that gets arbitrary-code execution in the network stack cannot open new firewall holes (to join a DDoS botnet such as [Mirai](https://en.wikipedia.org/wiki/Mirai_(malware)), for example).
The worst it can do to rest of the system is provide malicious data, but a system using TLS will have HMACs on received messages and so this is no worse than a malicious packet being injected from the network.

All of this is on top of the spatial and temporal safety properties that the CHERIoT platform provides at a base level.

Capabilities authorise communication
------------------------------------

CHERI systems use capabilities to authorise memory accesses.
CHERIoT provides abstractions for software-defined capabilities that can authorise different operations.
These are represented in the hardware via sealed (CHERI) capabilities that refer to specific kinds of objects.
These sealed capabilities can be treated as opaque tokens (and cannot be directly used) by most code but can be unsealed by the compartment that owns the corresponding unsealing capability.

The network stack uses three kinds of sealed capabilities:

 - Connection capabilities are baked into the firmware image and authorise establishing a connection.
 - Socket capabilities are dynamically created and provide a tamper-proof opaque handle that authorises sending and receiving data over a socket.
 - TLS session capabilities are also dynamically created (and wrap socket capabilities) and authorise sending and receiving encrypted data over a TLS session.

The flow for establishing a network connection is as follows:

 1. User code presents a connection capability to the Network API compartment authorising a connection to a remote host.
 2. The Network API compartment opens inspects the capability and extracts the name of the host.
 3. The Network API opens the firewall hole for the DNS resolver.
 4. The Network API compartment instructs the TCP/IP compartment to look up the name.
 5. The TCP/IP compartment sends and receives UDP packets (forwarded via the Firewall compartment) to look up the name.
 6. The Network API compartment instructs the firewall to close the hole for the DNS lookup.
 7. The Network API compartment instructs the TCP/IP stack to create a (sealed) socket.
 8. The Network API compartment instructs the firewall to open a hole for the local port and the remote endpoint.
 9. The Network API compartment returns the sealed capability for the socket to the caller.

At the end of this, the original caller can directly call the send and receive functions in the TCP/IP stack to send and receive data.

Safe sharing
------------

Each compartment needs to share some data with the others.
For UDP, the receive path can be entirely zero copy (after the packet leaves the driver).
A UDP packet arrives and is copied from the network interface into a new allocation.
This is processed by the TCP/IP stack and then claimed with the allocator capability passed the receive-message call, freed with the network stack's allocator capability, and returned.
This ensures that the packet is freed once the caller frees it, transferring ownership out to the caller.
Callers worried about time-of-check-to-time-of-use attacks from a compromised TCP/IP compartment may need to defensively copy.

BearSSL maintains its own send and receive buffers.
The TCP/IP stack can copy directly to and from these, as long as we can make this secure.
These are passed from the TLS compartment to the TCP/IP compartment as *bounded* capabilities with only load or store permissions.
This means that the TCP/IP stack cannot access out of bounds and cannot capture the pointer.
In the case of a store (read from the network), the TCP/IP compartment also cannot read stale data from the buffer (for example, it cannot read previously decrypted data).

Auditing
--------

The network stack relies on some interfaces being restricted to certain compartments.
For example, there are some APIs in the TCP/IP and Firewall compartments that should be exposed only to the Network API compartment.
These can be checked by the [cheriot-audit](https://github.com/CHERIoT-Platform/cheriot-audit) tool, with the aid of the policy in this repository.

The `network_stack.rego` file also makes it easy to extract connection capabilities.
For example, if you run the following Rego query against the [HTTPS example](examples/03.HTTPS) (after loading `network_stack.rego` with `-m`):

```rego
data.network_stack.all_connection_capabilities
```

You should see the following output (piped through `jq` for pretty printing):

```json
[
  {
    "capability": {
      "connection_type": "UDP",
      "host": "pool.ntp.org",
      "port": 123
    },
    "owner": "SNTP"
  },
  {
    "capability": {
      "connection_type": "TCP",
      "host": "example.com",
      "port": 443
    },
    "owner": "https_example"
  }
]
```

This tells you that the SNTP compartment has a capability that allows it to create a UDP socket and communicate with pool.ntp.org and that the `https_example` compartment can make TCP connections to example.com:443.
No other compartments can make connections and no compartment may communicate with hosts not on this list.
This can feed into more auditing infrastructure.

Do you want to check that all TLS connections are encrypted?
Try asking which compartments are calling the TCP connection function:

```rego
data.compartment.compartments_calling_export_matching("NetAPI", `network_socket_connect_tcp(.*)`)
```

Hopefully the output is very short:

```json
["TLS"]
```

This means that all TCP connections are made via the TLS compartment and, unless the TLS compartment is compromised, no traffic can flow over TCP that is not encrypted.
Unfortunately, SNTP is unencrypted.
It can have verified signatures (which you absolutely should use in a real deployment: the current prototype just talks to pool.ntp.org without authentication) though.
This should be the only thing used with UDP:

```rego
data.compartment.compartments_calling_export_matching("NetAPI", `network_socket_udp(.*)`)
```

```json
["SNTP"]
```

Now that you know that the SNTP compartment is the only one that can send and receive UDP packets, it's worth checking that it really is talking to the host that you expect:

```rego
[ data.network_stack.decode_connection_capability(c) | c = input.compartments.SNTP.imports[_] ; data.network_stack.is_connection_capability(c) ]i
```

```json
[{"connection_type":"UDP", "host":"pool.ntp.org", "port":123}]
```

If you've modified the SNTP compartment to point to your NTP service and use its authentication credentials, then this should be different.
This can all be part of your firmware's auditing policy.
