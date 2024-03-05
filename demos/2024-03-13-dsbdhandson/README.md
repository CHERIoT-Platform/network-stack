MQTT Demo
=========

Main files included in this demo:
---------------------------------

- `broker.sh`: generates certificates, and starts a containerized TLS MQTT broker on localhost at port 8883.
- `host_subscriber.sh`: connects to the broker through TLS, and subscribes to 'led', 'button', and 'control' topics on the local broker. All notifications are printed to the screen.
- `host_publisher.sh`: connects to the broker through TLS, and publishes messages on this broker from user input, with user-defined topics.

Both `host_publisher.sh` and `host_subscriber.sh` can be run towards a remote Mosquitto test broker as well by setting `USE_REMOTE` to `1`.

Other files included in this demo:
----------------------------------

- `broker.dockerfile`: Docker file used by `broker.sh`.
- `helpers/openssl.cnf`: If running `broker.sh` fails at certificate creation time with errors like `Can't open /usr/local/ssl/openssl.cnf for reading` or `unable to find 'distinguished_name' in config`, copy this into your default `openssl.cnf` location (to find it, type `openssl version -d`).
- `helpers/mosquitto.org.crt`: If running `host_publisher.sh` and `host_subscriber.sh` with a remote Mosquitto test broker, this certificate is used to authenticate the remote broker.

How to run this demo:
---------------------

1. First start `broker.sh` to generate certificates and start the broker (otherwise `host_publisher.sh` and `host_subscriber.sh` will return `Error: Connection refused`).

Note that `broker.sh` can generate RSA and ECDSA certificates (default). Unset `USE_ECDSA` in `broker.sh` to enable RSA.

If ECDSA is enabled, you will need to enter the same password three times (it would be nice to automate this in a future version of the script - that's not the case for RSA).

2. Then start `host_publisher.sh` and `host_subscriber.sh` in any order.
Try publishing messages in `host_publisher.sh`, they should appear in the output of `host_subscriber.sh`.

3. Then start the FPGA demo.

Example output:
---------------

### Terminal 1:
```
$ ./broker.sh
Generating a new CA certificate...
Generating RSA private key, 2048 bit long modulus
.......+++
......+++
e is 65537 (0x010001)
Signature ok
subject=C = UK, ST = England, L = Cambridge, O = SCI Semiconductor Ltd., OU = CHERIoT, CN = localhost
Getting Private key
Generating a new server certificate...
Generating RSA private key, 2048 bit long modulus
....+++
......................................................................................................................+++
e is 65537 (0x010001)
Signature ok
subject=C = UK, ST = England, L = Cambridge, O = SCI Semiconductor Ltd., OU = CHERIoT, CN = localhost
Getting CA Private Key
Building Docker container...
[+] Building 4.3s (17/17) FINISHED                                            docker:default
 => [internal] load .dockerignore                                                       0.0s
 => => transferring context: 2B                                                         0.0s
 => [internal] load build definition from broker.dockerfile                             0.0s
 => => transferring dockerfile: 736B                                                    0.0s
 => [internal] load metadata for docker.io/library/ubuntu:24.04                         1.0s
 => [ 1/12] FROM docker.io/library/ubuntu:24.04@sha256:723ad8033f109978f8c7e6421ee684e  0.0s
 => [internal] load build context                                                       0.0s
 => => transferring context: 8.27kB                                                     0.0s
 => CACHED [ 2/12] RUN apt -y update && apt -y install mosquitto                        0.0s
 => CACHED [ 3/12] RUN mkdir /mqtt/                                                     0.0s
 => [ 4/12] COPY certs/ /mqtt/certs                                                     0.0s
 => [ 5/12] RUN chmod a+rw /mqtt/certs/*                                                0.3s
 => [ 6/12] RUN rm /etc/mosquitto/mosquitto.conf && touch /etc/mosquitto/mosquitto.con  0.4s
 => [ 7/12] RUN echo "listener 8883" > /etc/mosquitto/mosquitto.conf                    0.4s
 => [ 8/12] RUN echo "cafile /mqtt/certs/ca.crt" >> /etc/mosquitto/mosquitto.conf       0.5s
 => [ 9/12] RUN echo "certfile /mqtt/certs/server.crt" >> /etc/mosquitto/mosquitto.con  0.4s
 => [10/12] RUN echo "keyfile /mqtt/certs/server.key" >> /etc/mosquitto/mosquitto.conf  0.4s
 => [11/12] RUN echo "require_certificate false" >> /etc/mosquitto/mosquitto.conf       0.4s
 => [12/12] RUN echo "allow_anonymous true" >> /etc/mosquitto/mosquitto.conf            0.3s
 => exporting to image                                                                  0.2s
 => => exporting layers                                                                 0.2s
 => => writing image sha256:d0c86432db81958205806a798cfcc4d4d4cda4f77e9c2827101eb8545b  0.0s
 => => naming to docker.io/library/mqtt-broker                                          0.0s
Launching the MQTT broker container...
1709781688: mosquitto version 2.0.18 starting
1709781688: Config loaded from /etc/mosquitto/mosquitto.conf.
1709781688: Opening ipv4 listen socket on port 8883.
1709781688: Opening ipv6 listen socket on port 8883.
1709781688: mosquitto version 2.0.18 running
1709781693: New connection from ::1:53870 on port 8883.
1709781693: New client connected from ::1:53870 as auto-47FCE971-CEEA-0472-5C55-21C082C0826D (p2, c1, k60).
1709781701: New connection from ::1:50564 on port 8883.
1709781701: New client connected from ::1:50564 as auto-72228A5F-2E6F-27EA-493C-846205B86A64 (p2, c1, k60).
1709781701: Client auto-72228A5F-2E6F-27EA-493C-846205B86A64 disconnected.
1709781704: New connection from ::1:50570 on port 8883.
1709781704: New client connected from ::1:50570 as auto-86823927-2FA8-5869-12EA-030A075A9EDF (p2, c1, k60).
1709781704: Client auto-86823927-2FA8-5869-12EA-030A075A9EDF disconnected.
1709781706: New connection from ::1:50582 on port 8883.
1709781706: New client connected from ::1:50582 as auto-1C95B3A3-7FAA-032F-55C4-260AD53C9911 (p2, c1, k60).
1709781706: Client auto-1C95B3A3-7FAA-032F-55C4-260AD53C9911 disconnected.
```

### Terminal 2:
```
$ ./host_subscriber.sh
cheri-led ON
cheri-led OFF
cheri-control END
```

### Terminal 3:

```
$ ./host_publisher.sh
Enter topic (valid: 'cheri-led', 'cheri-control'): cheri-led
Enter payload (for 'led': 'ON', 'OFF'; for 'control': 'END'): ON
> Sent 'ON'.
Enter topic (valid: 'cheri-led', 'cheri-control'): cheri-led
Enter payload (for 'led': 'ON', 'OFF'; for 'control': 'END'): OFF
> Sent 'OFF'.
Enter topic (valid: 'cheri-led', 'cheri-control'): cheri-control
Enter payload (for 'led': 'ON', 'OFF'; for 'control': 'END'): END
> Sent 'END'.
```
