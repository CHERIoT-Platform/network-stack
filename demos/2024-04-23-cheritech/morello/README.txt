Morello machine setup
=====================

This directory contains the files that are necessary to set up the Morello machine to act as the server in this demo.

Note: This contains the *private* key used on the server for the demo.
This would allow anyone to impersonate the server.
This does not matter because it is used *only* for the demo, never use this key for anything important!
Including the key here remove the need to generate a new header file for the client portion of the demo.

Pure-capability packages:

minicom

Hybrid packages:

bind918
isc-dhcp44-server
jq
npm
wireshark

Built from source:

cheriot-audit (no port yet)
mosquitto (xsltproc is broken and the port's no-docs mode doesn't work).

Make sure to build Release builds (-O0 is *really* slow on Morello, with -O0 Mosquitto can't keep up with two clients on FPGA!).
Install in /opt.

The following lines need to be added to /etc/rc.conf:

```
# Network interface for the demo
ifconfig_ue0="inet 10.0.0.10 netmask 255.0.0.0"

# DHCP server
dhcpd_enable="YES"				# dhcpd enabled?
dhcpd_ifaces="ue0"				# ethernet interface(s)
dhcpd_withumask="022"			# file creation mask

# bind
named_enable="YES"

# NTP
ntpd_enable="YES"

# Mosquitto
mosquitto_enable="YES"

devfs_enable="YES"
```

Setting up DHCP
---------------

The first thing that the demo will do is try to get a DHCP lease.
This requires dhcpd to listen in the demo ethernet adaptor (configured in `rc.conf`) and to provide the host IP (10.0.0.10) as the DNS server.
The `usr/local64/etc/dhcpd.conf` file contains the configuration for the DHCP server and should be copied into `/usr/local64/etc/dhcpd.conf`.

Setting up DNS
--------------

After acquiring a DHCP lease, the demo will try to look up host names via DNS.
For disconnected operation, we will fake the two DNS names (pool.ntp.org and cheriot.demo) by configuring the DNS server to be authoritative for these zones.
Add the following lines to the end of `/usr/local64/etc/namedb/named.conf`:

```
zone "cheriot.demo" {
        type master;
        file "/usr/local64/etc/namedb/db.cheriot.demo";
};

zone "pool.ntp.org" {
        type master;
        file "/usr/local64/etc/namedb/db.pool.ntp.org";
};
```

Then copy the `db.cheriot.demo` and `db.pool.ntp.org` files from `usr/local64/etc/namedb` to `/usr/local64/etc/namedb/`.

Setting up NTP
--------------

For disconnected operation, the NTP server needs to be configured to lie and pretend that it is an authoritative server when it can't sync with a real NTP server.
The following lines in /etc/ntp.conf will do this:

```
server 127.127.1.0 prefer
fudge 127.127.1.0 #stratum 10
```

Note: It would be better to use `tos orphan 4`, but this defaults to a 10-minute timeout before deciding to become authoritative and this needs to be dropped to a few seconds.

Setting up Mosquitto
--------------------

The Mosquitto MQTT server configuration is in `opt/etc/mosquitto/`.
Copy these files into `/opt/etc/mosquitto/`.
You can also copy the [rc script](https://github.com/freebsd/freebsd-ports/blob/main/net/mosquitto/files/mosquitto.in) from the port into `/usr/local/etc/rc.d/mosquitto` (replace `%%PREFIX%%` with `/opt`).
Alternatively, you can just start mosquitto manually and run it in the foreground.

Wireshark
---------

To inspect the packets, use Wireshark.
This requires that the demo user has access to the `bpf` device.
The easiest way of doing this is to add the user to a group called `bpf` and add the following to `/etc/devfs.conf`:

```
own	bpf	root:bpf
perm	bpf	660
```

Console UART
------------

The `home/demo/.minirc.dfl` file contains the configuration for minicom to connect to the FPGA.
Run minicom as `minicom -c on -D /dev/ttyU1` or `minicom -c on -D /dev/ttyU3` to connect to the FPGA.
The demo user will need to have access to the USB TTY devices.
The easiest way to do this is to add the user to the `dialer` group and add the following to `/etc/devfs.conf`:

```
own	ttyU*	root:dialer
perm	ttyU*	660
```

Note that each FPGA has two FDTI devices, you need to use the *odd* numbered ones.

Driving the demo
----------------

The auditing portions of the demo are driven by the `audit.sh` script in `home/demo`.
Drop this in a directory along with the board description JSON and the firmware JSON from the final build.

The script to push new JavaScript, and an example JavaScript file, for the demo are in: `home/demo/script`
The `cheri.js` file here is the host interfaces, people may wish to modify `demo.js` to show dynamic code updates.
Note: MQTT does not do caching, so you must push out the JavaScript each time a new client connects.

