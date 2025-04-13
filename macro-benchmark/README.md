FreeRTOS+TCP must be instrumented with the "Ping of the death" patch, in
`freertos-tcp.patch`.

Must be compiled with:
```
xmake config --sdk=/cheriot-tools/ --board=ibex-arty-a7-100 --scheduler-accounting=y --IPv6=n
```

Handy command to publish to the MQTT topic:
```
# If necessary, install `mosquitto_pub` with `sudo apt install mosquitto-clients`
mosquitto_pub -h demo.cheriot.org -p 8883 -t macrobenchmark-led -m ""
```
