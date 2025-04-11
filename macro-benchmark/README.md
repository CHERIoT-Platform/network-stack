Handy command to publish to the MQTT topic:
```
# If necessary, install `mosquitto_pub` with `sudo apt install mosquitto-clients`
mosquitto_pub -h demo.cheriot.org -p 8883 -t macrobenchmark-led -m ""
```
