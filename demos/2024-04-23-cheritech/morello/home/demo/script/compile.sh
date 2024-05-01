#!/bin/sh
set -e
microvium demo.js
echo Publishing code to MQTT broker
mosquitto_pub -h cheriot.demo -p 8883 --cafile /opt/etc/mosquitto/certs/cert.pem -t cheri-code -f demo.mvm-bc
