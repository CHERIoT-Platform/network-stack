#!/bin/sh

# Set to 1 to use the local broker, otherwise the Mosquitto test broker will be
# used
USE_REMOTE=0

# ---------------------

SUDO="sudo"
HOST=localhost
CERT="--cafile certs/server.crt --insecure"

if [ $USE_REMOTE = 1 ]
then
	HOST=test.mosquitto.org
	CERT="--cafile ./helpers/mosquitto.org.crt"
fi

if ! [ -x "$(command -v mosquitto_pub)" ]
then
	if ! [ -x "$(command -v apt)" ]
	then
	    echo "Error: mosquitto_pub is not installed on this system."
	    echo "This script can only automatically install it on Debian-based"
	    echo "systems. You can manually install mosquitto_pub from"
	    echo "https://mosquitto.org"
	    exit 1
	fi

	echo "mosquitto_pub not found, automatically installing."
	${SUDO} apt update && ${SUDO} apt install mosquitto-clients
fi

while true
do
	read -p "Enter topic (valid: 'cheri-led'): " topic
	read -p "Enter payload (for 'led': '0', '1', '2', or '3'): " payload
	mosquitto_pub -h $HOST -p 8883 -t ${topic} -m "${payload}" $CERT
	echo "> Sent '${payload}'."
done
