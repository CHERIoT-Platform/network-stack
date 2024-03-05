#!/bin/sh

# Set to 1 to use the local broker, otherwise the Mosquitto test broker will be
# used
USE_REMOTE=0

# ---------------------

TOPIC_LED="cheri-led"
TOPIC_SWITCH="cheri-switch/+"
TOPIC_BUTTON="cheri-button"

SUDO="sudo"
HOST=localhost
CERT="--cafile certs/server.crt --insecure"

if [ $USE_REMOTE = 1 ]
then
	HOST=test.mosquitto.org
	CERT="--cafile ./helpers/mosquitto.org.crt"
fi

if ! [ -x "$(command -v mosquitto_sub)" ]
then
	if ! [ -x "$(command -v apt)" ]
	then
	    echo "Error: mosquitto_sub is not installed on this system."
	    echo "This script can only automatically install it on Debian-based"
	    echo "systems. You can manually install mosquitto_sub from"
	    echo "https://mosquitto.org"
	    exit 1
	fi

	echo "mosquitto_sub not found, automatically installing."
	${SUDO} apt update && ${SUDO} apt install mosquitto-clients
fi

mosquitto_sub -v -h $HOST -p 8883 -t ${TOPIC_LED} -t ${TOPIC_SWITCH} -t \
	${TOPIC_BUTTON} $CERT
