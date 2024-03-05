#!/bin/sh

SCRIPT_DIRECTORY="$(dirname "$(realpath "$0")")"

# CONFIGURATION OPTIONS
# ---------------------

# Set to 1 to use ECDSA, otherwise RSA will be used
USE_ECDSA=1

# Set to the correct location of the brssl binary
BRSSL=${SCRIPT_DIRECTORY}/../../third_party/BearSSL/build/brssl

# INTERNAL CONSTANTS
# ------------------

DOCKER_CONTAINER_NAME="mqtt-broker"

CERTS_DIR=certs
CERT_EXPIRATION=300
SERVER_CERT_SIGN_REQ="${SCRIPT_DIRECTORY}/${CERTS_DIR}/server.csr"
SERVER_CERT="${SCRIPT_DIRECTORY}/${CERTS_DIR}/server.crt"
SERVER_KEY="${SCRIPT_DIRECTORY}/${CERTS_DIR}/server.key"
SERVER_PEM="${SCRIPT_DIRECTORY}/${CERTS_DIR}/server.pem"
CA_CERT_SIGN_REQ="${SCRIPT_DIRECTORY}/${CERTS_DIR}/ca.csr"
CA_CERT="${SCRIPT_DIRECTORY}/${CERTS_DIR}/ca.crt"
CA_KEY="${SCRIPT_DIRECTORY}/${CERTS_DIR}/ca.key"
C_TAs="${SCRIPT_DIRECTORY}/host.cert.h"

# ------------------

gen_rsa_cert() {
	# absolutely unsafe, do not do any of that in production.
	echo "> Generating a new CA certificate..."
	# Create CA key
	openssl genrsa -out ${CA_KEY} 2048
	# Create certificate from the key
	openssl req -new -key ${CA_KEY} -out ${CA_CERT_SIGN_REQ} -sha256
	openssl x509 -req -in ${CA_CERT_SIGN_REQ} -signkey ${CA_KEY} \
		-out ${CA_CERT} -days ${CERT_EXPIRATION}

	echo "> Generating a new server certificate..."
	openssl genrsa -out ${SERVER_KEY} 2048
	openssl req -out ${SERVER_CERT_SIGN_REQ} -key ${SERVER_KEY} -new -sha256
	openssl x509 -passin pass:foobar -req -in ${SERVER_CERT_SIGN_REQ} \
		-CA ${CA_CERT} -CAkey ${CA_KEY} -CAcreateserial -out ${SERVER_CERT} \
		-days ${CERT_EXPIRATION}
}

gen_ecdsa_cert() {
	echo "> Generating a new CA certificate..."
	# Create CA key
	openssl ecparam -genkey -name prime256v1 -out ${CA_KEY}
	# Create certificate from the key
	openssl req -new -x509 -key ${CA_KEY} -sha256 -days ${CERT_EXPIRATION} \
		-extensions v3_ca -out ${CA_CERT}

	echo "> Generating a new server certificate..."
	openssl genpkey -genparam -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out ${SERVER_PEM}
	openssl req -newkey ec:${SERVER_PEM} -keyout ${SERVER_KEY} -out ${SERVER_CERT_SIGN_REQ}
	openssl x509 -req -in ${SERVER_CERT_SIGN_REQ} \
		-CA ${CA_CERT} -CAkey ${CA_KEY} -CAcreateserial -out ${SERVER_CERT} \
		-days ${CERT_EXPIRATION}
}

BUILD_CERTS=0

if [ ! -d "${CERTS_DIR}" ]
then
	BUILD_CERTS=1
fi

if [ ! -f "${CA_CERT}" ]
then
	BUILD_CERTS=1
fi

if [ ! -f "${SERVER_KEY}" ]
then
	BUILD_CERTS=1
fi

if [ ! -f "${SERVER_CERT}" ]
then
	BUILD_CERTS=1
fi

if [ ! -f "${C_TAs}" ]
then
	BUILD_CERTS=1
fi

if [ $BUILD_CERTS = 1 ]
then
	if ! [ -x "$(command -v openssl)" ]
	then
		if ! [ -x "$(command -v apt)" ]
		then
		    echo "> Error: openssl is not installed on this system."
		    echo "> This script can only automatically install it on Debian-based"
		    echo "> systems. You can manually install openssl from"
		    echo "> https://openssl.org"
		    exit 1
		fi

		echo "> openssl not found, automatically installing."
		${SUDO} apt update && ${SUDO} apt install openssl
	fi

	echo "> Generating certificates..."
	rm -rf ${CERTS_DIR}
	mkdir ${CERTS_DIR}

	if [ $USE_ECDSA = 1 ]
	then
		gen_ecdsa_cert
	else
		gen_rsa_cert
	fi

	echo "> Generating the trust anchors..."
	rm -rf ${C_TAs}

	if [ ! -f ${BRSSL} ]; then
		echo "> brssl not found (searched at ${BRSSL})."
		echo "> Either build brssl at the above location (try running "
		echo "> \`make\` in the BearSSL directory), or edit the "
		echo "> \$BRSSL variable of this script."
		exit 1
	fi

	${BRSSL} ta ${SERVER_CERT} > ${C_TAs}
fi

echo "> Building Docker container..."
docker build -t ${DOCKER_CONTAINER_NAME} -f broker.dockerfile .

echo "> Launching the MQTT broker container..."
docker run --privileged -it --rm --net=host ${DOCKER_CONTAINER_NAME} mosquitto  -c /etc/mosquitto/mosquitto.conf
#docker run --privileged -it --rm --net=host ${DOCKER_CONTAINER_NAME} bash
