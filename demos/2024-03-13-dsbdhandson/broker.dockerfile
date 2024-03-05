FROM ubuntu:24.04

RUN apt -y update && apt -y install mosquitto

RUN mkdir /mqtt/
COPY certs/ /mqtt/certs
# Totally unsafe, please don't do that in production.
RUN chmod a+rw /mqtt/certs/*

RUN rm /etc/mosquitto/mosquitto.conf && touch /etc/mosquitto/mosquitto.conf
RUN echo "listener 8883" > /etc/mosquitto/mosquitto.conf
RUN echo "cafile /mqtt/certs/ca.crt" >> /etc/mosquitto/mosquitto.conf
RUN echo "certfile /mqtt/certs/server.crt" >> /etc/mosquitto/mosquitto.conf
RUN echo "keyfile /mqtt/certs/server.key" >> /etc/mosquitto/mosquitto.conf
RUN echo "require_certificate false" >> /etc/mosquitto/mosquitto.conf
RUN echo "allow_anonymous true" >> /etc/mosquitto/mosquitto.conf

CMD bash
