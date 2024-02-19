MQTT example
============

This example shows using the MQTT library to establish a connection with an MQTT test broker, subscribe and publish on a dummy topic with QoS 1, unsubscribe from the topic, and disconnect.
The example also checks that ACKs (SUBACK - ACK for subscribes, UNSUBACK - ACK for unsubscribes, PUBACK - ACK for publishes), and notifications for publishes are received as expected.
Finally, this examples checks that the implementation does not leak bytes from the heap between the connect and the disconnect.
