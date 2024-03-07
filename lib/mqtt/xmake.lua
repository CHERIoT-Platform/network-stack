-- Copyright SCI Semiconductor and CHERIoT Contributors.
-- SPDX-License-Identifier: MIT

debugOption("MQTT")

compartment("MQTT")
  add_rules("cheriot.component-debug")
  set_default(false)
  add_deps("freestanding", "NetAPI", "TLS")
  add_files("mqtt.cc")
  add_defines("CHERIOT_NO_AMBIENT_MALLOC", "CHERIOT_NO_NEW_DELETE")
  add_includedirs(".", "../../include", "../../third_party/coreMQTT/source/include",
                                        "../../third_party/coreMQTT/source/interface")
  add_files("../../third_party/coreMQTT/source/core_mqtt.c",
            "../../third_party/coreMQTT/source/core_mqtt_serializer.c",
            "../../third_party/coreMQTT/source/core_mqtt_state.c")
