if(NOT DEFINED HEYAKI_COTURN_DIR)
  message(FATAL_ERROR "HEYAKI_COTURN_DIR is required")
endif()
set(expected_digest "sha256:f4c2af06c3c535c4f49d64e14d484104e7e4fcc98c4cb83d6e1544f64d1e6158")
foreach(required_file IN ITEMS README.md turnserver.conf docker-compose.yml heyaki-turn.env.example)
  if(NOT EXISTS "${HEYAKI_COTURN_DIR}/${required_file}")
    message(FATAL_ERROR "Missing coturn deployment file: ${required_file}")
  endif()
endforeach()

file(READ "${HEYAKI_COTURN_DIR}/README.md" readme)
if(NOT readme MATCHES "coturn/coturn:4\\.10\\.0-debian" OR
   NOT readme MATCHES "${expected_digest}" OR
   NOT readme MATCHES "username = <expiry_unix_seconds>:<tenant>:<DeviceId>")
  message(FATAL_ERROR "coturn README pin or credential contract is inconsistent")
endif()

file(READ "${HEYAKI_COTURN_DIR}/docker-compose.yml" compose)
if(NOT compose MATCHES "coturn/coturn:4\\.10\\.0-debian@${expected_digest}")
  message(FATAL_ERROR "coturn compose file is not pinned to the immutable digest")
endif()

file(READ "${HEYAKI_COTURN_DIR}/turnserver.conf" turn_conf)
foreach(required_option IN ITEMS
    "use-auth-secret"
    "static-auth-secret=__TURN_SECRET__"
    "tls-listening-port=5349"
    "min-port=49160"
    "max-port=49200"
    "denied-peer-ip=10.0.0.0-10.255.255.255")
  string(FIND "${turn_conf}" "${required_option}" option_position)
  if(option_position EQUAL -1)
    message(FATAL_ERROR "coturn config is missing ${required_option}")
  endif()
endforeach()
if(turn_conf MATCHES "static-auth-secret=[A-Za-z0-9+/=_-]+" AND
   NOT turn_conf MATCHES "static-auth-secret=__TURN_SECRET__")
  message(FATAL_ERROR "coturn config must not commit a real static-auth-secret")
endif()
