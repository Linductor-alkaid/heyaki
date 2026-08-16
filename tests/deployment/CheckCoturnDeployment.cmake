if(NOT DEFINED HEYAKI_COTURN_DIR)
  message(FATAL_ERROR "HEYAKI_COTURN_DIR is required")
endif()
set(expected_digest "sha256:f4c2af06c3c535c4f49d64e14d484104e7e4fcc98c4cb83d6e1544f64d1e6158")
foreach(required_file IN ITEMS README.md turnserver.conf docker-compose.yml heyaki-turn.env.example run_topology.sh run_allocation_probe.sh)
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
    "external-ip=__ADVERTISED_ADDRESS__/__LISTEN_ADDRESS__"
    "tls-listening-port=5349"
    "min-port=49160"
    "max-port=49200"
    "total-quota=100"
    "user-quota=12"
    "max-bps=2000000"
    "bps-capacity=16000000"
    "max-allocate-lifetime=3600"
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
if(turn_conf MATCHES "no-loopback-peers")
  message(FATAL_ERROR
    "no-loopback-peers is not supported by the pinned coturn 4.10.0 image; "
    "loopback peers are denied by default and denied-peer-ip=127.0.0.0-127.255.255.255 is explicit")
endif()
if(NOT turn_conf MATCHES "denied-peer-ip=127\.0\.0\.0-127\.255\.255\.255")
  message(FATAL_ERROR "coturn config must explicitly deny loopback peer ranges")
endif()

file(READ "${HEYAKI_COTURN_DIR}/run_allocation_probe.sh" allocation_probe)
foreach(required_allocation IN ITEMS
    "TURN REST API"
    "ALLOCATION_OK"
    "never writes the secret to a log")
  string(FIND "${allocation_probe}" "${required_allocation}" allocation_position)
  if(allocation_position EQUAL -1)
    message(FATAL_ERROR "coturn allocation probe is missing ${required_allocation}")
  endif()
endforeach()

file(READ "${HEYAKI_COTURN_DIR}/run_topology.sh" topology)
foreach(required_topology IN ITEMS
    "two isolated client network namespaces"
    "turnutils_stunclient"
    "inter-client forwarding is blocked"
    "TOPOLOGY_OK")
  string(FIND "${topology}" "${required_topology}" topology_position)
  if(topology_position EQUAL -1)
    message(FATAL_ERROR "coturn topology script is missing ${required_topology}")
  endif()
endforeach()
