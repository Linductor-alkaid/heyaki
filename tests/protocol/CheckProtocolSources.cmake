foreach(required_variable IN ITEMS
    HEYAKI_PROTO_DIR
    HEYAKI_WIRE_DOCUMENT
    HEYAKI_THREAT_MODEL
    HEYAKI_GOLDEN_VECTOR_FILE
    HEYAKI_PROTOCOL_MAJOR
    HEYAKI_PROTOCOL_MINOR)
  if(NOT DEFINED ${required_variable})
    message(FATAL_ERROR "${required_variable} is required")
  endif()
endforeach()

foreach(required_file IN ITEMS
    "${HEYAKI_WIRE_DOCUMENT}"
    "${HEYAKI_THREAT_MODEL}"
    "${HEYAKI_GOLDEN_VECTOR_FILE}")
  if(NOT EXISTS "${required_file}")
    message(FATAL_ERROR "Required M1 protocol asset is missing: ${required_file}")
  endif()
endforeach()

set(protocol_domains
  common enrollment signaling session pairing message rpc event stream file shell)
foreach(domain IN LISTS protocol_domains)
  set(schema "${HEYAKI_PROTO_DIR}/heyaki/${domain}/v1/${domain}.proto")
  if(NOT EXISTS "${schema}")
    message(FATAL_ERROR "Missing versioned ${domain} schema: ${schema}")
  endif()
  file(READ "${schema}" contents)
  if(NOT contents MATCHES "syntax[ \t]*=[ \t]*\"proto3\"[ \t]*;" OR
     NOT contents MATCHES "package[ \t]+heyaki\\.protocol\\.${domain}\\.v1[ \t]*;" OR
     NOT contents MATCHES "option[ \t]+optimize_for[ \t]*=[ \t]*LITE_RUNTIME[ \t]*;")
    message(FATAL_ERROR "Schema is not a versioned Protobuf Lite schema: ${schema}")
  endif()
endforeach()

file(GLOB_RECURSE checked_in_generated
  "${HEYAKI_PROTO_DIR}/*.pb.cc"
  "${HEYAKI_PROTO_DIR}/*.pb.h")
if(checked_in_generated)
  message(FATAL_ERROR "Generated Protobuf sources must stay in the build tree: ${checked_in_generated}")
endif()

file(READ "${HEYAKI_GOLDEN_VECTOR_FILE}" golden_json)
string(JSON vector_format ERROR_VARIABLE format_error GET "${golden_json}" format)
string(JSON vector_major ERROR_VARIABLE major_error GET "${golden_json}" protocol major)
string(JSON vector_minor ERROR_VARIABLE minor_error GET "${golden_json}" protocol minor)
if(format_error OR major_error OR minor_error)
  message(FATAL_ERROR "Golden vector JSON is malformed")
endif()
if(NOT vector_format STREQUAL "heyaki-m1-golden-vectors-v1")
  message(FATAL_ERROR "Unknown golden vector format: ${vector_format}")
endif()
if(NOT vector_major EQUAL HEYAKI_PROTOCOL_MAJOR OR
   NOT vector_minor EQUAL HEYAKI_PROTOCOL_MINOR)
  message(FATAL_ERROR
    "Golden vector protocol ${vector_major}.${vector_minor} does not match build protocol "
    "${HEYAKI_PROTOCOL_MAJOR}.${HEYAKI_PROTOCOL_MINOR}")
endif()

file(READ "${HEYAKI_WIRE_DOCUMENT}" wire_document)
if(NOT wire_document MATCHES "Protocol version: ${HEYAKI_PROTOCOL_MAJOR}\\.${HEYAKI_PROTOCOL_MINOR}" OR
   NOT wire_document MATCHES "tests/vectors/m1-golden-vectors\\.json")
  message(FATAL_ERROR "Wire protocol document version/vector reference is inconsistent")
endif()

file(READ "${HEYAKI_THREAT_MODEL}" threat_model)
foreach(required_threat IN ITEMS
    "Malicious registered device"
    "Controlled relay"
    "Password guessing"
    "ProfileStore theft"
    "Replay"
    "Downgrade"
    "Resource exhaustion"
    "Path traversal"
    "Malicious terminal data"
    "Supply-chain compromise")
  if(NOT threat_model MATCHES "${required_threat}")
    message(FATAL_ERROR "Threat model is missing required threat: ${required_threat}")
  endif()
endforeach()
