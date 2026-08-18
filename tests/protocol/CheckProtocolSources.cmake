foreach(required_variable IN ITEMS
    HEYAKI_PROTO_DIR
    HEYAKI_WIRE_DOCUMENT
    HEYAKI_THREAT_MODEL
    HEYAKI_GOLDEN_VECTOR_FILE
    HEYAKI_M3A_GOLDEN_VECTOR_FILE
    HEYAKI_PROTOCOL_MAJOR
    HEYAKI_PROTOCOL_MINOR)
  if(NOT DEFINED ${required_variable})
    message(FATAL_ERROR "${required_variable} is required")
  endif()
endforeach()

foreach(schema_contract IN ITEMS
    "common|enum ErrorCode"
    "discovery|message LanPresence"
    "discovery|uint64 sequence = 7"
    "enrollment|message EndpointRecord"
    "enrollment|message EnrollmentResult"
    "enrollment|message ControlError"
    "enrollment|message ServiceManifest"
    "signaling|bytes initiator_nonce = 5"
    "signaling|optional bytes responder_nonce = 7"
    "signaling|bytes signaling_transcript_sha256 = 4"
    "signaling|string owner_ice_ufrag = 5"
    "signaling|bytes owner_dtls_fingerprint = 6"
    "session|bytes signaling_transcript_sha256 = 7"
    "file|message FileReject"
    "shell|message ShellEof"
    "shell|message ShellError"
    "shell|message ShellClose")
  string(REPLACE "|" ";" contract_parts "${schema_contract}")
  list(GET contract_parts 0 domain)
  list(GET contract_parts 1 required_text)
  set(schema "${HEYAKI_PROTO_DIR}/heyaki/${domain}/v1/${domain}.proto")
  file(READ "${schema}" contents)
  string(FIND "${contents}" "${required_text}" required_position)
  if(required_position EQUAL -1)
    message(FATAL_ERROR "Schema contract '${required_text}' is missing from ${schema}")
  endif()
endforeach()

set(relay_control_schema "${HEYAKI_PROTO_DIR}/heyaki/relay/v1/relay_control.proto")
if(NOT EXISTS "${relay_control_schema}")
  message(FATAL_ERROR "Missing versioned relay control schema: ${relay_control_schema}")
endif()
file(READ "${relay_control_schema}" relay_control_contents)
foreach(relay_control_contract IN ITEMS
    "package heyaki.protocol.relay.v1;"
    "option optimize_for = LITE_RUNTIME;"
    "message LoginResult"
    "message HeartbeatRequest"
    "message EndpointPublish"
    "message EndpointQueryResult"
    "message SignalingSend"
    "message SignalingDeliver")
  string(FIND "${relay_control_contents}" "${relay_control_contract}" contract_position)
  if(contract_position EQUAL -1)
    message(FATAL_ERROR "Schema contract '${relay_control_contract}' is missing from ${relay_control_schema}")
  endif()
endforeach()

set(lan_schema "${HEYAKI_PROTO_DIR}/heyaki/signaling/v1/lan.proto")
if(NOT EXISTS "${lan_schema}")
  message(FATAL_ERROR "Missing versioned LAN signaling schema: ${lan_schema}")
endif()
file(READ "${lan_schema}" lan_schema_contents)
foreach(lan_schema_contract IN ITEMS
    "package heyaki.protocol.signaling.v1;"
    "option optimize_for = LITE_RUNTIME;"
    "message LanHello"
    "bytes sender_tls_certificate_sha256 = 7"
    "bytes observed_peer_tls_certificate_sha256 = 8")
  string(FIND "${lan_schema_contents}" "${lan_schema_contract}" contract_position)
  if(contract_position EQUAL -1)
    message(FATAL_ERROR "Schema contract '${lan_schema_contract}' is missing from ${lan_schema}")
  endif()
endforeach()

foreach(raw_header_contract IN ITEMS
    "stream|message StreamDataHeader"
    "file|message FileChunkHeader"
    "shell|message ShellDataHeader")
  string(REPLACE "|" ";" contract_parts "${raw_header_contract}")
  list(GET contract_parts 0 domain)
  list(GET contract_parts 1 forbidden_text)
  set(schema "${HEYAKI_PROTO_DIR}/heyaki/${domain}/v1/${domain}.proto")
  file(READ "${schema}" contents)
  string(FIND "${contents}" "${forbidden_text}" forbidden_position)
  if(NOT forbidden_position EQUAL -1)
    message(FATAL_ERROR "Raw payload header '${forbidden_text}' must not be a Protobuf schema")
  endif()
endforeach()

foreach(required_file IN ITEMS
    "${HEYAKI_WIRE_DOCUMENT}"
    "${HEYAKI_THREAT_MODEL}"
    "${HEYAKI_GOLDEN_VECTOR_FILE}"
    "${HEYAKI_M3A_GOLDEN_VECTOR_FILE}")
  if(NOT EXISTS "${required_file}")
    message(FATAL_ERROR "Required M1 protocol asset is missing: ${required_file}")
  endif()
endforeach()

set(protocol_domains
  common discovery enrollment signaling session pairing message rpc event stream file shell)
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
string(JSON canonical_hex ERROR_VARIABLE canonical_error GET
  "${golden_json}" canonical_offer canonical_hex)
string(JSON signed_message_hex ERROR_VARIABLE signed_message_error GET
  "${golden_json}" ed25519_canonical_offer message_hex)
string(JSON signature_hex ERROR_VARIABLE signature_error GET
  "${golden_json}" ed25519_canonical_offer signature_hex)
string(JSON transcript_domain ERROR_VARIABLE transcript_domain_error GET
  "${golden_json}" signaling_transcript domain)
string(JSON transcript_hash ERROR_VARIABLE transcript_hash_error GET
  "${golden_json}" signaling_transcript sha256_hex)
if(format_error OR major_error OR minor_error OR canonical_error OR signed_message_error OR
   signature_error OR transcript_domain_error OR transcript_hash_error)
  message(FATAL_ERROR "Golden vector JSON is malformed")
endif()
string(LENGTH "${transcript_hash}" transcript_hash_length)
if(NOT transcript_domain STREQUAL "heyaki.signaling-transcript.v1" OR
   NOT transcript_hash_length EQUAL 64)
  message(FATAL_ERROR "Signaling transcript vector must contain the v1 domain and SHA-256")
endif()
if(NOT vector_format STREQUAL "heyaki-m1-golden-vectors-v1")
  message(FATAL_ERROR "Unknown golden vector format: ${vector_format}")
endif()
string(LENGTH "${signature_hex}" signature_hex_length)
if(NOT signed_message_hex STREQUAL canonical_hex OR NOT signature_hex_length EQUAL 128)
  message(FATAL_ERROR "Ed25519 vector must sign the canonical offer and contain 64 signature bytes")
endif()
if(NOT vector_major EQUAL 1 OR NOT vector_minor EQUAL 0)
  message(FATAL_ERROR
    "M1 N-1 golden vector must remain protocol 1.0, got ${vector_major}.${vector_minor}")
endif()

file(READ "${HEYAKI_M3A_GOLDEN_VECTOR_FILE}" m3a_golden_json)
string(JSON m3a_format ERROR_VARIABLE m3a_format_error GET "${m3a_golden_json}" format)
string(JSON m3a_major ERROR_VARIABLE m3a_major_error GET "${m3a_golden_json}" protocol major)
string(JSON m3a_minor ERROR_VARIABLE m3a_minor_error GET "${m3a_golden_json}" protocol minor)
string(JSON m3a_datagram_magic ERROR_VARIABLE m3a_magic_error GET
  "${m3a_golden_json}" discovery datagram_magic_hex)
string(JSON m3a_max_datagram ERROR_VARIABLE m3a_datagram_error GET
  "${m3a_golden_json}" discovery max_datagram_bytes)
string(JSON m3a_public_key ERROR_VARIABLE m3a_public_key_error GET
  "${m3a_golden_json}" signing_key public_key_hex)
string(JSON m3a_presence_domain ERROR_VARIABLE m3a_presence_domain_error GET
  "${m3a_golden_json}" canonical_lan_presence domain)
string(JSON m3a_presence_signature ERROR_VARIABLE m3a_presence_signature_error GET
  "${m3a_golden_json}" canonical_lan_presence signature_hex)
string(JSON m3a_hello_domain ERROR_VARIABLE m3a_hello_domain_error GET
  "${m3a_golden_json}" canonical_lan_hello domain)
string(JSON m3a_hello_signature ERROR_VARIABLE m3a_hello_signature_error GET
  "${m3a_golden_json}" canonical_lan_hello signature_hex)
if(m3a_format_error OR m3a_major_error OR m3a_minor_error OR m3a_magic_error OR
   m3a_public_key_error OR
   m3a_datagram_error OR m3a_presence_domain_error OR m3a_presence_signature_error OR
   m3a_hello_domain_error OR m3a_hello_signature_error)
  message(FATAL_ERROR "M3A LAN golden vector JSON is malformed")
endif()
string(LENGTH "${m3a_presence_signature}" m3a_presence_signature_length)
string(LENGTH "${m3a_hello_signature}" m3a_hello_signature_length)
string(LENGTH "${m3a_public_key}" m3a_public_key_length)
if(NOT m3a_format STREQUAL "heyaki-m3a-lan-golden-vectors-v1" OR
   NOT m3a_major EQUAL HEYAKI_PROTOCOL_MAJOR OR
   NOT m3a_minor EQUAL HEYAKI_PROTOCOL_MINOR OR
   NOT m3a_datagram_magic STREQUAL "48594c44" OR
   NOT m3a_max_datagram EQUAL 1200 OR
   NOT m3a_public_key_length EQUAL 64 OR
   NOT m3a_presence_domain STREQUAL "heyaki.lan-presence.v1" OR
   NOT m3a_hello_domain STREQUAL "heyaki.lan-hello.v1" OR
   NOT m3a_presence_signature_length EQUAL 128 OR
   NOT m3a_hello_signature_length EQUAL 128)
  message(FATAL_ERROR "M3A LAN vector version, envelope, domain, or signature is inconsistent")
endif()

file(READ "${HEYAKI_WIRE_DOCUMENT}" wire_document)
if(NOT wire_document MATCHES "Protocol version: ${HEYAKI_PROTOCOL_MAJOR}\\.${HEYAKI_PROTOCOL_MINOR}" OR
   NOT wire_document MATCHES "tests/vectors/m1-golden-vectors\\.json" OR
   NOT wire_document MATCHES "tests/vectors/m3a-lan-golden-vectors\\.json" OR
   NOT wire_document MATCHES "239\\.192\\.72\\.89" OR
   NOT wire_document MATCHES "ff12::4845:5941:4b49" OR
   NOT wire_document MATCHES "heyaki\\.lan-presence\\.v1" OR
   NOT wire_document MATCHES "heyaki\\.lan-hello\\.v1" OR
   NOT wire_document MATCHES "heyaki\\.enrollment-record\\.v1" OR
   NOT wire_document MATCHES "responder nonce" OR
   NOT wire_document MATCHES "heyaki\\.signaling-transcript\\.v1" OR
   NOT wire_document MATCHES "StreamData :=" OR
   NOT wire_document MATCHES "`0x78`.*`SHELL_CLOSE`")
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
