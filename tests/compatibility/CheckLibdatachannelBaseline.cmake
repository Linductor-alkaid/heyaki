file(READ "${HEYAKI_LIBDATACHANNEL_SOURCE_DIR}/CMakeLists.txt" cmake_source)
file(READ "${HEYAKI_LIBDATACHANNEL_SOURCE_DIR}/src/impl/icetransport.cpp" ice_source)

foreach(required_default IN ITEMS
    "option(USE_GNUTLS \"Use GnuTLS instead of OpenSSL\" OFF)"
    "option(USE_MBEDTLS \"Use Mbed TLS instead of OpenSSL\" OFF)"
    "option(USE_NICE \"Use libnice instead of libjuice\" OFF)")
  string(FIND "${cmake_source}" "${required_default}" default_index)
  if(default_index EQUAL -1)
    message(FATAL_ERROR
      "Pinned libdatachannel baseline changed; missing default: ${required_default}")
  endif()
endforeach()

foreach(required_ice_behavior IN ITEMS
    "TURN transports TCP and TLS are not supported with libjuice"
    "NICE_RELAY_TYPE_TURN_TCP"
    "NICE_RELAY_TYPE_TURN_TLS"
    "NICE_RELAY_TYPE_TURN_UDP")
  string(FIND "${ice_source}" "${required_ice_behavior}" behavior_index)
  if(behavior_index EQUAL -1)
    message(FATAL_ERROR
      "Pinned libdatachannel ICE behavior changed; missing: ${required_ice_behavior}")
  endif()
endforeach()
