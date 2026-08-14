cmake_minimum_required(VERSION 3.25)
project(heyaki_consumer LANGUAGES CXX)

find_package(heyaki CONFIG REQUIRED)

add_executable(heyaki_consumer main.cpp)
target_compile_features(heyaki_consumer PRIVATE cxx_std_20)
target_link_libraries(heyaki_consumer PRIVATE
  heyaki::core
  heyaki::profile
  heyaki::client
  heyaki::services
  heyaki::transport_webrtc)

