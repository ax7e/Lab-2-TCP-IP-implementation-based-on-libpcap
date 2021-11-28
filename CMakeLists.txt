# This CMakefile is copyed and changed from gzz2000's git repo
cmake_minimum_required(VERSION 3.10)

project(lab2)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
include(envs/pcap-config.cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -lpcap -lpthread -O0 -Wall -Wno-sign-compare -ggdb3 -DZDEBUG -Wl,--wrap=getaddrinfo,--wrap=freeaddrinfo")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -lpcap -lpthread -O2 -Wall -Wno-sign-compare -Wl,--wrap=getaddrinfo,--wrap=freeaddrinfo")

include_directories(PUBLIC "${PROJECT_SOURCE_DIR}")

add_library(link_lib
  src/link/link.h
  src/link/device.cpp
  src/link/packetio.cpp
)
target_link_libraries(link_lib PUBLIC  ${PCAP_LIBRARY} Threads::Threads)

add_library(ip_lib
  src/ip/ip.cpp
  src/ip/ip_route.cpp
  )
target_link_libraries(ip_lib PUBLIC  ${PCAP_LIBRARY} Threads::Threads link_lib)

add_library(tcp_lib
  src/tcp/socket.h
  src/tcp/socket_wrapper.cpp
  src/tcp/tcp_impl.cpp
  src/tcp/tcp_impl.h
)
target_link_libraries(tcp_lib PUBLIC  ${PCAP_LIBRARY} Threads::Threads link_lib ip_lib)
add_subdirectory(src/testbench)