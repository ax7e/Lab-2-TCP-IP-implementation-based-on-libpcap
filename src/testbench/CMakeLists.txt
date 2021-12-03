add_executable(link_listen link/link_test_listen.cpp)
add_executable(link_helloworld link/link_test_helloworld.cpp)
target_link_libraries(link_helloworld PUBLIC link_lib)
target_link_libraries(link_listen PUBLIC link_lib)

add_executable(ip_test ip/ip_test.cpp)
target_link_libraries(ip_test PUBLIC ip_lib)

add_executable(ip_route ip/ip_route_test.cpp)
target_link_libraries(ip_route PUBLIC ip_lib)

add_executable(show_addr link/show_address.cpp)
target_link_libraries(show_addr PUBLIC ip_lib link_lib)

add_library(unp
    tcp/unp.cpp
    tcp/unp.h
)
target_link_libraries(unp PUBLIC tcp_lib)
# set (LIB_WRAPS "-Wl,--wrap=bind,--wrap=listen,--wrap=connect,--wrap=accept,--wrap=bind,--wrap=read,--wrap=close,--wrap=getaddrinfo" tcp_lib)
# set(LIB_WRAPS "-Wl,--wrap=bind,--wrap=listen,--wrap=connect,--wrap=accept,--wrap=bind,--wrap=read,--wrap=close,--wrap=getaddrinfo" tcp_lib unp)
set(LIB_WRAPS tcp_lib unp)


add_executable(echo_client tcp/echo_client.cpp)
target_link_libraries(echo_client PUBLIC ${LIB_WRAPS})
add_executable(echo_server tcp/echo_server.cpp)
target_link_libraries(echo_server PUBLIC ${LIB_WRAPS})
add_executable(perf_server tcp/perf_server.cpp)
target_link_libraries(perf_server PUBLIC ${LIB_WRAPS})
add_executable(perf_client tcp/perf_client.cpp)
target_link_libraries(perf_client PUBLIC ${LIB_WRAPS})
add_executable(send_tcp_packet tcp/test_send_packet.cpp)
target_link_libraries(send_tcp_packet PUBLIC ${LIB_WRAPS})

add_executable(fake_client tcp/fake_echo_client.cpp)
target_link_libraries(fake_client PUBLIC ${LIB_WRAPS})
add_executable(fake_server tcp/fake_echo_server.cpp)
target_link_libraries(fake_server PUBLIC ${LIB_WRAPS})