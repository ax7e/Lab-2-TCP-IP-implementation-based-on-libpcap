add_executable(link_listen link/link_test_listen.cpp)
add_executable(link_helloworld link/link_test_helloworld.cpp)
target_link_libraries(link_helloworld PUBLIC link_lib)
target_link_libraries(link_listen PUBLIC link_lib)

add_executable(ip_test ip/ip_test.cpp)
target_link_libraries(ip_test PUBLIC ip_lib)

add_executable(show_addr link/show_address.cpp)
target_link_libraries(show_addr PUBLIC ip_lib link_lib)