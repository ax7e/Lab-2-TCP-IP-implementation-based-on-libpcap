#pragma once
#include <atomic>

#define TCP_SEND_BUFFER_SIZE 102400
#define TCP_MSL 10
#define TCP_RECV_BUFFER_SIZE 102400
#define TCP_HEADER_LEN 20
#define PROTO_TCP 6
#define TCP_FLAG_FIN 0x1
#define TCP_FLAG_SYN 0x2
#define TEST_MSG_CNT 10000
#define TCP_FLAG_RST 0x4
#define TCP_FLAG_PSH 0x8
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_MAX_PACKET_LENGTH 1400
#define HAS_FLAG(x,y) ((bool)(x&y))

void testTCPSendPacket();
void testTCPEchoServer(); 
void testTCPEchoClient(); 
