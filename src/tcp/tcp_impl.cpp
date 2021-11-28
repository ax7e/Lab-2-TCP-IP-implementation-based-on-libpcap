#include "tcp_impl.h"
#include <thread>
#include <sys/socket.h>
#include "src/ip/ip.h"
#include <set>
#include <map>
#include <mutex>
#include <vector>
#include <future>

struct tcp_header_t {
    uint16_t srcPort;
    uint16_t dstPort; 
    uint32_t seq; 
    uint32_t ack;
    uint8_t offset;
    uint8_t flags;
    uint16_t window; 
    uint16_t checksum;
    uint16_t urgentP;
};

enum struct TCPState {
    TCP_CLOSED, 
    TCP_LISTEN, 
    TCP_SYN_RCVD, 
    TCP_SYN_SENT, 
    TCP_ESTAB, 
    TCP_FINWAIT_1,
    TCP_CLOSE_WAIT, 
    TCP_LAST_ACK,
    TCP_FINWAIT_2
};

struct socket_t {
    int srcPort;
    //In network form
    uint32_t srcIP;
    //In network form
    uint32_t dstIP;
    int dstPort;
    socket_t() = default;
    socket_t(int srcPort, uint32_t srcIP, uint32_t dstIP, int dstPort):
        srcPort(srcPort), srcIP(srcIP), dstIP(dstIP), dstPort(dstPort) {

        }
};

bool operator<(const socket_t &lhs, const socket_t &rhs) {
    int v[4];
    v[0] = lhs.srcPort - rhs.srcPort;
    v[1] = (int)(lhs.srcIP - rhs.srcIP);
    v[2] = lhs.srcPort - rhs.srcPort;
    v[3] = (int)(lhs.dstIP - rhs.dstIP);
    for (int i = 0;i < 4;++i) if (v[i] != 0) {
        if (v[i] < 0) return true; 
        else return false;
    }
    return false;
}

struct TCB {
    std::thread thread;
    TCPState state;
    socket_t socket;
    int seq, ack;
    uint8_t *sendBuffer;
    // Send buffer length
    int snd_una;
    int snd_nxt;
    int snd_wnd;
    int snd_iss;
    int snd_sqn;
    uint32_t iss;
    // Double buffer, the latter part 
    uint8_t *receiveBuffer;
    // Receive buffer length
    int rbl;
    int rcv_nxt;
    int rcv_wnd;
    int rcv_off = 0; 
    int irs;
    std::mutex mutex;
    int bufferTCPPacket(const void *buf, int len)
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (snd_una - snd_iss > TCP_SEND_BUFFER_SIZE) {
            memcpy(sendBuffer, sendBuffer + TCP_SEND_BUFFER_SIZE, TCP_SEND_BUFFER_SIZE);
            snd_iss += TCP_SEND_BUFFER_SIZE;
        }
        if (snd_sqn - snd_iss + len > TCP_SEND_BUFFER_SIZE * 2) {
            printf("[Err] TCP send buffer overflow\n");
            return -1;
        }
        memcpy(sendBuffer + snd_sqn - snd_iss, buf, TCP_SEND_BUFFER_SIZE);
        snd_sqn += len;
        return 0; 
    }
    int sendTCPPacket(const void *buf, int len, uint8_t flags) {
        char obuf[len + TCP_HEADER_LEN];
        tcp_header_t* header = (tcp_header_t*)obuf;
        header->srcPort = htons(socket.srcPort); 
        header->dstPort = htons(socket.dstPort);
        header->seq = htonl(seq);
        header->ack = htonl(ack); 
        header->offset = TCP_HEADER_LEN * 8;
        header->flags = flags;
        header->window = htons(snd_wnd);
        header->urgentP = 0;
        memcpy(obuf + TCP_HEADER_LEN, buf, TCP_HEADER_LEN);
        ip_header_t fakeHeader;
        fakeHeader.src_addr = socket.srcIP;
        fakeHeader.dst_addr = socket.dstIP;
        fakeHeader.protocol = PROTO_TCP;
        calcTCPChecksum(fakeHeader, obuf, len);
        if (sendIPPacket(socket.srcIP, socket.dstIP, PROTO_TCP, obuf, len)) {
            printf("[Err] sendTCPPacket failed at sendIPPacket.");
            return -1; 
        }
        return 0; 
    }
    static void calcTCPChecksum(const ip_header_t &fakeHeader, char *obuf, int len) {
        tcp_header_t *header=(tcp_header_t *)obuf;
        header->checksum = 0;
        uint32_t sum = 0; 
        sum += fakeHeader.src_addr >> 16;
        sum += fakeHeader.src_addr & 0xFFFF; 
        sum += fakeHeader.dst_addr >> 16;
        sum += fakeHeader.dst_addr & 0xFFFF;
        sum += ntohs(fakeHeader.protocol);
        sum += ntohs((uint16_t)(len + TCP_HEADER_LEN));
        for (int i = 0;i < TCP_HEADER_LEN+len;i += 2) {
            if (i+1<TCP_HEADER_LEN+len) 
                sum += ((uint16_t*)obuf)[i/2];
            else 
                sum += (uint16_t)obuf[i];
        }
        while(sum>>16)sum=(sum&0xFFFF)+(sum>>16);
        header->checksum = ~sum;
    }
    ~TCB(){
        thread.join();
    }
};

void tcpSenderThread(TCB& c) {
    while(true) {
        return;
    }
}

void initConnectionBuffer(TCB &c) {
    c.sendBuffer = new uint8_t[TCP_SEND_BUFFER_SIZE << 1];
    c.receiveBuffer = new uint8_t[TCP_SEND_BUFFER_SIZE << 1];
    c.iss = rand();
    c.thread = std::thread(tcpSenderThread, std::ref(c)); 
}

void freeConnectionBuffer(TCB &c) {
    delete c.sendBuffer;
    delete c.receiveBuffer;
}


std::map<socket_t,TCB> connections;

void processTCPStateMachineOnReceive(TCB &c, const void *buf, int len) {
    std::lock_guard<std::mutex> lock(c.mutex);
    switch (c.state) {
    case TCPState::TCP_CLOSED:
    break;
    case TCPState::TCP_CLOSE_WAIT:
    break;
    case TCPState::TCP_LISTEN:
    break;
    case TCPState::TCP_SYN_RCVD:
    break;
    case TCPState::TCP_SYN_SENT:
    break;
    case TCPState::TCP_ESTAB:
    break;
    case TCPState::TCP_FINWAIT_1:
    break;
    case TCPState::TCP_FINWAIT_2:
    break;
    case TCPState::TCP_LAST_ACK:
    break;
    }
}

//typedef int (*IPPacketReceiveCallback)(const void *buf, int len);
int TCPPacketReceiveIPInterface(const void *buf, int len) {
    if (len < IP_HEADER_LEN + TCP_HEADER_LEN) {
        printf("[Err] Invalid TCP header."); 
        return -1;
    }
    ip_header_t *header_ip = (ip_header_t*)(buf);
    tcp_header_t *header_tcp = (tcp_header_t*)((char*)header_ip + TCP_HEADER_LEN);
    auto key = socket_t(header_tcp->srcPort, header_tcp->dstPort, header_ip->src_addr, header_ip->dst_addr); 
    if (!connections.count(key)) {
        printf("[Err] TCP connection does not exist\n");
        return -1;
    }
    processTCPStateMachineOnReceive(connections[key], buf, len);
    return 0;
}

vector<std::future<int>> initTcpService(int cnt) {
    return initRouteService(cnt); 
}