#include "tcp_impl.h"
#include <thread>
#include <cstring>
#include <sys/socket.h>
#include "src/ip/ip.h"
#include <set>
#include <map>
#include <mutex>
#include <vector>
#include <cassert>
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
    CLOSED, 
    CLOSEING,
    LISTEN, 
    SYN_RCVD, 
    SYN_SENT, 
    ESTAB, 
    FINWAIT_1,
    FINWAIT_2,
    CLOSE_WAIT, 
    LAST_ACK,
    //TODO: Not implemented yet
    TIMEWAIT
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
    // [0, snd_una)-[snd_una, snd_nxt)-[snd_nxt, snd_sqn) 
    int snd_una;
    int snd_nxt;
    //TODO : NOT IMPLEMENTED
    int snd_wnd;
    int snd_iss;
    int snd_sqn;
    uint32_t iss;
    int rcv_nxt;
    //TODO : NOT IMPLEMENTED
    int rcv_wnd;
    std::mutex mutex;
    bool legalToSend() { 
        static const std::set<TCPState> legal = { TCPState::ESTAB, TCPState::CLOSE_WAIT }; 
        if (!legal.count(state)) {
            printf("[Err] Try to send packet in closed TCP state machine.\n"); 
            return false;
        }
        return true;
    }
    void clearBufferedTCPPacket() {
        if (!legalToSend()) return;
        while (snd_sqn > snd_nxt) {
            int len = std::min(TCP_MAX_PACKET_LENGTH, snd_sqn - snd_nxt);
            sendTCPPacket(nullptr, 0, TCP_FLAG_ACK);
            snd_nxt += len;
        }
    }
    int sendPacket(const void *buf, int len, uint8_t flags = TCP_FLAG_ACK, bool imme = false) {
        if (!legalToSend()) return -1;
        __sendPacket(buf, len, flags, imme);
        return 0; 
    }
    int __sendPacket(const void *buf, int len, uint8_t flags = TCP_FLAG_ACK, bool imme = false)
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (imme) {
            clearBufferedTCPPacket();
        }
        if (snd_una - snd_iss > TCP_SEND_BUFFER_SIZE)
        {
            memcpy(sendBuffer, sendBuffer + TCP_SEND_BUFFER_SIZE, TCP_SEND_BUFFER_SIZE);
            snd_iss += TCP_SEND_BUFFER_SIZE;
        }
        if (snd_sqn - snd_iss + len > TCP_SEND_BUFFER_SIZE * 2)
        {
            printf("[Err] TCP send buffer overflow\n");
            return -1;
        }
        memcpy(sendBuffer + snd_sqn - snd_iss, buf, TCP_SEND_BUFFER_SIZE);
        snd_sqn += len != 0 ? len : 1;
        if (imme) {
            sendTCPPacket(buf, len, flags); 
        }
        return 0;
    }
    int sendTCPPacket(const void *buf, int len, uint8_t flags) {
        char obuf[len + TCP_HEADER_LEN];
        tcp_header_t* header = (tcp_header_t*)obuf;
        header->srcPort = htons(socket.srcPort); 
        header->dstPort = htons(socket.dstPort);
        header->seq = htonl(seq);
        header->ack = htonl(ack); 
        header->offset = 5<<4;
        header->flags = flags;
        header->window = htons(snd_wnd);
        header->urgentP = 0;
        memcpy(obuf + TCP_HEADER_LEN, buf, TCP_HEADER_LEN);
        ip_header_t fakeHeader;
        fakeHeader.src_addr = socket.srcIP;
        fakeHeader.dst_addr = socket.dstIP;
        fakeHeader.protocol = PROTO_TCP;
        calcTCPChecksum(fakeHeader, obuf, len);
        if (sendIPPacket(socket.srcIP, socket.dstIP, PROTO_TCP, obuf, len + TCP_HEADER_LEN)) {
            printf("[Err] sendPacket failed at sendIPPacket.\n");
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
    void sendCloseSignal() {
        std::lock_guard<std::mutex> lock(mutex);
        switch (state)
        {
        case TCPState::CLOSED: 
            break;
        case TCPState::CLOSE_WAIT:
            __sendPacket(nullptr, 0, TCP_FLAG_FIN, true); 
            state = TCPState::LAST_ACK;
            break;
        case TCPState::LISTEN:
            state = TCPState::CLOSED;
            break;
        case TCPState::SYN_RCVD:
            __sendPacket(nullptr, 0, TCP_FLAG_FIN, true); 
            state = TCPState::FINWAIT_1;
            break;
        case TCPState::SYN_SENT:
            state = TCPState::CLOSED;
            break;
        case TCPState::ESTAB:
            __sendPacket(nullptr, 0, TCP_FLAG_FIN, true);
            state = TCPState::FINWAIT_1;
            break;
        case TCPState::CLOSEING:
        case TCPState::FINWAIT_1:
        case TCPState::FINWAIT_2:
        case TCPState::LAST_ACK:
        case TCPState::TIMEWAIT:
            printf("[Err] Double close TCP connection.\n");
            exit(-1); 
            break;
        }
    }
    void processTCPStateMachineOnReceive(const void *buf, int len)
    {
        std::lock_guard<std::mutex> lock(mutex);
        tcp_header_t *hdr = (tcp_header_t *)buf;
        auto syn = [&]
        { return (HAS_FLAG(hdr->flags, TCP_FLAG_SYN)); };
        auto ack = [&]
        { return (HAS_FLAG(hdr->flags, TCP_FLAG_ACK)); };
        auto valid_ack = [&]
        { return ack() && hdr->ack == rcv_nxt; };
        auto fin = [&]
        { return (HAS_FLAG(hdr->flags, TCP_FLAG_FIN)); };
        auto sqn = [&] { return hdr->seq; };
        switch (state)
        {
        case TCPState::CLOSED:
            break;
        case TCPState::CLOSE_WAIT:
            break;
        case TCPState::LISTEN:
            if (syn() && !valid_ack())
            {
                __sendPacket(nullptr, 0, TCP_FLAG_SYN | TCP_FLAG_ACK, true); 
                state = TCPState::SYN_RCVD;
            }
            break;
        case TCPState::SYN_RCVD:
            if (valid_ack() && !syn()) {
                state = TCPState::ESTAB;
            }
            break;
        case TCPState::SYN_SENT:
            if (!valid_ack() && syn()) {
                rcv_nxt = hdr->seq + 1; 
                __sendPacket(nullptr, 0, TCP_FLAG_ACK, true); 
                state = TCPState::SYN_RCVD;
            } else if (valid_ack() && syn()) {
                __sendPacket(nullptr, 0, TCP_FLAG_ACK, true);
                state = TCPState::ESTAB;
            }
            break;
        case TCPState::ESTAB:
            if (fin())
            {
                __sendPacket(nullptr, 0, TCP_FLAG_ACK, true);
                state = TCPState::CLOSE_WAIT;
            } else if (syn()) {
                printf("[Err] Curious packet contains syn was dropped.\n");
                break;
            } else {
                goto receivePacket;
            }
            break;
        case TCPState::FINWAIT_1:
            if (valid_ack()) {
                state = TCPState::FINWAIT_2;
            } else if (fin()) {
                state = TCPState::CLOSEING;
            }
            goto receivePacket;
            break;
        case TCPState::FINWAIT_2:
            if (fin()) {
                __sendPacket(nullptr, 0, TCP_FLAG_ACK, true);
                state = TCPState::TIMEWAIT;
            }
            goto receivePacket;
            break;
        case TCPState::LAST_ACK:
            if (valid_ack()) {
                state = TCPState::CLOSED;
            }
            break;
        case TCPState::TIMEWAIT:
            //TODO: Implement this
            state = TCPState::CLOSED;
            break;
        case TCPState::CLOSEING:
            if (valid_ack()) {
                state = TCPState::TIMEWAIT;
            }
        receivePacket:
            if (hdr->seq == rcv_nxt) {
                hdr->seq += len - TCP_HEADER_LEN; 
                printf("[Info] Received packet of [%d,%d).\n", hdr->seq - len + TCP_HEADER_LEN, hdr->seq);
            }
        }
    }
};

void tcpSenderThread(TCB &c)
{
    while (true)
    {
        {
            std::lock_guard<std::mutex> lock(c.mutex);
            c.clearBufferedTCPPacket();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); 
        return;
    }
}

void initTCPConnection(TCB &c)
{
    c.sendBuffer = new uint8_t[TCP_SEND_BUFFER_SIZE << 1];
    c.iss = rand();
    c.thread = std::thread(tcpSenderThread, std::ref(c));
}

void freeConnectionBuffer(TCB &c)
{
    delete c.sendBuffer;
}

std::map<socket_t, TCB> connections;

//typedef int (*IPPacketReceiveCallback)(const void *buf, int len);
int TCPPacketReceiveIPInterface(const void *buf, int len)
{
    if (len < IP_HEADER_LEN + TCP_HEADER_LEN)
    {
        printf("[Err] Invalid TCP header.");
        return -1;
    }
    ip_header_t *header_ip = (ip_header_t *)(buf);
    tcp_header_t *header_tcp = (tcp_header_t *)((char *)header_ip + TCP_HEADER_LEN);
    auto key = socket_t(header_tcp->srcPort, header_tcp->dstPort, header_ip->src_addr, header_ip->dst_addr);
    if (!connections.count(key))
    {
        printf("[Err] TCP connection does not exist\n");
        return -1;
    }
    connections[key].processTCPStateMachineOnReceive(buf, len);
    return 0;
}

vector<std::future<int>> initTcpService(int cnt)
{
    return initRouteService(cnt);
}

//Just for debug.
void testTCPSendPacket(){
    TCB c; 
    auto r = initTcpService(100); 
    initTCPConnection(c); 
    c.socket.dstIP = 0x0a640101;
    c.socket.srcIP = 0x23333332;
    c.socket.srcPort = 123;
    c.socket.dstPort = 456;
    char buf[] = "Hello World!"; 
    for (int i = 0; i < 100;++i) {
        printf("[Info] Before send TCP Packet.\n");
        c.sendTCPPacket(buf, strlen(buf), TCP_FLAG_SYN);
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }
}

//Just for debug.
void testTCPEchoServer() {
    TCB c; 
    c.socket.dstIP = 0x0a640101;
    c.socket.srcIP = 0x23333332;
    c.socket.srcPort = 123;
    c.socket.dstPort = 456;
    auto r = initTcpService(100); 
}


void testTCPEchoClient() {
    TCB c; 
    c.socket.srcIP = 0x0a640101;
    c.socket.dstIP = 0x23333332;
    c.socket.dstPort = 123;
    c.socket.srcPort = 456;

}