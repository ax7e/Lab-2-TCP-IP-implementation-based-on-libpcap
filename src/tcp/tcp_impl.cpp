#include <set>
#include <map>
#include <mutex>
#include <deque>
#include <thread>
#include <vector>
#include <future>
#include <cassert>
#include <cstring>
#include "tcp_impl.h"
#include "src/ip/ip.h"
#include <sys/socket.h>

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

string to_string(TCPState state) {
#define BRANCH(x) if(state==TCPState::x)return #x;
    BRANCH(CLOSED)
    BRANCH(CLOSEING)
    BRANCH(LISTEN) 
    BRANCH(SYN_RCVD) 
    BRANCH(SYN_SENT) 
    BRANCH(ESTAB) 
    BRANCH(FINWAIT_1)
    BRANCH(FINWAIT_2)
    BRANCH(CLOSE_WAIT) 
    BRANCH(LAST_ACK)
    BRANCH(TIMEWAIT)
    return "Error";
}

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

//typedef int (*IPPacketReceiveCallback)(const void *buf, int len);
void debugTCPPacket(const void *buf, int len) {
    printf("[Info] TCP packet:\n");
    tcp_header_t *header = (tcp_header_t *)((char*)buf + IP_HEADER_LEN);
    ip_header_t *hdr_ip = (ip_header_t *)(buf);
    printf("(%x:%d<->%x:%d),", hdr_ip->src_addr, ntohs(header->srcPort), (hdr_ip->dst_addr), ntohs(header->dstPort)); 
    printf("[ack:%d,seq:%d,window:%d,checksum:%x]\n",ntohl(header->ack),ntohl(header->seq),header->window,header->checksum);
    printf("Flags:");
#define CHECK_FLAG(x) if (header->flags&TCP_FLAG_##x){printf(#x);putchar(' ');}
    CHECK_FLAG(URG)
    CHECK_FLAG(ACK)
    CHECK_FLAG(PSH)
    CHECK_FLAG(RST)
    CHECK_FLAG(SYN)
    CHECK_FLAG(FIN)
    puts("");
}

struct TCB {
    std::thread thread;
    TCPState state;
    socket_t socket;
    int ack;
    uint8_t *sendBuffer;
    // [0, snd_una)-[snd_una, snd_nxt)-[snd_nxt, snd_sqn) 
    int snd_una;
    //TODO : NOT IMPLEMENTED
    int snd_nxt;
    //TODO : NOT IMPLEMENTED
    int snd_wnd;
    int snd_iss;
    int snd_sqn;
    int rcv_nxt;
    vector<char> rcv_buf;
    // request buffer, the promise<int> marks whether the read request is finished, 0 makrs succeed, -1 otherwise.
    std::deque<std::tuple<char*,int,std::promise<int>> > rcv_requests; 
    int rcv_buf_p;
    /** There are several cases on receiving data
     *  1. connection not established, buffer the request
     *  2. connection established, buffer the request and process
     *  3. sender closed, do not buffer new data, but still answer user using the old data
     */
    std::future<int> readData(char *buf, int len) {
        static const std::set<TCPState> ill = { TCPState::CLOSEING, TCPState::LAST_ACK, TCPState::TIMEWAIT, TCPState::CLOSED };
        std::lock_guard<std::mutex> lock(mutex); 
        std::promise<int> pro;
        auto f = pro.get_future();
        if (ill.count(state)) {
            pro.set_value(-1); 
            return f;
        }
        rcv_requests.push_back(std::make_tuple(buf, len, std::move(pro)));
        processReceiveRequest(); 
        return f;
    }
    void processReceiveRequest() {
        static const std::set<TCPState> ill = { TCPState::CLOSEING, TCPState::LAST_ACK, TCPState::TIMEWAIT, TCPState::CLOSED,
            TCPState::CLOSE_WAIT};
        int s = rcv_buf.size(); 
        while (rcv_buf_p < s) {
            while (!rcv_requests.empty() && s - rcv_buf_p >= std::get<1>(rcv_requests.front())) {
                memcpy(std::get<0>(rcv_requests.front()), 
                    &rcv_buf[rcv_buf_p], std::get<1>(rcv_requests.front()));
                std::get<2>(rcv_requests.front()).set_value(0); 
                rcv_requests.pop_front();
            }
        }
        //No furthur incoming packet, release all the request.
        if (ill.count(state))
        {
            while (!rcv_requests.empty())
            {
                std::get<2>(rcv_requests.front()).set_value(-1);
                rcv_requests.pop_front();
            }
        }
    }
    //TODO : NOT IMPLEMENTED
    int rcv_wnd;
    std::mutex mutex;
    bool legalToSend() { 
        //TODO: User should be able to send a syn request under listen state according to RFC 793
        static const std::set<TCPState> legal = { TCPState::ESTAB, TCPState::CLOSE_WAIT, 
            TCPState::SYN_SENT, TCPState::SYN_RCVD}; 
        if (!legal.count(state)) {
            return false;
        }
        return true;
    }
    /*
    bool legalToReceive() {
        static const std::set<TCPState> legal = { TCPState::ESTAB, TCPState::LISTEN, TCPState::SYN_SENT, TCPState::SYN_RCVD, };
        if (!legal.count(state)) {
            return false;
        }
        return true;
    }
    */
    void clearBufferedTCPPacket() {
        if (!legalToSend()) return;
        while (snd_sqn > snd_nxt) {
            int len = std::min(TCP_MAX_PACKET_LENGTH, snd_sqn - snd_nxt);
            constructTCPPacket(nullptr, 0, TCP_FLAG_ACK);
            snd_nxt += len;
        }
    }
    void checkShrink(){
        int s = rcv_buf.size() - rcv_buf_p;
        if (rcv_buf.size() > 100 && rcv_buf.size() - rcv_buf_p < rcv_buf.size() / 2) {
            for (int i = 0;i < rcv_buf.size() - rcv_buf_p;i++) {
                rcv_buf[i] = rcv_buf[i+rcv_buf_p];
            }
            rcv_buf_p = 0; 
        }
    }
    void pushReceiveBuffer(char *buf, int len) {
        checkShrink(); 
        for (int i = 0;i < len;++i) rcv_buf.push_back(buf[i]); 
    }
    void init()
    {
        sendBuffer = new uint8_t[TCP_SEND_BUFFER_SIZE << 1];
        snd_una = snd_sqn = snd_nxt = snd_iss = rand();
        thread = std::thread(tcpSenderThread, std::ref(*this));
        rcv_buf_p = 0; 
        state = TCPState::CLOSED;
        printf("[Info] Init finished, snd_sqn = %d, snd_iss = %d\n", snd_sqn, snd_iss);
    }

    int sendPacket(const void *buf, int len, uint8_t flags = TCP_FLAG_ACK, bool imme = false) {
        std::lock_guard<std::mutex> g(mutex);
        if (!legalToSend()) {
            printf("[Err] Try to send packet in closed TCP state machine.\n"); 
            return -1;
        }
        __sendPacket(buf, len, flags, imme);
        return 0; 
    }
    /**
     * @brief Call Ether interface to send packet. (shouldn't have a lock)
     * @param buf Pure data
     * @param len 
     * @param flags 
     * @param imme Will the function call be blocked until the packet returns
     * @return whether this operation succeeded 
     */
    int __sendPacket(const void *buf, int len, uint8_t flags = TCP_FLAG_ACK, bool imme = false)
    {
        printf("[Info] Try to send.\n");
        printf("[Info] snd_sqn = %d, snd_iss = %d\n", snd_sqn, snd_iss);
        if (imme) {
            clearBufferedTCPPacket();
        }
        printf("[Info] clear buffered packet succeed.\n");
        if (snd_una - snd_iss > TCP_SEND_BUFFER_SIZE)
        {
            printf("[Info] send buffer shift.\n");
            memcpy(sendBuffer, sendBuffer + TCP_SEND_BUFFER_SIZE, TCP_SEND_BUFFER_SIZE);
            snd_iss += TCP_SEND_BUFFER_SIZE;
        }
        if (snd_sqn - snd_iss + len > TCP_SEND_BUFFER_SIZE * 2)
        {
            printf("[Err] TCP send buffer overflow\n");
            return -1;
        }
        if (len) {
            memcpy(sendBuffer + snd_sqn - snd_iss, buf, len);
        }
        snd_sqn += len != 0 ? len : 1;
        if (imme) {
            constructTCPPacket(buf, len, flags); 
        }
        return 0;
    }
    int constructTCPPacket(const void *buf, int len, uint8_t flags) {
        printf("[Info] construct packet.\n");
        char obuf[len + TCP_HEADER_LEN];
        tcp_header_t* header = (tcp_header_t*)obuf;
        header->srcPort = htons(socket.srcPort); 
        header->dstPort = htons(socket.dstPort);
        header->seq = htonl(snd_sqn);
        header->ack = htonl(ack); 
        header->offset = 5<<4;
        header->flags = flags;
        header->window = htons(snd_wnd);
        header->urgentP = 0;
        memcpy(obuf + TCP_HEADER_LEN, buf, len);
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
        printf("[Info] Before state = %s\n", to_string(state).c_str());
        tcp_header_t *hdr = (tcp_header_t *)((char*)buf+IP_HEADER_LEN);
        auto syn = [&]
        { return (HAS_FLAG(hdr->flags, TCP_FLAG_SYN)); };
        auto ack = [&]
        { return (HAS_FLAG(hdr->flags, TCP_FLAG_ACK)); };
        auto valid_ack = [&]
        { return ack() && hdr->ack == rcv_nxt; };
        auto fin = [&]
        { return (HAS_FLAG(hdr->flags, TCP_FLAG_FIN)); };
        switch (state)
        {
        case TCPState::CLOSED:
            break;
        case TCPState::CLOSE_WAIT:
            break;
        case TCPState::LISTEN:
            printf("[Info] %d,%d\n",syn(),valid_ack());
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
                rcv_nxt += len - TCP_HEADER_LEN;
                printf("[Info] Received packet of [%d,%d).\n", hdr->seq, hdr->seq + len - TCP_HEADER_LEN);
                pushReceiveBuffer((char*)buf + TCP_HEADER_LEN, len - TCP_HEADER_LEN);
            }
        }
        printf("[Info] Now state = %s\n", to_string(state).c_str());
    }
    int startConnection() {
        std::lock_guard<std::mutex> lock(mutex);
        if (state != TCPState::CLOSED) {
            printf("[Err] Try to start connection on not closed TCB.\n");
            return -1;
        }
        printf("[Info] Start connection snd_sqn = %d, snd_iss = %d\n", snd_sqn, snd_iss);
        auto t =  __sendPacket(nullptr, 0, TCP_FLAG_SYN, true);
        state = TCPState::SYN_SENT;
        return t;
    }
    int startListen() {
        std::lock_guard<std::mutex> lock(mutex);
        if (state != TCPState::CLOSED) {
            printf("[Err] Try to start listen on not closed TCB.\n");
            return -1;
        }
        printf("[Info] snd_sqn = %d, snd_iss = %d\n", snd_sqn, snd_iss);
        state = TCPState::LISTEN;
        return 0;
    }
    bool established(){ 
        std::lock_guard<std::mutex> lock(mutex);
        return state == TCPState::ESTAB; 
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



void freeConnectionBuffer(TCB &c)
{
    delete c.sendBuffer;
}

//TODO:needs mutex
std::map<socket_t, TCB> connections;

int TCPOnIPCallback(const void *buf, int len)
{
    if (len < IP_HEADER_LEN + TCP_HEADER_LEN)
    {
        printf("[Err] Invalid TCP header.");
        return -1;
    }
    ip_header_t *header_ip = (ip_header_t *)(buf);
    tcp_header_t *header_tcp = (tcp_header_t *)(((char *)buf) + IP_HEADER_LEN);
    if (header_ip->protocol != PROTO_TCP) {
        printf("[Info] Drop packet since it's not TCP\n");
    }
    auto key = socket_t(ntohs(header_tcp->srcPort), header_ip->src_addr, header_ip->dst_addr, ntohs(header_tcp->dstPort));
    std::swap(key.dstIP,key.srcIP);
    std::swap(key.dstPort,key.srcPort);
    printf("Q (%d,%d,%x,%x)\n",key.srcPort,key.dstPort,key.srcIP,key.dstIP);
    if (!connections.count(key))
    {
        printf("[Err] TCP connection does not exist\n");
        return -1;
    }
    debugTCPPacket((const char *)buf, len);
    connections[key].processTCPStateMachineOnReceive(buf, len);
    return 0;
}

vector<std::future<int>> initTcpService(int cnt)
{
    setIPPacketReceiveCallback(TCPOnIPCallback);
    return initRouteService(cnt);
}

//Just for debug.
void testTCPSendPacket(){
    socket_t socket;
    socket.dstIP = 0x0a640101;
    socket.srcIP = 0x23333332;
    socket.srcPort = 123;
    socket.dstPort = 456;
    TCB &c=connections[socket]; 
    c.socket=socket;
    auto r = initTcpService(100); 
    c.init();
    char buf[] = "Hello World!"; 
    for (int i = 0; i < 100;++i) {
        printf("[Info] Before send TCP Packet.\n");
        c.constructTCPPacket(buf, strlen(buf), TCP_FLAG_SYN);
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }
}

//Just for debug.
void testTCPEchoServer() {
    socket_t socket;
    socket.dstIP = 0x0a640102;
    socket.srcIP = 0x0a640101;
    socket.srcPort = 123;
    socket.dstPort = 456;
    TCB &c=connections[socket]; 
    auto &key=socket;
    printf("I (%hu,%hu,%x,%x)\n",key.srcPort,key.dstPort,key.srcIP,key.dstIP);
    c.socket=socket;
    c.init();
    printf("[Info] Server should be ns1.\n");
    auto r = initTcpService(100); 
    c.startListen();
    for (int i = 0;i < 10;++i) {
        char buf[10];
        c.readData(buf, 1); 
        printf("[Info] Server received [%c].\n", buf[0]); 
    }
    c.sendCloseSignal();
}

void testTCPEchoClient() {
    socket_t socket;
    socket.srcIP = 0x0a640102;
    socket.dstIP = 0x0a640101;
    socket.dstPort = 123;
    socket.srcPort = 456;
    TCB &c=connections[socket]; 
    auto &key=socket;
    printf("I (%hu,%hu,%x,%x)\n",key.srcPort,key.dstPort,key.srcIP,key.dstIP);
    c.socket=socket;
    c.init();
    auto r = initTcpService(100); 
    const char *buf = "0123456789";
    printf("[Info] trys to start tcp connection.\n");
    printf("[Info] Client should be ns2.\n");
    //TODO: This is ugly, (wait for dist vector)
    std::this_thread::sleep_for(std::chrono::seconds(2));
    c.startConnection();
    printf("[Info] trys to start tcp connection.\n");
    //TODO: This is ugly, (wait for handshake)
    std::this_thread::sleep_for(std::chrono::seconds(4));
    for (int i = 0;i < strlen(buf); ++i) {
        c.sendPacket(buf+i, 1);
    }
    c.sendCloseSignal();
}