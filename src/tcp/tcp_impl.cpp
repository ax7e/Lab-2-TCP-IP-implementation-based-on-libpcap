#include <set>
#include <future>
#include <map>
#include <mutex>
#include <deque>
#include <thread>
#include <vector>
#include <future>
#include <optional>
#include <cassert>
#include <cstring>
#include "tcp_impl.h"
#include "src/ip/ip.h"
#include "src/tcp/socket.h"

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

struct tcp_id_t {
    int srcPort;
    //In network form
    uint32_t srcIP;
    //In network form
    uint32_t dstIP;
    int dstPort;
    tcp_id_t() = default;
    tcp_id_t(int srcPort, uint32_t srcIP, uint32_t dstIP, int dstPort):
        srcPort(srcPort), srcIP(srcIP), dstIP(dstIP), dstPort(dstPort) {

        }
};

bool operator<(const tcp_id_t &lhs, const tcp_id_t &rhs) {
    int v[4];
    v[0] = lhs.srcPort - rhs.srcPort;
    v[1] = (int)(lhs.srcIP - rhs.srcIP);
    v[2] = lhs.dstPort - rhs.dstPort;
    v[3] = (int)(lhs.dstIP - rhs.dstIP);
    for (int i = 0;i < 4;++i) if (v[i] != 0) {
        if (v[i] < 0) return true; 
        else return false;
    }
    return false;
}
bool operator==(const tcp_id_t &l, const tcp_id_t &r) { return (!(l<r))&&(!(r<l)); }

//typedef int (*IPPacketReceiveCallback)(const void *buf, int len);
void debugTCPPacket(const void *buf, int len, bool hasIP = true) {
    tcp_header_t *header = (tcp_header_t *)(((char*)buf) + (hasIP ? IP_HEADER_LEN : 0));
    ip_header_t *hdr_ip = (ip_header_t *)(buf);
    if (hasIP) {
        V1 printf("[\e[32mInfo\e[0m] (%x:%d<->%x:%d),", hdr_ip->src_addr, ntohs(header->srcPort), (hdr_ip->dst_addr), ntohs(header->dstPort)); 
    } else {
        V1 printf("[\e[32mInfo\e[0m] (%d<->%d),", ntohs(header->srcPort), ntohs(header->dstPort)); 
    }
    printf("(len:%d,ack:%d,seq:%d,window:%d,checksum:%x), ",len- TCP_HEADER_LEN-(hasIP?IP_HEADER_LEN:0), 
        ntohl(header->ack),ntohl(header->seq),header->window,header->checksum);
    V1 printf("Flags:");
#define CHECK_FLAG(x) if (header->flags&TCP_FLAG_##x){printf(#x);putchar(' ');}
    CHECK_FLAG(URG)
    CHECK_FLAG(ACK)
    CHECK_FLAG(PSH)
    CHECK_FLAG(RST)
    CHECK_FLAG(SYN)
    CHECK_FLAG(FIN)
    V1 puts("");
}

struct TCB {
    std::thread thread;
    TCPState state;
    tcp_id_t socket;
    uint8_t *sendBuffer;
    // [0, snd_una)-[snd_una, snd_nxt)-[snd_nxt, snd_sqn) 
    int snd_una;
    //TODO : NOT IMPLEMENTED
    int snd_nxt;
    //TODO : snd_NOT IMPLEMENTED
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
        V2 printf("[\e[32mInfo\e[0m] Lock!.\n");
        std::promise<int> pro;
        auto f = pro.get_future();
        if (ill.count(state)) {
            pro.set_value(-1); 
            return f;
        }
        rcv_requests.push_back(std::make_tuple(buf, len, std::move(pro)));
        clrRcvBuf(); 
        V2 printf("[\e[32mInfo\e[0m] Unlock!.\n");
        return f;
    }
    void clrRcvBuf() {
        V2 printf("[\e[32mInfo\e[0m] clrRcvBuf.\n"); 
        static const std::set<TCPState> ill = { TCPState::CLOSEING, TCPState::LAST_ACK, TCPState::TIMEWAIT, TCPState::CLOSED,
            TCPState::CLOSE_WAIT};
        int s = rcv_buf.size(); 
        while (!rcv_requests.empty() && s - rcv_buf_p >= std::get<1>(rcv_requests.front())) {
            V2 printf("[\e[32mInfo\e[0m] \e[33m putvalue \e[0m %c\n", rcv_buf[rcv_buf_p]);
            memcpy(std::get<0>(rcv_requests.front()),
                   &rcv_buf[rcv_buf_p], std::get<1>(rcv_requests.front()));
            std::get<2>(rcv_requests.front()).set_value(0);
            rcv_buf_p += std::get<1>(rcv_requests.front()); 
            rcv_requests.pop_front();
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
        V2 printf("[\e[32mInfo\e[0m] clrRcvBuf ends.\n"); 
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
            constructTCPPacket(sendBuffer + snd_nxt - snd_iss, len, TCP_FLAG_ACK);
            snd_nxt += len;
        }
    }
    void checkShrink(){
        int s = rcv_buf.size() - rcv_buf_p;
        if (rcv_buf.size() > 100 && s < rcv_buf.size() / 2) {
            V2 printf("[\e[32mInfo\e[0m] Shrink send buffer.\n");
            for (int i = 0;i < rcv_buf.size() - rcv_buf_p;i++) {
                rcv_buf[i] = rcv_buf[i+rcv_buf_p];
            }
            rcv_buf_p = 0; 
        }
    }
    void pushReceiveBuffer(char *buf, int len) {
        checkShrink(); 
        for (int i = 0;i < len;++i) rcv_buf.push_back(buf[i]); 
        clrRcvBuf(); 
    }
    
    int sendPacket(const void *buf, int len, uint8_t flags = TCP_FLAG_ACK, bool imme = false) {
        std::lock_guard<std::mutex> g(mutex);
        V2 printf("[\e[32mInfo\e[0m] lock!.\n");
        if (!legalToSend()) {
            printf("[Err] Try to send packet in closed TCP state machine.\n"); 
            return -1;
        }
        __sendPacket(buf, len, flags, imme);
        V2 printf("[\e[32mInfo\e[0m] unlock!.\n");
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
        V2 printf("[\e[32mInfo\e[0m] Try to send packet, flag = %d\n", flags);
        if (imme) {
            clearBufferedTCPPacket();
        }
        V2 printf("[\e[32mInfo\e[0m] clear buffered packet succeed.\n");
        if (snd_una - snd_iss > TCP_SEND_BUFFER_SIZE)
        {
            V2 printf("[\e[32mInfo\e[0m] send buffer shift.\n");
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
        snd_sqn += len != 0 ? len : (bool)((flags & TCP_FLAG_SYN) || (flags & TCP_FLAG_FIN));
        if (imme) {
            constructTCPPacket(buf, len, flags);
            snd_nxt += len;
        }
        return 0;
    }
    int constructTCPPacket(const void *buf, int len, uint8_t flags) {
        V2 printf("[\e[32mInfo\e[0m] construct packet, len = %d", len);
        if (buf == nullptr) V2 printf("(empty)");
        V2 puts("");
        char obuf[len + TCP_HEADER_LEN];
        tcp_header_t* header = (tcp_header_t*)obuf;
        header->srcPort = htons(socket.srcPort); 
        header->dstPort = htons(socket.dstPort);
        header->seq = htonl(snd_sqn);
        header->ack = htonl(rcv_nxt); 
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
        V1 printf("[\e[32mInfo\e[0m] Send packet content:\n");
        debugTCPPacket(obuf, len + TCP_HEADER_LEN, false); 
        if (sendIPPacket(socket.srcIP, socket.dstIP, PROTO_TCP, obuf, len + TCP_HEADER_LEN)) {
            printf("[Err] sendPacket failed at sendIPPacket.\n");
            return -1; 
        }
        return 0; 
    }
    //TODO: Maybe it's wrong
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
    int sendFlag(uint8_t flag) {
        return __sendPacket(nullptr, 0, flag, true);
    }
    void sendCloseSignal() {
        std::lock_guard<std::mutex> lock(mutex);
        V2 printf("[\e[32mInfo\e[0m] lock!.\n");
        V2 printf("[\e[32mInfo\e[0m] CLOSE \e[31mstate\e[0m = %s\n", to_string(state).c_str());
        switch (state)
        {
        case TCPState::CLOSED: 
            break;
        case TCPState::CLOSE_WAIT:
            sendFlag(TCP_FLAG_FIN);
            state = TCPState::LAST_ACK;
            break;
        case TCPState::LISTEN:
            --socketCount;
            state = TCPState::CLOSED;
            break;
        case TCPState::SYN_RCVD:
            sendFlag(TCP_FLAG_FIN); 
            state = TCPState::FINWAIT_1;
            break;
        case TCPState::SYN_SENT:
            --socketCount;
            state = TCPState::CLOSED;
            break;
        case TCPState::ESTAB:
            sendFlag(TCP_FLAG_FIN);
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
        V2 printf("[\e[32mInfo\e[0m] Now \e[31mstate\e[0m = %s\n", to_string(state).c_str());
        V2 printf("[\e[32mInfo\e[0m] unlock!.\n");
    }
    void processTCPStateMachineOnReceive(const void *buf, int len)
    {
        std::lock_guard<std::mutex> lock(mutex);
        V2 printf("[\e[32mInfo\e[0m] lock!.\n");
        V1 printf("[\e[32mInfo\e[0m] Before \e[31m state \e[0m = %s, len = %d\n", to_string(state).c_str(), len);
        tcp_header_t *hdr = (tcp_header_t *)((char*)buf+IP_HEADER_LEN);
        auto syn = [&]
        { return (HAS_FLAG(hdr->flags, TCP_FLAG_SYN)); };
        auto ack = [&]
        { return (HAS_FLAG(hdr->flags, TCP_FLAG_ACK)); };
        auto valid_ack = [&]
        { 
            return ack() && ntohl(hdr->ack) == snd_sqn + 1; 
        };
        auto fin = [&]
        { return (HAS_FLAG(hdr->flags, TCP_FLAG_FIN)); };
        switch (state)
        {
        case TCPState::CLOSED:
            break;
        case TCPState::CLOSE_WAIT:
            break;
        case TCPState::LISTEN:
            if (syn() && !ack())
            {
                rcv_nxt = ntohl(hdr->seq) + 1;
                state = TCPState::SYN_RCVD;
                sendFlag(TCP_FLAG_ACK | TCP_FLAG_SYN);
            }
            break;
        case TCPState::SYN_RCVD:
            if (valid_ack() && !syn()) {
                state = TCPState::ESTAB;
            }
            break;
        case TCPState::SYN_SENT:
            if (!ack() && syn()) {
                rcv_nxt = ntohl(hdr->seq)+1;
                sendFlag(TCP_FLAG_ACK);
                state = TCPState::SYN_RCVD;
            } else if (ack() && syn()) {
                rcv_nxt = ntohl(hdr->seq)+1;
                sendFlag(TCP_FLAG_ACK);
                state = TCPState::ESTAB;
            }
            break;
        case TCPState::ESTAB:
            if (fin())
            {
                sendFlag(TCP_FLAG_ACK);
                rcv_nxt++;
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
                rcv_nxt++;
                state = TCPState::CLOSEING;
                sendFlag(TCP_FLAG_ACK);
            }
            goto receivePacket;
            break;
        case TCPState::FINWAIT_2:
            if (fin()) {
                rcv_nxt++;
                sendFlag(TCP_FLAG_ACK);
                state = TCPState::TIMEWAIT;
            }
            goto receivePacket;
            break;
        case TCPState::LAST_ACK:
            if (valid_ack()) {
                --socketCount;
                state = TCPState::CLOSED;
            }
            break;
        case TCPState::TIMEWAIT:
            break;
        case TCPState::CLOSEING:
            if (valid_ack()) {
                state = TCPState::TIMEWAIT;
                std::thread t([](TCB& t){
                    std::this_thread::sleep_for(std::chrono::seconds(TCP_MSL)); 
                    {
                        std::lock_guard<std::mutex> lock(t.mutex);
                        --socketCount;
                        t.state = TCPState::CLOSED;
                    }
                    printf("socketCount = %d\n", socketCount.load());
                    printf("[\e[32mInfo\e[0m] Connection closed.\n");
                }, std::ref(*this));
                t.detach();
            }
        receivePacket:
            if (htonl(hdr->seq) == rcv_nxt) {
                rcv_nxt += len - TCP_HEADER_LEN - IP_HEADER_LEN;
                V2 printf("[\e[32mInfo\e[0m] Received packet of {len=%d}[%d,%d).\n",
                       len - TCP_HEADER_LEN - IP_HEADER_LEN,
                       htonl(hdr->seq), htonl(hdr->seq) + len - TCP_HEADER_LEN - IP_HEADER_LEN);
                pushReceiveBuffer((char *)buf + TCP_HEADER_LEN + IP_HEADER_LEN, len - TCP_HEADER_LEN - IP_HEADER_LEN);
                if (htonl(hdr->ack) > snd_una) {
                    snd_una = htonl(hdr->ack);
                }
            }
        }
        V1 printf("[\e[32mInfo\e[0m] Now \e[31m state \e[0m = %s\n", to_string(state).c_str());
        V2 printf("[\e[32mInfo\e[0m] unlock!.\n");
    }
    int startConnection() {
        std::lock_guard<std::mutex> lock(mutex);
        V2 printf("[\e[32mInfo\e[0m] lock!.\n");
        if (state != TCPState::CLOSED) {
            printf("[Err] Try to start connection on not closed TCB.\n");
            return -1;
        }
        V2 printf("[\e[32mInfo\e[0m] Start connection snd_sqn = %d, snd_iss = %d.\n", snd_sqn, snd_iss);
        auto t = sendFlag(TCP_FLAG_SYN);
        snd_nxt += 1;
        printf("%d,%d\n", snd_sqn, snd_nxt);
        fflush(stdout);
        state = TCPState::SYN_SENT;
        V2 printf("[\e[32mInfo\e[0m] lock!.\n");
        return t;
    }
    
    int startListen()
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (state != TCPState::CLOSED) {
            printf("[Err] Try to start listen on not closed TCB.\n");
            return -1;
        }
        V2 printf("[\e[32mInfo\e[0m] snd_sqn = %d, snd_iss = %d\n", snd_sqn, snd_iss);
        state = TCPState::LISTEN;
        return 0;
    }
    bool established(){ 
        std::lock_guard<std::mutex> lock(mutex);
        return state == TCPState::ESTAB; 
    }
    void init();
};
void tcpSenderThread(TCB &c)
{
    while (true)
    {
        {
            std::lock_guard<std::mutex> lock(c.mutex);
            c.clearBufferedTCPPacket();
            if (c.state == TCPState::CLOSED) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void TCB::init()
{
    sendBuffer = new uint8_t[TCP_SEND_BUFFER_SIZE << 1];
    snd_una = snd_sqn = snd_nxt = snd_iss = rand();
    thread = std::thread(tcpSenderThread, std::ref(*this));
    rcv_buf_p = 0;
    state = TCPState::CLOSED;
    snd_wnd = TCP_SEND_BUFFER_SIZE * 2;
    V2 printf("[\e[32mInfo\e[0m] Init finished, snd_sqn = %d, snd_iss = %d\n", snd_sqn, snd_iss);
}

void freeConnectionBuffer(TCB &c)
{
    delete c.sendBuffer;
}

//TODO:needs mutex
std::map<uint16_t, vector<std::shared_ptr<TCB>>> connections;

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
        V2 printf("[\e[32mInfo\e[0m] Drop packet since it's not TCP\n");
    }
    auto key = tcp_id_t(ntohs(header_tcp->srcPort), header_ip->src_addr, header_ip->dst_addr, ntohs(header_tcp->dstPort));
    std::swap(key.dstIP,key.srcIP);
    std::swap(key.dstPort,key.srcPort);
    V2 printf("[\e[32mInfo\e[0m] Q (%d,%d,%x,%x)\n",key.srcPort,key.dstPort,key.srcIP,key.dstIP);
    if (!connections.count(key.srcPort))
    {
        printf("[Err] TCP connection does not exist\n");
        return -1;
    } 
    std::shared_ptr<TCB> p;
    for (auto x:connections[key.srcPort]) {
       if (x->socket == key) {
           p = x;
       } 
    }
    if (!p) {
        for (auto t:connections[key.srcPort]) {
            auto &x=*t;
            if (x.socket.dstIP == 0) {
                x.socket.dstIP = key.dstIP;
                x.socket.dstPort = key.dstPort;
                V1 printf("[\e[32mInfo\e[0m] Connection setup!\n");
                p=t;
            }
        }
    }
    if (!p) {
        printf("[Err] TCP connection does not exist\n");
        return -1;
    }
    V1 printf("[\e[32mInfo\e[0m] Received TCP:\n");
    debugTCPPacket((const char *)buf, len);
    p->processTCPStateMachineOnReceive(buf, len);
    return 0;
}

vector<std::future<int>> initTcpService(int cnt)
{
    static bool init = false;
    if (!init) {
        init = true;
        srand(time(0));
        setIPPacketReceiveCallback(TCPOnIPCallback);
        return initRouteService(cnt);
    }
    return {}; 
}

//Just for debug.
void testTCPSendPacket(){
    tcp_id_t socket;
    socket.dstIP = 0x0a640101;
    socket.srcIP = 0x23333332;
    socket.srcPort = 123;
    socket.dstPort = 456;
    connections[socket.srcPort].push_back(std::make_shared<TCB>()); 
    TCB &c=*connections[socket.srcPort][0]; 
    c.socket=socket;
    auto r = initTcpService(100); 
    c.init();
    char buf[] = "Hello World!"; 
    for (int i = 0; i < 100;++i) {
        V2 printf("[\e[32mInfo\e[0m] Before send TCP Packet.\n");
        c.constructTCPPacket(buf, strlen(buf), TCP_FLAG_SYN);
        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    }
}

//Just for debug.
void testTCPEchoServer() {
    socketCount = 1;
    tcp_id_t socket;
    socket.dstIP = 0;
    socket.srcIP = 0x0a640101;
    socket.srcPort = 123;
    socket.dstPort = 0;
    connections[socket.srcPort].push_back(std::make_shared<TCB>()); 
    TCB &c=*connections[socket.srcPort][0]; 
    c.socket=socket;
    V1 printf("[\e[32mInfo\e[0m] Server should be ns1.\n");
    auto r = initTcpService(100); 
    c.init();
    c.startListen();
    char *buf = new char[11]; buf[10] = 0;
    for (int i = 0;i < 10;++i) {
        V2 printf("[\e[32mInfo\e[0m] request at %d.\n", i); 
        auto f = c.readData(buf + i, 1); 
        V2 printf("[\e[32mInfo\e[0m] Before get.\n"); 
        if (f.get() != 0) {
            printf("[Message] Failed on get.\n");
        } else {
            printf("[Message] Server received [%c].\n", buf[i]);
        }
    }
    delete buf;
    c.sendCloseSignal();
}

void testTCPEchoClient() {
    socketCount = 1;
    auto r = initTcpService(100); 
    tcp_id_t socket;
    socket.srcIP = 0x0a640102;
    socket.dstIP = 0x0a640101;
    socket.dstPort = 123;
    socket.srcPort = 456;
    connections[socket.srcPort].push_back(std::make_shared<TCB>()); 
    TCB &c=*connections[socket.srcPort][0]; 
    c.socket=socket;
    c.init();
    const char *buf = "0123456789";
    V2 printf("[\e[32mInfo\e[0m] trys to start tcp connection.\n");
    V2 printf("[\e[32mInfo\e[0m] Client should be ns2.\n");
    std::this_thread::sleep_for(std::chrono::seconds(2));
    c.startConnection();
    do {
        std::this_thread::sleep_for(std::chrono::seconds(4));
    } while (c.state != TCPState::ESTAB);
    for (int i = 0;i < strlen(buf); ++i) {
        c.sendPacket(buf+i, 1, TCP_FLAG_ACK, true);
    }
    c.sendCloseSignal();
}

/*
enum struct SocketState {
    IDLE, BIND, CONNECTED 
};
struct socket_t {
    uint32_t ip;   
    uint16_t port; 
};
//socket control block
struct scb {
    SocketState state; 
    socket_t src, dst; 
    std::shared_ptr<TCB> c;
};

std::mutex mapSocketMutex; 
std::map<int, scb> map; 

int getNewUserSocket() {
    return rand();
}
int __wrap_socket(int domain, int type, int protocol) {
    if (socketCount.fetch_add(1) == 0) {
        initTcpService(TEST_MST_CNT);
    }
    bool support = (domain == AF_INET) && ((type & SOCK_STREAM) == SOCK_STREAM) && 
        (!protocol || protocol == IPPROTO_TCP);
    if (!support) {
        return __real_socket(domain, type, protocol);
    }
    int t = getNewUserSocket(); 
    map[t] = scb(); 
    return t; 
}

std::optional<scb*> getSocket(int x) {
    std::lock_guard<std::mutex> lock(mapSocketMutex);
    return map.count(x) ? std::optional<scb*>(&map[x]) : std::nullopt;
}

int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len) {
    auto s = getSocket(socket); 
    if (s) {
        if (((sockaddr_in*)address)->sin_family != AF_INET) {
            printf("[Err] bind to a non IPV4 addr.\n");
            return -1;
        }
        auto *p = (sockaddr_in*)address;
        s.value()->src.ip = p->sin_addr.s_addr; 
        s.value()->src.port = ntohs(p->sin_port);
        return 0;
    } else {
        return __real_bind(socket, address, address_len);
    }
}

int __wrap_listen(int socket, int backlog) {
    auto s = getSocket(socket);
    if (!socket) {
        return __real_listen(socket, backlog);
    }
    s.value()->state = SocketState::BIND;
    return 0; 
}
int __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len) {
    auto s = getSocket(socket); 
    if (!socket) return __real_connect(socket, address, address_len);
    s.value()->c = std::make_shared<TCB>(); 
    auto &c = s.value()->c;
}

int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len) {

}

ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte) {

}

ssize_t __wrap_read(int fildes, void *buf, size_t nbyte) {

}

int __wrap_close(int fildes) {
    auto s = getSocket(fildes); 
    s.value()->c->sendCloseSignal();
}
*/