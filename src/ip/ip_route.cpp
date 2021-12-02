#include "ip_route.h"
#include <cassert>
#include <iostream>
#include "ip.h"
#include "src/link/link.h"
#include <netinet/ip.h>
#include <future>
#include <cstring> 
#include <string> 
#include <mutex>
#include <chrono>
#include <map>
#include <optional>
#include <set>
#define BROADCAST_IP  0xFFFFFFFF

using std::string; 
using std::mutex;
using std::map; 
using std::set;


set<RouteTableEntry> routeTable; 
mutex routeTableMutex;
map<uint32_t, DistVectorEntry> distVector; 
mutex distVectorMutex;

typedef int (*IPPacketReceiveCallback)(const void *buf, int len);
IPPacketReceiveCallback ipReceiveCallback = nullptr;

int verbose=1; 

bool operator<(const RouteTableEntry &lhs, const RouteTableEntry &rhs) {
    return lhs.dest.s_addr == rhs.dest.s_addr ? lhs.mask.s_addr < rhs.mask.s_addr : lhs.dest.s_addr < rhs.dest.s_addr;
}
bool operator==(const RouteTableEntry &lhs, const RouteTableEntry &rhs) {
    return lhs<rhs && rhs<lhs;
}

uint16_t calcChecksum(const void *header) {
    uint32_t sum = 0; 
    for (auto i = (uint16_t*)header; i < (uint16_t*)header + IP_HEADER_LEN/2; ++i) {
        sum += ntohs(*i);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return htons((~sum)&0xFFFF);
}

int setRoutingTable(const in_addr dest, const in_addr mask,
                    const void * nextHopMAC, const string &device) {
    RouteTableEntry e; 
    e.dest = dest;
    e.mask = mask; 
    memcpy(e.nextHopMAC, nextHopMAC, 6); 
    int res = getMACAddress(device.c_str(), e.deviceMac); 
    e.deviceName = string(device); 
    std::lock_guard<std::mutex> lock(routeTableMutex); 
    if (routeTable.count(e)) {
        routeTable.erase(e); 
        routeTable.insert(e);
    } else {
        routeTable.insert(e);
    }
    return res;
}

int queryRouteTable(RouteTableEntry &res, uint32_t ip) {
    std::lock_guard<std::mutex> guard(routeTableMutex);
    uint32_t resMask = 0; 
    for (auto x : routeTable) {
        V2 printf("[\e[32mInfo\e[0m] Route table entry (dest=%s,mask=%s)\n", ipv4_int_to_string(x.dest.s_addr, nullptr).c_str(),
            ipv4_int_to_string(x.mask.s_addr, nullptr).c_str());
        uint32_t eIp = ip, eDst = ntohl(x.dest.s_addr), eMask = x.mask.s_addr;
        V2 printf("[\e[32mInfo\e[0m] ip=%x,dst=%x,mask=%x\n", eIp, eDst, eMask);
        if (eIp == (eDst&eMask) && eMask > resMask) {
            resMask = eMask;
            res = x; 
        }
    }
    return resMask;
}

int routeIPPacket(const void *buf, int len, std::optional<string> portName = std::nullopt) {
    if (!portName) {
        RouteTableEntry e;
        auto hdr = (ip_header_t*)(buf);
        if (--hdr->ttl == 0) {
            V1 printf("[\e[32mInfo\e[0m] Packet dropped due to 0 ttl.\n");
            return 0;
        }
        int res = queryRouteTable(e, hdr->dst_addr);
        V2 printf("[\e[32mInfo\e[0m] Packet dst addr = %x\n", ((ip_header_t *)buf)->dst_addr);
        if (res == 0)
        {
            auto ip = ((ip_header_t *)buf)->dst_addr;
            V2 printf("[\e[32mInfo\e[0m] count = %lu\n", distVector.count(ip));
            if (distVector.count(ip) && distVector[ip].distance == 0) {
                V2 printf("[\e[32mInfo\e[0m] Packet is for me, call ip call back.\n");
                ipReceiveCallback(buf, len);
                return 0;
            }
            else
            {
                V1 printf("[\e[32mInfo\e[0m] Drop IP packet due to failed to find respective route table entry\n");
                return -1;
            }
        }
        sendFrame(buf, len, IPV4_ETHER_TYPE, e.nextHopMAC, e.deviceName);
        V2 printf("[\e[32mInfo\e[0m] frame sent.\n");
    } else {
        mac_t mac = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; 
        sendFrame(buf, len, IPV4_ETHER_TYPE, mac, portName.value());
        return 0; 
    }
    return 0;
}

int sendIPPacket(const uint32_t src, const uint32_t dest, 
    int proto, const void *data, int len, std::optional<string> portName) {
    unsigned char buf[len + IP_HEADER_LEN];
    ip_header_t *header = (ip_header_t*)buf; 
    header->ver_ihl = 0x45;
    header->tos = 0;
    header->total_length = htons(IP_HEADER_LEN + len);
    header->id = 0;
    header->flags_fo = 1<<6;
    header->ttl = 128; 
    header->protocol = proto; 
    header->src_addr = src; 
    header->dst_addr = dest;  
    header->checksum = 0; 
    header->checksum = calcChecksum(buf); 
    memcpy(buf+IP_HEADER_LEN, data, len);
    V2 printf("[\e[32mInfo\e[0m] IP packet, len + IP header len = %d\n", len + IP_HEADER_LEN);
    return routeIPPacket(buf, len + IP_HEADER_LEN, portName);
}

//TODO:Implement IP call back logic on ether level.

void* writeDistVec(int &bufLen, string id) {
    const char *premble = "DistVector";
    auto vecLen = distVector.size();
    //['DistVector'][distVectorLen]{distVectorLen*[dstIP|nextHopMAC|dstHop]}
    bufLen = strlen(premble) + sizeof(int) + (sizeof(int) + 6 + 4) * vecLen;
    char *buf = (char*)malloc(bufLen);
    char *p=buf;
    //Premble
    memcpy(buf, premble, strlen(premble)); 
    p += strlen(premble);
    *((unsigned int *)p) = htonl(distVector.size());
    p+=4;
    for (auto x : distVector) {
        *((unsigned int *)p) = htonl(x.first);
        p+=4;
        getMACAddress(id.c_str(), (u_char*)p);
        p+=6;
        *((unsigned int *)p) = htonl(x.second.distance);
        p+=4;
    }
    return buf;
}

bool debugUpdateHappend; 
void updateDistVecEntry(const uint32_t ip, DistVectorEntry e, string device)
{
    e.distance += 1;
    if (distVector.count(ip))
    {
        uint64_t old_mac; memcpy(&old_mac, distVector[ip].nextHopMAC, 6);
        uint64_t mac; memcpy(&mac, e.nextHopMAC, 6);
        auto &e0 = distVector[ip];
        if (old_mac == mac || e.distance < e0.distance)
        {
            debugUpdateHappend |= e.distance != e0.distance; 
            e0 = e;
            setRoutingTable((in_addr){htonl(ip)}, (in_addr){htonl(0xFFFFFFFF)},e.nextHopMAC,device);
            V2 printf("[\e[32mInfo\e[0m] Set type 1.\n");
        } 
    }
    else
    {
        distVector[ip] = e;
        setRoutingTable((in_addr){htonl(ip)}, (in_addr){htonl(0xFFFFFFFF)},e.nextHopMAC,device);
        V2 printf("[\e[32mInfo\e[0m] Set type 2.\n");
        debugUpdateHappend = 1;
    }
}

bool containsDistVec(const void *packet, int len) {
    ip_header_t *header_ip = (ip_header_t*)((char*)packet + ETH_HLEN); 
    char *data_ip = (char*)packet + ETH_HLEN + IP_HEADER_LEN; 
    return len >= IP_HEADER_LEN + PREMBLE_LEN + ETH_HLEN &&
        string(data_ip, data_ip+PREMBLE_LEN) == "DistVector" &&
        header_ip->protocol == 253; 
}

void debugDistVector(const map<uint32_t, DistVectorEntry> &v)
{
    V2 printf("[\e[32mInfo\e[0m] Dist Vector:\n");
    for (auto e : v) 
    {
        uint32_t ip = e.first;
        V2 printf("[\e[32mInfo\e[0m] Vector Entry (%x)%d.%d.%d.%d, ", ip, (ip>>24)&0xFF,(ip>>16)&0xFF,(ip>>8)&0xFF,(ip>>0)&0xFF); 
        for (int j = 0;j < 6; ++j) V2 printf("%02x%c", e.second.nextHopMAC[j], ":,"[j==5]); 
        V2 printf("%d\n", e.second.distance);
    }
}

map<uint32_t, DistVectorEntry> parseDistVec(char *packet, int len) {
    V2 printf("[\e[32mInfo\e[0m] parseDistVec.\n");
    char *p = packet + ETH_HLEN + IP_HEADER_LEN + PREMBLE_LEN; 
    assert(len >= ETH_HLEN + IP_HEADER_LEN + PREMBLE_LEN);
    map<uint32_t, DistVectorEntry> v; 
    auto readUInt = [&]() { 
        auto r = ntohl(*((uint32_t*)p));
        p += 4; 
        return r;
    };
    auto readChar = [&]() { return *p++; };
    uint32_t tlen = readUInt(); 
    assert(len >= ETH_HLEN + IP_HEADER_LEN + PREMBLE_LEN + 4 + tlen * (4+6+4));
    for (int i = 0; i < tlen;++i) {
        uint32_t ip = readUInt(); 
        auto &e = (v[ip] = DistVectorEntry()); 
        for (int j = 0;j < 6; ++j) e.nextHopMAC[j] = readChar();
        e.distance = readUInt(); 
    }
    //debugDistVector(v); 
    return v;
}

#define TIMEOUT (5 * 1000)
typedef std::chrono::high_resolution_clock clk;
using namespace std::chrono;
map<uint64_t, decltype(clk::now())> timeOutTable; 

int updateDistVecTable(const map<uint32_t, DistVectorEntry> &m, string device) {
    std::lock_guard<std::mutex> lock(distVectorMutex);
    debugUpdateHappend = false;
    for (auto e : m) {
        updateDistVecEntry(e.first, e.second, device);
    }
    uint64_t mac = 0; 
    memcpy(&mac, m.begin()->second.nextHopMAC, 6); 
    timeOutTable[mac] = clk::now(); 
    V2 printf("[\e[32mInfo\e[0m] Set %lx\n", mac); 
    V2 printf("[\e[32mInfo\e[0m] Updated dist vector.\n");
    if (debugUpdateHappend) debugDistVector(distVector);
    return 0;
}


int setIPPacketReceiveCallback(IPPacketReceiveCallback callback)
{
    ipReceiveCallback = callback;
    return 0;
}

int receiveIPPacketEtherWrapper(const void * packet, int len, string from) {
    V2 printf("[\e[32mInfo\e[0m] received ether packet called at port %s.\n", from.c_str());
    if (containsDistVec(packet, len)){
        V2 printf("[\e[32mInfo\e[0m] Detected DV broadcast at port %s\n", from.c_str()); 
        auto r = parseDistVec((char*)packet, len); 
        updateDistVecTable(r, from); 
        return 0;
    } else {
        return routeIPPacket((void*)((char*)packet + ETH_HLEN), len - ETH_HLEN); 
    }
}
vector<std::future<int>> initLegalPort(int cnt) {
    vector<std::future<int>> res;
    auto r = getLegalPortName();
    for (auto x : r)
    {
        addDevice(x);
        setFrameReceiveCallback(x, receiveIPPacketEtherWrapper);
        V2 printf("[\e[32mInfo\e[0m] Before actiave listen on %s\n", x.c_str()); 
        res.push_back(activateListen(x, cnt));
        V2 printf("[\e[32mInfo\e[0m] End actiave listen on %s\n", x.c_str()); 
    }
    return res;
}

void checkDVTimeOut() {
    std::lock_guard<std::mutex> lock(distVectorMutex);
    set<uint64_t> toDel;
    for (auto &e : distVector) if (e.second.distance != 0) {
        uint64_t mac = 0;
        memcpy(&mac, e.second.nextHopMAC, 6);
        auto t = duration_cast<std::chrono::milliseconds>(clk::now()-timeOutTable[mac]).count();
        V2 printf("Timeout for %lx=%ld\n", mac, t);  
        if (t > TIMEOUT)
        {
            toDel.insert(mac); 
        }
    }
    if (toDel.size()) {
        printf("[\e[32mInfo\e[0m] Timeout happened and deleted.\n");
        decltype(distVector) n;
        for (auto e:distVector) {
            uint64_t mac;
            memcpy(&mac, e.second.nextHopMAC, 6);
            if (toDel.count(mac)) e.second.distance = e.second.infinityDist;
            n.insert(e);
        }
        distVector = n;
        debugDistVector(distVector); 
    }
}

vector<std::future<int>> initRouteService(int cnt) {
    auto f_r = initLegalPort(cnt); 
    V2 printf("[\e[32mInfo\e[0m] Init legal port finished!\n"); 
    auto r = getLegalPortName(); 
    std::lock_guard<std::mutex> guard(distVectorMutex); 
    for (auto local_host : r) {
        DistVectorEntry e; 
        e.distance = 0;
        getMACAddress(local_host.c_str(), e.nextHopMAC); 
        in_addr ip; 
        getIPAddress(local_host.c_str(), &ip); 
        distVector[ntohl(ip.s_addr)] = e; 
    }
    debugDistVector(distVector); 
    //Thread responsible for broadcast of the distance vector.
    f_r.push_back(std::async([=](int cnt){
        V1 printf("[\e[32mInfo\e[0m] DV thread "); 
        V1 std::cout << std::this_thread::get_id() << std::endl; 
        while (cnt -- && socketCount != 0) {
            V2 printf("[\e[32mInfo\e[0m] Cnt = %d now.\n", cnt);
            V2 debugDistVector(distVector); 
            for (auto local_host : r) {
                V2 printf("[\e[32mInfo\e[0m] send dist packet to port %s\n", local_host.c_str());
                std::lock_guard<std::mutex> guard(distVectorMutex);
                //src,dst,proto,data,len
                in_addr src, dst;
                dst.s_addr = BROADCAST_IP;
                getIPAddress(local_host.c_str(), &src);
                int proto = 253;
                int bufLen;
                void *buf = writeDistVec(bufLen, local_host);
                sendIPPacket(src.s_addr, dst.s_addr, proto, buf, bufLen, local_host);
                free(buf);
            }
            checkDVTimeOut(); 
            if (cnt % 10 == 9) V1 debugDistVector(distVector) ;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        V1 printf("[\e[32mInfo\e[0m] Ends DV thread "); 
        V1 std::cout << std::this_thread::get_id() << std::endl; 
        return 0; 
    }, cnt));
    return f_r; 
}
