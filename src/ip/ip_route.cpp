#include "ip_route.h"
#include "ip.h"
#include "src/link/link.h"
#include <netinet/ip.h>
#include <cstring> 
#include <string> 

using std::string; 


vector<RouteTableEntry> routeTable; 

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
    routeTable.push_back(e);
    return res;
}

int queryRouteTable(RouteTableEntry &res, uint32_t ip) {
    uint32_t resMask = 0; 
    for (auto x : routeTable) {
        printf("[Info] Route table entry (dest=%s,mask=%s)\n", ipv4_int_to_string(x.dest.s_addr, nullptr).c_str(),
            ipv4_int_to_string(x.mask.s_addr, nullptr).c_str());
        if (x.dest.s_addr == (ip&x.mask.s_addr) && x.mask.s_addr > resMask) {
            resMask = x.mask.s_addr; 
            res = x; 
        }
    }
    return resMask;
}



int routeIPPacket(const void *buf, int len) {
    RouteTableEntry e;  
    int res = queryRouteTable(e, ((ip_header_t*)buf)->dst_addr.s_addr);
    if (res == 0) {
        printf("[Info] Drop IP packet due to failed to find respective route table entry\n");
        return -1; 
    }
    sendFrame(buf, len, IPV4_ETHER_TYPE, e.nextHopMAC, e.deviceName);
    return 0;
}

int sendIPPacket(const struct in_addr src, const struct in_addr dest, 
    int proto, const void *data, int len) {
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
    printf("len + IP header len = %d\n", len + IP_HEADER_LEN);
    return routeIPPacket(buf, len + IP_HEADER_LEN);
}

void initLegalPort()
{
    auto r = getLegalPortName();
    for (auto x : r)
    {
        printf("[Info] Add device %s\n", x.c_str());
        addDevice(x);
    }
}
