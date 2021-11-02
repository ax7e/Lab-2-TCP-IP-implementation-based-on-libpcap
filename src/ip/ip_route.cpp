#include "ip_route.h"
#include "ip.h"
#include "src/link/link.h"
#include <netinet/ip.h>
#include <cstring> 
#include <string> 

using std::string; 


vector<RouteTableEntry> routeTable; 

uint16_t calcChecksum(const void *header) {
    uint32_t sum; 
    for (auto i = (uint16_t*)header; i < (uint16_t*)header + IP_HEADER_LEN/2; ++i) {
        sum += *i;
        sum = (sum&0xFFFF)+(sum>>16);
    }
    return ~sum;
}

int setRoutingTable(const in_addr dest, const in_addr mask,
                    const void * nextHopMAC, const string &device) {
    RouteTableEntry e; 
    e.dest = dest;
    e.mask = mask; 
    memcpy(e.nextHopMAC, nextHopMAC, 6); 
    int res = getMACAddress(device.c_str(), e.deviceMac); 
    e.deviceName = string(device); 
    return res;
}

int queryRouteTable(RouteTableEntry &res, uint32_t ip) {
    uint32_t resMask = 0; 
    for (auto x : routeTable) {
        if (x.dest.s_addr == (ip&x.mask.s_addr) && x.dest.s_addr > resMask) {
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
    sendFrame(buf, len, DEFALUT_ETH_TYPE, e.nextHopMAC, e.deviceName);
    return 0;
}

int sendIPPacket(const struct in_addr src, const struct in_addr dest, 
    int proto, const void *data, int len) {
    unsigned char buf[len + IP_HEADER_LEN];
    ip_header_t *header = (ip_header_t*)buf; 
    header->ver_ihl = 0x45;
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
    return routeIPPacket(buf, len + IP_HEADER_LEN); 
}

