#pragma once
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string> 
#include <future>
#include <vector> 

using std::string; 
using std::vector; 
#pragma once
#include <netinet/ip.h>

/**
* @brief Manully add an item to routing table . Useful when talking
with real Linux machines .
*
* @param dest The destination IP prefix .
* @param mask The subnet mask of the destination IP prefix .
* @param nextHopMAC MAC address of the next hop.
* @param device Name of device to send packets on.
* @return 0 on success , -1 on error
*/
int setRoutingTable(const in_addr dest, const in_addr mask,
    const void *nextHopMAC, const string &device);


struct RouteTableEntry {
    in_addr dest;
    in_addr mask; 
    u_char nextHopMAC[6]; 
    u_char deviceMac[6]; 
    string deviceName; 
};
bool operator==(const RouteTableEntry &lhs, const RouteTableEntry &rhs) ;
bool operator<(const RouteTableEntry &lhs, const RouteTableEntry &rhs) ;

struct DistVectorEntry {
    static const int infinityDist = 1e9; 
    u_char nextHopMAC[6]; 
    int distance; 
};

vector<std::future<int>> initRouteService(int);
