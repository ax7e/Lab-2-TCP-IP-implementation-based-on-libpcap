#pragma once
/**
* @file ip.h
* @brief Library supporting sending / receiving IP packets encapsulated
in an Ethernet II frame .
*/
#include <netinet/ip.h>
#include <arpa/inet.h> // inet_ntop & inet_pton
#include <string.h> // strerror_r
#include <arpa/inet.h> // ntohl & htonl
#include "src/link/link.h"
#include "ip_route.h"
#define IP_HEADER_LEN 20
#define PREMBLE_LEN 10
#define V0 if(verbose>=0)
#define VM1 if(verbose>=-1)
#define V1 if(verbose>=1)
#define V2 if(verbose>=2)
extern int verbose;
/**
* @brief Send an IP packet to specified host .
*
* @param src Source IP address .
* @param dest Destination IP address .
* @param proto Value of ‘protocol ‘ field in IP header .
* @param buf pointer to IP payload
* @param len Length of IP payload
* @return 0 on success , -1 on error .
*/
int sendIPPacket(const uint32_t src, const uint32_t dest,
                 int proto, const void *buf, int len, std::optional<string> = std::nullopt);
/**
* @brief Process an IP packet upon receiving it.
*
* @param buf Pointer to the packet .
* @param len Length of the packet .
* @return 0 on success , -1 on error .
* @see addDevice
*/
typedef int (*IPPacketReceiveCallback)(const void *buf, int len);
/**
* @brief Register a callback function to be called each time an IP
packet was received .
*
* @param callback The callback function .
* @return 0 on success , -1 on error .
* @see IPPacketReceiveCallback
*/
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);
/**
 * Get IP address of the device name 
 * 
 * @param dst Location to store the result
 * @param name port name of
 * @return 0 on success, otherwise failure
 */
int getIPAddress(const char *name, u_char *dst);
int getIPAddress(const char *name, in_addr *dst);

const uint32_t sToIP(string s) ;

struct ip_header_t {
    uint8_t  ver_ihl; 
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo; // 3 bits flags and 13 bits fragment-offset
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t   src_addr;
    uint32_t   dst_addr;

    uint8_t ihl() const { return ver_ihl &0x0F; }
    size_t size() const { return ihl() * 4; }
  };

using std::to_string; 
string ipv4_int_to_string(uint32_t in, bool *const success);
uint32_t ipv4_string_to_int(const string &in, bool *const success);

/**
 * @brief init IP service on host
 * @param cnt number of packet to receive before quit(per port)
 * @return vector<std::future<int>> 
 */
vector<std::future<int>> initLegalPort(int);