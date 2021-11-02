#include "ip.h"
#include "src/link/link.h"
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pcap.h>


int getIPAddress(const char *name, u_char *dst)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    if (pcap_findalldevs(&alldevsp, errbuf) == PCAP_ERROR)
    {
        printf("[Error] %s\n", errbuf);
        return -1;
    }
    for (pcap_if_t *i = alldevsp; i != NULL; i = i->next)
    {
        if (strcmp(i->name, name) == 0)
        {
            for (auto k = i->addresses; k != NULL; k = k->next)
                if (k->addr->sa_family == AF_INET)
                {
                    memcpy(dst, &((struct sockaddr_in *)k->addr)->sin_addr, 4);
                    pcap_freealldevs(alldevsp);
                    return 0;
                }
        }
    }
    pcap_freealldevs(alldevsp);
    return -1;
}

const uint32_t sToIP(string s) {
    return inet_addr(s.c_str()); 
}