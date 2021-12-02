#include "device.h"
#include "packetio.h"
#include <pcap/pcap.h>
#include <map>
#include <vector>
#include <thread>
#include <future>
#include <cstring>
using std::map; 
using std::thread;
using std::vector; 

#define MAC_ADDRESS 17

map<string, Info>& getIDCache() {
    static map<string, Info> v; 
    return v; 
}

int get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) {
        case AF_INET:
            memcpy(s, &((struct sockaddr_in*)sa)->sin_addr, 4);
            return AF_INET; 
        case AF_INET6:
            memcpy(s, &((struct sockaddr_in6 *)sa)->sin6_addr, 16);
            return AF_INET6; 
        case MAC_ADDRESS:
            memcpy(s, sa->sa_data+10, 6);
            return MAC_ADDRESS;
        default:
            printf("%d\n", sa->sa_family);
            strncpy(s, "Unknown AF", maxlen);
            return -1;
    }
}

int displayDevice() {
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_if_t *alldevsp; 
    if (pcap_findalldevs(&alldevsp, errbuf) == PCAP_ERROR) {
        printf("ERROR : %s\n", errbuf);
        return -1;
    }
    for (pcap_if_t *i = alldevsp; i != NULL; i = i->next) {
        printf("Name: %20s  Desc : %50s  Flags : 0x%x.", i->name, i->description, i->flags);
        if (PCAP_IF_UP & i->flags) printf("[up]");
        if (PCAP_IF_RUNNING & i->flags) printf("[running]");
        if (PCAP_IF_WIRELESS & i->flags) printf("[wireless]");
        if ((PCAP_IF_CONNECTION_STATUS & i->flags) == PCAP_IF_CONNECTION_STATUS_CONNECTED) printf("[connected]");
        if ((PCAP_IF_CONNECTION_STATUS & i->flags) == PCAP_IF_CONNECTION_STATUS_UNKNOWN) printf("[unknown]");
        if ((PCAP_IF_CONNECTION_STATUS & i->flags) == PCAP_IF_CONNECTION_STATUS_DISCONNECTED) printf("[disconnected]");
        if ((PCAP_IF_CONNECTION_STATUS & i->flags) == PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE) printf("[not_applicable]");
        puts(""); 
        if (i->addresses != NULL) {
            char buf[100];
            for (auto k = i->addresses; k != NULL; k = k->next)
            {
                int type = get_ip_str(k->addr, buf, 100); 
                switch(type) {
                    case AF_INET:
                        printf("IPV4: ");
                        for (int j = 0;j < 4; ++j) printf("%d%c", buf[j], ".\n"[j==3]);
                        break;
                    case AF_INET6:
                        printf("IPV6: ");
                        for (int j = 0;j < 16; ++j) printf("%02x", (unsigned char) buf[j]);
                        puts(""); 
                        break;
                    case MAC_ADDRESS:
                        printf("MAC: ");
                        for (int j = 0;j < 6; ++j) printf("%02x:", (unsigned char)buf[j]);
                        puts(""); 
                        break;
                    default:
                        printf("Unknown Address.\n");

                }
            }
        }
    }
    pcap_freealldevs(alldevsp);
    return 0; 
}

vector<string> getLegalPortName() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    vector<string> res;
    if (pcap_findalldevs(&alldevsp, errbuf) == PCAP_ERROR) {
        printf("[Error] %s\n", errbuf);
        return res;
    }
    for (pcap_if_t *i = alldevsp; i != NULL; i = i->next) {
        if (i->addresses != NULL) {
            char buf[100];
            for (auto k = i->addresses; k != NULL; k = k->next)
            {
                int type = get_ip_str(k->addr, buf, 100); 
                switch(type) {
                    case AF_INET:
                        res.push_back(string(i->name)); 

                }
            }
        }
    }
    pcap_freealldevs(alldevsp);
    return res;
}

int getMACAddress(const char *name, u_char *dst) {
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_if_t *alldevsp; 
    if (pcap_findalldevs(&alldevsp, errbuf) == PCAP_ERROR) {
        printf("ERROR : %s\n", errbuf);
        return -1;
    }
    for (pcap_if_t *i = alldevsp; i != NULL; i = i->next) {
        if (strcmp(i->name, name) == 0) {
            for (auto k = i->addresses; k != NULL; k = k->next)
                if (k->addr->sa_family == MAC_ADDRESS) {
                    memcpy(dst, (char*)k->addr->sa_data + 10, 6);
                    pcap_freealldevs(alldevsp);
                    return 0; 
                }
        }
    }
    pcap_freealldevs(alldevsp);
    return -1; 
}


int addDevice(string device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *ptr; 
    if ((ptr = pcap_create(device.c_str(), errbuf)) == NULL) {
        printf("[Error] %s\n", errbuf); 
        return -1;
    }
   	if (pcap_set_timeout(ptr, PACKET_TIMEOUT) != 0) {
        printf("[Error] %s\n", errbuf); 
        return -1;
    }

    auto tmp = pcap_set_immediate_mode(ptr, 1);
    if (tmp != 0) {
        printf("[Error] Set Immediate Mode.\n"); 
        return -1;
    }
    if (pcap_activate(ptr) < 0) {
        printf("[Error] : pcap_activate.\n"); 
        return -1;
    }

    printf("[\e[32mInfo\e[0m] Activation succeed!\n");
    getIDCache()[device] = (Info){ptr,nullptr,0};
    int res = getMACAddress(device.c_str(), getIDCache()[device].mac);
    printf("[\e[32mInfo\e[0m] Successfully fetched MAC address!\n");
    if (res != 0) {
        printf("[Error] Failed to get MAC address\n");
    }
    return 0;
}

std::future<int> activateListen(string id, int cnt = 0) {
    pcap_t* handle = getIDCache()[id].handle;
    auto callback = getIDCache()[id].callback;
    printf("[\e[32mInfo\e[0m] Listen thread of port %s begins. \n", id.c_str()); 
    return std::async([=](int cnt){
        int res; 
        do {
            pcap_pkthdr *hdr; 
            const u_char *data; 
            res = pcap_next_ex(handle, &hdr, &data);
            if (res == 1) callback(data, hdr->caplen, id);  
            cnt = cnt - 1; 
            std::this_thread::sleep_for(std::chrono::milliseconds(20)); 
        } while (res != PCAP_ERROR && cnt != 0 && socketCount != 0);
        printf("[\e[32mInfo\e[0m] Listen thread of port %s ends. \n", id.c_str()); 
        if (res == PCAP_ERROR || cnt != 0) return -1; 
        return 0; 
    }, cnt);
}


std::atomic<int> socketCount;