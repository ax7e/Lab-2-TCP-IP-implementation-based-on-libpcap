#include "device.h"
#include "packetio.h"
#include <pcap/pcap.h>
#include <map>
#include <cstring>
#include <vector>
#include <thread>
using std::map; 
using std::thread;
using std::vector; 

vector<Info>& getIDCache() {
    static vector<Info> v; 
    return v; 
}

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    s, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    s, maxlen);
            break;

        case 17:
            for (int i = 10; i < 16; ++i) {
                sprintf(s+(i-10)*3, "%.2x", (u_char)sa->sa_data[i]);
                if (i!=15) sprintf(s+(i-10)*3+2, ":");
            }
            break;
        default:
            printf("%d\n", sa->sa_family);
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
    }
    return s;
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
                get_ip_str(k->addr, buf, 100); 
                printf("Addr:%20s\n",buf);
            }
        }
    }
    pcap_freealldevs(alldevsp);
    return 0; 
}

int getMACAddr(const char *name, u_char *dst) {
    printf("name = %s\n", name); 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_if_t *alldevsp; 
    if (pcap_findalldevs(&alldevsp, errbuf) == PCAP_ERROR) {
        printf("ERROR : %s\n", errbuf);
        return -1;
    }
    for (pcap_if_t *i = alldevsp; i != NULL; i = i->next) {
        if (strcmp(i->name, name) == 0) {
	    printf("Hit\n"); 
            for (auto k = i->addresses; k != NULL; k = k->next)
                if (k->addr->sa_family == 17) {
                    for (int j = 10; j < 16; ++j)
                    {
                        dst[j-10] = k->addr->sa_data[j];
			printf("%x:", dst[j-10]); 
                    }
                }
        }
    }
    puts("[End mac].\n"); 
    pcap_freealldevs(alldevsp);
    return -1; 
}


int addDevice(string device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *ptr; 
    if ((ptr = pcap_create(device.c_str(), errbuf)) == NULL) {
        printf("ERROR : %s\n", errbuf); 
        return -1;
    }
    if (pcap_activate(ptr) < 0) {
        printf("ERROR : pcap_activate.\n"); 
        return -1;
    }
    printf("Activate succeed!\n");
    int id = getIDCache().size()+1;
    getIDCache().push_back((Info){ptr,nullptr});
    getMACAddr(device.c_str(), getIDCache()[id-1].mac);
    return id;
}

std::thread activateListen(int id, int cnt = 0) {
    pcap_t* handle = getIDCache()[id-1].handle;
    auto callback = getIDCache()[id-1].callback;
    std::thread thread([=](int cnt){
        int res; 
        do {
            pcap_pkthdr *hdr; 
            const u_char *data; 
            res = pcap_next_ex(handle, &hdr, &data);
            printf("Link layer header type = %d\n", pcap_datalink(handle));
            printf("Header info : cap_len : %d, len : %d\n", hdr->caplen, hdr->len);
            if (hdr->caplen < 200) {
                printf("Content:");
                for (int i = 0;i < hdr->caplen; ++i)printf("%x",data[i]) ;
                puts(""); 
            }
            callback(data, hdr->caplen, id);  
            fflush(stdout); 
            cnt = cnt - 1; 
        } while (res != PCAP_ERROR && cnt != 0);
    }, cnt);
    return thread; 
}
