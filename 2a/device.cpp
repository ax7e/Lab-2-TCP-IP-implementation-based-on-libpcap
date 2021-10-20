#include "device.h"
#include "packetio.h"
#include <pcap/pcap.h>
#include <map>
#include <vector>
#include <thread>
using std::map; 
using std::thread;
using std::vector; 

vector<Info>& getIDCache() {
    static vector<Info> v; 
    return v; 
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
    }
    pcap_freealldevs(alldevsp);
    return 0; 
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
    int id = getIDCache().size();
    getIDCache().push_back((Info){ptr,nullptr});
    return id;
}

int activateListen(int id) {
    pcap_t* handle = getIDCache()[id-1].handle;
    std::thread thread([=]{
        int res; 
        do {
            pcap_pkthdr *hdr; 
            const u_char *data; 
            res = pcap_next_ex(handle, &hdr, &data); 
            printf("res = %d\n", res); 
            //printf("Header type : %d\n", pcap_datalink(handle));
        } while(res != PCAP_ERROR);
    });
    return 0; 
}
