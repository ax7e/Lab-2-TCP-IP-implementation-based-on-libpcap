#include <cstdio>
#include <cstring>
#include "src/link/device.h"
#include "src/link/packetio.h"
#include "src/ip/ip.h"

#define NAME_LENGTH 1000
#define ETHER_HEAD 14

int callback(const void *data, int len, int id)
{
    const u_char *p = (u_char *)data;
    printf("Destination MAC : ");
    for (int i = 0; i < 6; ++i)
        printf("%02x%c", p[i], ": "[i == 5]);
    printf("Source MAC : ");
    for (int i = 6; i < 12; ++i)
        printf("%02x%c", p[i], ": "[i == 11]);
    printf("Type : 0x");
    for (int i = 12; i < 13; ++i)
    {
        printf("%02x", p[i]);
    }
    puts("");
    return 0;
}

int main(int argc, char *argv[])
{
    int res = displayDevice();
    if (res != 0) {
        printf("[Error] Error occurred.\n"); 
        exit(-1); 
    }
    printf("-----------------------------------\n");
    auto r = getLegalPortName(); 
    for (auto x : r) {
        printf("Name = %10s, IPV4 =", x.c_str()); 
        ip_t ip; 
        getIPAddress(x.c_str(), ip);
        for (int i = 0;i < 4; ++i) printf("%d%c", ip[i], ". "[i==3]);
        mac_t mac; 
        getMACAddress(x.c_str(), mac);
        printf(",Mac =");
        for (int i = 0;i < 6; ++i) printf("%d%c", ip[i], ":\n"[i==5]);
    }
    return 0;
}
