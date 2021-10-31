#include <cstdio>
#include "src/link/device.h"
#include <cstring>
#include "src/link/packetio.h"

#define NAME_LENGTH 1000
#define ETHER_HEAD 14

int callback(const void *data, int len, int id) {
    const u_char *p = (u_char *)data;
    if (len < 200)
    {
        printf("Destination MAC : ");
        for (int i = 0; i < 6; ++i)
            printf("%x%c", p[i], ":\n"[i==5]);
        printf("Source MAC : ");
        for (int i = 6; i < 12; ++i)
            printf("%x%c", p[i], ":\n"[i==11]);
        printf("Type : 0x");
        for (int i = 12; i < 13; ++i)
        {
            printf("%x", p[i]);
        }
        puts(""); 
    }
    return 0; 
}

int main(int argc, char *argv[]) {
    displayDevice(); 
    int id = addDevice("eth0");
    setFrameReceiveCallback(id, callback); 
    auto t = activateListen(id, 20); 
    t.join();
    return 0; 
}
