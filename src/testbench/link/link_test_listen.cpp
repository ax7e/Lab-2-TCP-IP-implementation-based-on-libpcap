#include <cstdio>
#include "src/link/device.h"
#include <cstring>
#include "src/link/packetio.h"

#define NAME_LENGTH 1000
#define ETHER_HEAD 14

int callback(const void *data, int len, string ) {
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
    string dev = "eth0";    
    setFrameReceiveCallback(dev, callback);
    auto t = activateListen(dev, 20);
    int i = t.get();
    if (i == 0)
    {
        printf("[Info] Process exited successfully\n");
    }
    else
    {
        printf("[Error] Error orrured!\n");
        exit(-1);
    }
    return 0;
}
