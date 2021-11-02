#include <cstdio>
#include "src/link/device.h"
#include <cstring>
#include "src/link/packetio.h"

#define NAME_LENGTH 1000
#define ETHER_HEAD 14

int main(int argc, char *argv[])
{
    int res = addDevice("eth0");
    if (res != 0) {
        printf("[Error] Failed to add device.\n");
        exit(-1); 
    }
    char s[] = "Hello world!";
    char *buf = (char *)malloc(strlen(s) + ETHER_HDR_LEN);
    strncpy(buf + ETHER_HDR_LEN, s, strlen(s));
    u_char dest[] = {0x12, 0x13, 0x13, 0x22, 0x44, 0x03};
    for (int i = 0; i < 100; ++i)
        sendFrame(buf, strlen(s) + 14, 0x80, dest, "eth0");
    return 0;
}
