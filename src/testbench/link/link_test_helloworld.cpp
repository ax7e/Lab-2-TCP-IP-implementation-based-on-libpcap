#include <cstdio>
#include "src/link/device.h"
#include <cstring>
#include "src/link/packetio.h"

#define NAME_LENGTH 1000

int main(int argc, char *argv[])
{
    int res = addDevice("veth1-2");
    if (res != 0) {
        printf("[Error] Failed to add device.\n");
        exit(-1); 
    }
    char s[] = "Hello world!";
    u_char dest[] = {0x12, 0x13, 0x13, 0x22, 0x44, 0x03};
    for (int i = 0; i < 100; ++i)
        sendFrame(s, strlen(s), 0x80, dest, "veth1-2");
    return 0;
}
