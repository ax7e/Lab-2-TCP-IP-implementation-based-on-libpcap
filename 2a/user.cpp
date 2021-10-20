#include <cstdio>
#include "device.h"
#include "packetio.h"

#define NAME_LENGTH 1000

int main(int argc, char *argv[]) {
    char deviceName[NAME_LENGTH]; 
    displayDevice(); 
    int id = addDevice("eth0");
    activateListen(id); 
    return 0; 
}