#include "src/ip/ip.h"
#include "src/link/link.h"
#include "src/ip/ip_route.h"
#include <string> 
using std::string; 

int main(int argc, char *argv[]) {
    auto dest = (in_addr){sToIP("10.1.1.1")};
    auto mask = (in_addr){sToIP("255.255.255.0")}; 
    mac_t mac = {0x12,0x13,0x14,0x15,0x16,0x17};
    auto deviceName = getLegalPortName()[0]; 
    setRoutingTable(dest, mask, (const void*) mac, deviceName);
}