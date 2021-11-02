#include "src/ip/ip.h"
#include "src/link/link.h"
#include "src/ip/ip_route.h"
#include <string> 
using std::string; 

int main(int argc, char *argv[]) {
    auto src = (in_addr){sToIP("10.100.1.1")};
    auto dest = (in_addr){sToIP("10.100.1.2")};
    auto mask = (in_addr){sToIP("255.255.255.0")}; 
    auto tableDest = (in_addr){sToIP("10.100.1.0")};
    mac_t mac = {10,100,1,1,182,206};
    auto deviceName = getLegalPortName()[0]; 

    initLegalPort();
    setRoutingTable(tableDest, mask, (const void*) mac, deviceName);
    const char *data = "Hello World!";
    sendIPPacket(dest, src, 253, data, strlen(data));
}