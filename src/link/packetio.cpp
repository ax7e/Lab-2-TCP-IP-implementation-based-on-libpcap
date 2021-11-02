#include "packetio.h"
#include "device.h"
#include <net/ethernet.h>
#include <cstring>

int setFrameReceiveCallback(string id, frameReceiveCallback callback) {
    getIDCache()[id].callback = callback;
    return 0; 
}

int sendFrame(const void* buf, int len, int ethtype, const void *dstmac, const string &name) {
    struct ether_header *header_ethernet;
	u_char *new_packet;

	new_packet = (u_char*)malloc(sizeof(u_char) * (ETH_HLEN + len));
	memcpy(new_packet + ETH_HLEN, buf, len);
	header_ethernet = (struct ether_header *)new_packet;
	memcpy(header_ethernet->ether_shost, getIDCache()[name].mac, ETH_ALEN);
	memcpy(header_ethernet->ether_dhost, dstmac, ETH_ALEN);
	header_ethernet->ether_type = ethtype;
	if (getIDCache().count(name) == 0) {
		printf("[Error] device not activated!\n"); 
		free(new_packet);
		return -1;
	}
	auto res = pcap_sendpacket(getIDCache()[name].handle, new_packet, ETH_HLEN + len);
	if (res < 0) {
		printf("[Error] sendFrame\n");
		free(new_packet);
        return -1;
	}
	free(new_packet);
    return 0; 
}
