#include "packetio.h"
#include "device.h"
#include <net/ethernet.h>
#include <cstring>

int setFrameReceiveCallback(int id, frameReceiveCallback callback) {
    getIDCache()[id-1].callback = callback;
    return 0; 
}

int sendFrame(const void* buf, int len, int ethtype, const void *dstmac, int id) {
    struct ether_header *header_ethernet;
	u_char *new_packet;

	new_packet = (u_char*)malloc(sizeof(u_char) * len);
	memcpy(new_packet, buf, len);
	header_ethernet = (struct ether_header *)new_packet;
	memcpy(header_ethernet->ether_shost, getIDCache()[id-1].mac, ETH_ALEN);
	memcpy(header_ethernet->ether_dhost, dstmac, ETH_ALEN);
	header_ethernet->ether_type = ethtype;
	auto res = pcap_sendpacket(getIDCache()[id-1].handle, new_packet, len);
	if (res < 0) {
		printf("\t ERROR : sendFrame");
        return -1;
	}
	free(new_packet);
    return 0; 
}
