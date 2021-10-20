#include "packetio.h"
#include "device.h"

int setFrameReceiveCallback(int id, frameReceiveCallback callback) {
    getIDCache()[id].callback = callback;
    return 0; 
}