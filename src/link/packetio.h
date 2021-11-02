#pragma once

#define IPV4_ETHER_TYPE 0x08
/**
* @file packetio.h
* @brief Library supporting sending/receiving Ethernet II frames.
*/
#include <netinet/ether.h>
#include "device.h"
/**
* @brief Encapsulate some data into an Ethernet II frame and send it.
*
* @param buf Pointer to the payload.
* @param len Length of the payload.
* @param ethtype EtherType field value of this frame.
* @param destmac MAC address of the destination.
* @param id ID of the device(returned by ‘addDevice ‘) to send on.
* @return 0 on success , -1 on error.
* @see addDevice
*/
int sendFrame(const void* buf , int len ,
int ethtype , const void* destmac , const string &id);

/**
* @brief Register a callback function to be called each time an
* Ethernet II frame was received.
*
* @param callback the callback function.
* @return 0 on success , -1 on error.
* @see frameReceiveCallback
*/
int setFrameReceiveCallback(string id, frameReceiveCallback callback);