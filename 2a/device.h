#pragma once
#include <cstdio>
#include <string>
#include <map>
#include <pcap/pcap.h>
#include <vector>
using std::vector;
using std::string;
/**
* @file device.h
* @brief Library supporting network device management.
*/
/**
* Add a device to the library for sending/receiving packets.
*
* @param device Name of network device to send/receive packet on.
* @return A non -negative _device -ID_ on success , -1 on error.
*/
int addDevice(string device);
/**
* Find a device added by ‘addDevice ‘.
*
* @param device Name of the network device.
* @return A non -negative _device -ID_ on success , -1 if no such device
* was found.
*/
int displayDevice();
int activateListen(int id);
/**
* @brief Process a frame upon receiving it.
*
* @param buf Pointer to the frame.
* @param len Length of the frame.
* @param id ID of the device (returned by ‘addDevice ‘) receiving
* current frame.
* @return -1 on success , -1 on error.
* @see addDevice
*/
typedef int (* frameReceiveCallback)(const void*, int , int);
struct Info {
    pcap_t *handle; 
    frameReceiveCallback callback; 
};
vector<Info>& getIDCache();