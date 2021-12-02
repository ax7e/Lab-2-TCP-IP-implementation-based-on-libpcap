#pragma once
#include <cstdio>
#include <string>
#include <map>
#include <thread>
#include <pcap/pcap.h>
#include <vector>
#include <future>
using std::vector;
using std::string;

typedef u_char mac_t[6];
typedef u_char ip_t[4];

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
vector<string> getLegalPortName(); 
/**
 * @brief Activate listen on given devices. 
 * 
 * @param cnt Number of messages to process, 0 means infinity
 * @return A thread which does the listen job. The thread returns -1 on failure. 
 *
*/
std::future<int> activateListen(string id, int);
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
typedef int (* frameReceiveCallback)(const void*, int , string);
struct Info {
    pcap_t *handle; 
    frameReceiveCallback callback; 
    u_char mac[6];
};

std::map<string, Info>& getIDCache();

int getMACAddress(const char *name, u_char *dst);
extern std::atomic<int> socketCount;