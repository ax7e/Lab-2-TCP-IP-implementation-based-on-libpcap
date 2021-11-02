#include "ip.h"
#include "src/link/link.h"
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pcap.h>


int getIPAddress(const char *name, u_char *dst)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevsp;
    if (pcap_findalldevs(&alldevsp, errbuf) == PCAP_ERROR)
    {
        printf("[Error] %s\n", errbuf);
        return -1;
    }
    for (pcap_if_t *i = alldevsp; i != NULL; i = i->next)
    {
        if (strcmp(i->name, name) == 0)
        {
            for (auto k = i->addresses; k != NULL; k = k->next)
                if (k->addr->sa_family == AF_INET)
                {
                    memcpy(dst, &((struct sockaddr_in *)k->addr)->sin_addr, 4);
                    pcap_freealldevs(alldevsp);
                    return 0;
                }
        }
    }
    pcap_freealldevs(alldevsp);
    return -1;
}

const uint32_t sToIP(string s) {
    return inet_addr(s.c_str()); 
}

string ipv4_int_to_string(uint32_t in, bool *const success = nullptr)
{
    string ret(INET_ADDRSTRLEN, '\0');
    const bool _success = (NULL != inet_ntop(AF_INET, &in, &ret[0], ret.size()));
    if (success)
    {
        *success = _success;
    }
    if (_success)
    {
        ret.pop_back(); // remove null-terminator required by inet_ntop
    }
    else if (!success)
    {
        char buf[200] = {0};
        strerror_r(errno, buf, sizeof(buf));
        throw std::runtime_error(string("error converting ipv4 int to string ") + to_string(errno) + string(": ") + string(buf));
    }
    return ret;
}
// return is native-endian
// when an error occurs: if success ptr is given, it's set to false, otherwise a std::runtime_error is thrown.
uint32_t ipv4_string_to_int(const string &in, bool *const success = nullptr)
{
    uint32_t ret;
    const bool _success = (1 == inet_pton(AF_INET, in.c_str(), &ret));
    if (success)
    {
        *success = _success;
    }
    else if (!_success)
    {
        char buf[200] = {0};
        strerror_r(errno, buf, sizeof(buf));
        throw std::runtime_error(string("error converting ipv4 string to int ") + to_string(errno) + string(": ") + string(buf));
    }
    return ret;
}