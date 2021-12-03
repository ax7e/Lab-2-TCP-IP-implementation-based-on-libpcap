#include "socket.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdlib>

int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                       struct addrinfo **res)
{
    addrinfo *ret = new addrinfo;
    sockaddr_in *addr = new struct sockaddr_in;
    if (node != nullptr && service != nullptr)
    {
        bool valid_hints = hints != nullptr && (hints->ai_family == AF_INET && hints->ai_protocol == IPPROTO_TCP && hints->ai_flags == 0);
        if (valid_hints)
        {
            addr->sin_family = AF_INET;
            if (node)
            {
                // inet_aton() returns nonzero if the address is valid, zero if not.
                if (inet_aton(node, &addr->sin_addr) == 0)
                {
                    delete (ret);
                    delete (addr);
                    return EAI_NONAME;
                }
            }
            else
            {
                addr->sin_addr.s_addr = 0;
            }
            addr->sin_port = service ? htons(atoi(service)) : 0;
            ret->ai_next = nullptr;
            ret->ai_flags = 0;
            ret->ai_family = AF_INET;
            ret->ai_socktype = SOCK_STREAM;
            ret->ai_protocol = IPPROTO_TCP;
            ret->ai_addrlen = sizeof(struct sockaddr_in);
            ret->ai_addr = (sockaddr *)addr;
            ret->ai_canonname = nullptr;
            (*res) = ret;
            return 0;
        }
    }
    delete (ret);
    delete (addr);
    return EAI_SERVICE;
}

int __wrap_freeaddrinfo(struct addrinfo *res)
{
    std::vector<addrinfo *> to_del;
    for (auto i = res; i; i = i->ai_next)
    {
        to_del.push_back(i);
    }
    for (auto u : to_del)
    {
        if (u->ai_addr)
            delete u->ai_addr;
        delete u;
    }
    return 0;
}

