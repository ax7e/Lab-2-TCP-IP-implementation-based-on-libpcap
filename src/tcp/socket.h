#pragma once
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

extern "C"
{
    int __wrap_socket(int domain, int type, int protocal);
    int __real_socket(int domain, int type, int protocal);
    int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len);
    int __wrap_listen(int socket, int backlog);
    int __wrap_accept(int socket, struct sockaddr *address, socklen_t *address_len);
    ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte);
    ssize_t __wrap_read(int fildes, void *buf, size_t nbyte);
    int __wrap_close(int fildes);
    int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
    int __wrap_freeaddrinfo(struct addrinfo *res);
    int __real_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
    int __real_freeaddrinfo(struct addrinfo *res);
    int  __wrap_connect(int socket, const struct sockaddr *address, socklen_t address_len) ;
    int  __real_connect(int socket, const struct sockaddr *address, socklen_t address_len) ;
    int __real_bind(int, const struct sockaddr *, socklen_t);
    int __real_listen(int, int);
    int __real_accept(int, struct sockaddr *, socklen_t *);
    ssize_t __real_read(int, void *, size_t);
    ssize_t __real_write(int, const void *, size_t);
    int __real_close(int);
}