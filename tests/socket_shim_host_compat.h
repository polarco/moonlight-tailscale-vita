#ifndef TSVITA_SOCKET_SHIM_HOST_COMPAT_H
#define TSVITA_SOCKET_SHIM_HOST_COMPAT_H

#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifndef SO_NONBLOCK
#define SO_NONBLOCK 0x1009
#endif

uint64_t sceKernelGetProcessTimeWide(void);
int sceKernelDelayThread(unsigned int microseconds);

int lwip_socket(int domain, int type, int protocol);
int lwip_connect(int socket_id, const struct sockaddr *address,
                 socklen_t address_length);
int lwip_bind(int socket_id, const struct sockaddr *address,
              socklen_t address_length);
int lwip_listen(int socket_id, int backlog);
int lwip_accept(int socket_id, struct sockaddr *address,
                socklen_t *address_length);
ssize_t lwip_send(int socket_id, const void *buffer, size_t length, int flags);
ssize_t lwip_recv(int socket_id, void *buffer, size_t length, int flags);
ssize_t lwip_sendto(int socket_id, const void *buffer, size_t length, int flags,
                    const struct sockaddr *destination,
                    socklen_t destination_length);
ssize_t lwip_recvfrom(int socket_id, void *buffer, size_t length, int flags,
                      struct sockaddr *source, socklen_t *source_length);
int lwip_shutdown(int socket_id, int how);
int lwip_close(int descriptor);
ssize_t lwip_read(int descriptor, void *buffer, size_t length);
ssize_t lwip_write(int descriptor, const void *buffer, size_t length);
int lwip_fcntl(int descriptor, int command, int value);
int lwip_ioctl(int descriptor, long command, void *value);
int lwip_setsockopt(int socket_id, int level, int option, const void *value,
                    socklen_t value_length);
int lwip_getsockopt(int socket_id, int level, int option, void *value,
                    socklen_t *value_length);
int lwip_getsockname(int socket_id, struct sockaddr *address,
                     socklen_t *address_length);
int lwip_getpeername(int socket_id, struct sockaddr *address,
                     socklen_t *address_length);
int lwip_poll(struct pollfd *descriptors, nfds_t count, int timeout);
int lwip_select(int max_descriptor, fd_set *read_set, fd_set *write_set,
                fd_set *error_set, struct timeval *timeout);
int lwip_getaddrinfo(const char *node, const char *service,
                     const struct addrinfo *hints, struct addrinfo **result);
void lwip_freeaddrinfo(struct addrinfo *result);

#endif
