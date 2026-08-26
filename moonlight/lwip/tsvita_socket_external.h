#ifndef TSVITA_LWIP_SOCKET_EXTERNAL_H
#define TSVITA_LWIP_SOCKET_EXTERNAL_H

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/tcp.h>

/*
 * VitaSDK exposes the BSD socket ABI used by Moonlight, but omits several
 * constants/types that lwIP's socket implementation expects.  Keep the
 * public Vita structures and fill only the missing compatibility surface.
 */
#ifndef SIN_ZERO_LEN
#define SIN_ZERO_LEN 6
#endif

#ifndef inet_addr_from_ip4addr
#define inet_addr_from_ip4addr(target_inaddr, source_ipaddr) \
    ((target_inaddr)->s_addr = ip4_addr_get_u32(source_ipaddr))
#endif
#ifndef inet_addr_to_ip4addr
#define inet_addr_to_ip4addr(target_ipaddr, source_inaddr) \
    (ip4_addr_set_u32(target_ipaddr, (source_inaddr)->s_addr))
#endif

#ifndef IOV_MAX
#define IOV_MAX 0xffff
#endif

typedef int msg_iovlen_t;

#ifndef MSG_MORE
#define MSG_MORE 0x0400
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x0800
#endif

#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE 136
#endif
#ifndef IPPROTO_RAW
#define IPPROTO_RAW 255
#endif

#ifndef SO_NO_CHECK
#define SO_NO_CHECK 0x100a
#endif
#ifndef SO_BINDTODEVICE
#define SO_BINDTODEVICE 0x100b
#endif

#ifndef TCP_KEEPALIVE
#define TCP_KEEPALIVE 0x02
#endif
#ifndef TCP_KEEPIDLE
#define TCP_KEEPIDLE 0x03
#endif
#ifndef TCP_KEEPINTVL
#define TCP_KEEPINTVL 0x04
#endif
#ifndef TCP_KEEPCNT
#define TCP_KEEPCNT 0x05
#endif

#ifndef IFNAMSIZ
#define IFNAMSIZ 6
struct ifreq {
    char ifr_name[IFNAMSIZ];
};
#endif

#ifndef LWIP_SELECT_MAXNFDS
#define LWIP_SELECT_MAXNFDS FD_SETSIZE
#endif

#ifndef FIONREAD
#define FIONREAD 0x4004667fUL
#endif

#ifndef FIONBIO
#define FIONBIO 0x8004667eUL
#endif

#endif
