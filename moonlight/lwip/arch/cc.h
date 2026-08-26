#ifndef TSVITA_MOONLIGHT_LWIP_ARCH_CC_H
#define TSVITA_MOONLIGHT_LWIP_ARCH_CC_H

#include <errno.h>
#include <stdint.h>
#include <netdb.h>
#include <sys/time.h>

/* VitaSDK's netdb.h omits the legacy resolver error used internally by lwIP. */
#ifndef HOST_NOT_FOUND
#define HOST_NOT_FOUND 210
#endif

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

typedef uint32_t sys_prot_t;

#ifndef FIONBIO
#define FIONBIO 0x8004667eUL
#endif

#define LWIP_PLATFORM_DIAG(message) do { (void)0; } while (0)
#define LWIP_PLATFORM_ASSERT(message) do { (void)(message); } while (0)

uint32_t lwip_port_rand(void);
#define LWIP_RAND() lwip_port_rand()

#endif
