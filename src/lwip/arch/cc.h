#ifndef TSVITA_LWIP_ARCH_CC_H
#define TSVITA_LWIP_ARCH_CC_H

#include <stdint.h>

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#define LWIP_PLATFORM_DIAG(message) do { (void)0; } while (0)
#define LWIP_PLATFORM_ASSERT(message) do { (void)(message); } while (0)

uint32_t tsvita_lwip_rand(void);
#define LWIP_RAND() tsvita_lwip_rand()

#endif
