#include "wireguard-platform.h"

#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/rng.h>

#include <stdint.h>
#include <string.h>
#include <time.h>

#include "crypto.h"

static int g_random_error;

int tsvita_wireguard_random_error(void) {
  return g_random_error;
}

#ifndef TSVITA_LWIP_SYS_NOW_PROVIDED
uint32_t sys_now(void) {
  return (uint32_t)(sceKernelGetProcessTimeWide() / 1000ULL);
}
#endif

uint32_t wireguard_sys_now(void) {
  return (uint32_t)(sceKernelGetProcessTimeWide() / 1000ULL);
}

uint32_t tsvita_lwip_rand(void) {
  uint32_t value = 0;
  wireguard_random_bytes(&value, sizeof(value));
  return value;
}

void wireguard_random_bytes(void *bytes, size_t size) {
  int result = sceKernelGetRandomNumber(bytes, (SceSize)size);
  if (result < 0) {
    g_random_error = result;
    crypto_zero(bytes, size);
  }
}

void wireguard_tai64n_now(uint8_t *output) {
  uint64_t seconds = 0x400000000000000aULL + (uint64_t)time(NULL);
  uint32_t nanos =
      (uint32_t)((sceKernelGetProcessTimeWide() % 1000000ULL) * 1000ULL);
  U64TO8_BIG(output, seconds);
  U32TO8_BIG(output + 8, nanos);
}

bool wireguard_is_under_load(void) {
  return false;
}
