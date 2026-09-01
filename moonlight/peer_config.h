#ifndef TSVITA_PEER_CONFIG_H
#define TSVITA_PEER_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#define TSVITA_PEER_CONFIG_MAX_SIZE 511U
#define TSVITA_PEER_PUBLIC_KEY_SIZE 32U

typedef enum TsvitaPeerConfigError {
  TSVITA_PEER_CONFIG_OK = 0,
  TSVITA_PEER_CONFIG_ERROR_ARGUMENT = -1,
  TSVITA_PEER_CONFIG_ERROR_TOO_LARGE = -2,
  TSVITA_PEER_CONFIG_ERROR_EMBEDDED_NUL = -3,
  TSVITA_PEER_CONFIG_ERROR_SYNTAX = -4,
  TSVITA_PEER_CONFIG_ERROR_MISSING_FIELD = -5,
  TSVITA_PEER_CONFIG_ERROR_DUPLICATE_FIELD = -6,
  TSVITA_PEER_CONFIG_ERROR_BASE64 = -7,
  TSVITA_PEER_CONFIG_ERROR_IPV4 = -8,
  TSVITA_PEER_CONFIG_ERROR_PORT = -9,
  TSVITA_PEER_CONFIG_ERROR_VALUE_TOO_LONG = -10
} TsvitaPeerConfigError;

typedef struct TsvitaPeerConfig {
  uint8_t public_key[TSVITA_PEER_PUBLIC_KEY_SIZE];
  char endpoint_ip[16];
  uint16_t endpoint_port;
} TsvitaPeerConfig;

TsvitaPeerConfigError tsvita_peer_config_parse(const char *text, size_t size,
                                                TsvitaPeerConfig *result);
const char *tsvita_peer_config_error_name(TsvitaPeerConfigError error);

#endif
