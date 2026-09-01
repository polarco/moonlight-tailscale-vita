#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "peer_config.h"

#define VALID_KEY "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

static int expect(const char *name, const char *text, size_t size,
                  TsvitaPeerConfigError wanted) {
  TsvitaPeerConfig result;
  TsvitaPeerConfigError got = tsvita_peer_config_parse(text, size, &result);
  if (got != wanted) {
    fprintf(stderr, "FALHOU parser %s: got=%d (%s) wanted=%d\n", name, got,
            tsvita_peer_config_error_name(got), wanted);
    return 1;
  }
  return 0;
}

int main(void) {
  static const char valid[] =
      "# peer publico\r\n"
      " endpoint_port = 51820 \r\n"
      "unknown_future_field = preserved\r\n"
      "peer_public_key = " VALID_KEY "\r\n"
      " endpoint_ip = 192.0.2.143\r\n";
  TsvitaPeerConfig result;
  if (tsvita_peer_config_parse(valid, sizeof(valid) - 1U, &result) !=
          TSVITA_PEER_CONFIG_OK ||
      result.endpoint_port != 51820U ||
      strcmp(result.endpoint_ip, "192.0.2.143") != 0 ||
      result.public_key[0] != 0U || result.public_key[31] != 31U) {
    fputs("FALHOU parser valido CRLF/ordem livre\n", stderr);
    return 1;
  }

  static const char missing[] = "endpoint_ip=192.0.2.1\nendpoint_port=1\n";
  static const char duplicate[] =
      "peer_public_key=" VALID_KEY "\npeer_public_key=" VALID_KEY
      "\nendpoint_ip=192.0.2.1\nendpoint_port=1\n";
  static const char bad_base64[] =
      "peer_public_key=!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
      "endpoint_ip=192.0.2.1\nendpoint_port=1\n";
  static const char bad_ip[] =
      "peer_public_key=" VALID_KEY "\nendpoint_ip=192.0.2.999\n"
      "endpoint_port=1\n";
  static const char long_ip[] =
      "peer_public_key=" VALID_KEY "\nendpoint_ip=1234567890123456\n"
      "endpoint_port=1\n";
  static const char bad_port[] =
      "peer_public_key=" VALID_KEY "\nendpoint_ip=192.0.2.1\n"
      "endpoint_port=65536\n";
  static const char syntax[] = "recognized-but-no-equals\n";
  static const char embedded_nul[] =
      "peer_public_key=" VALID_KEY "\0endpoint_ip=192.0.2.1\n";
  char too_large[TSVITA_PEER_CONFIG_MAX_SIZE + 1U];
  memset(too_large, '#', sizeof(too_large));

  if (expect("argument", NULL, 0U, TSVITA_PEER_CONFIG_ERROR_ARGUMENT) ||
      expect("too-large", too_large, sizeof(too_large),
             TSVITA_PEER_CONFIG_ERROR_TOO_LARGE) ||
      expect("embedded-nul", embedded_nul, sizeof(embedded_nul) - 1U,
             TSVITA_PEER_CONFIG_ERROR_EMBEDDED_NUL) ||
      expect("syntax", syntax, sizeof(syntax) - 1U,
             TSVITA_PEER_CONFIG_ERROR_SYNTAX) ||
      expect("missing", missing, sizeof(missing) - 1U,
             TSVITA_PEER_CONFIG_ERROR_MISSING_FIELD) ||
      expect("duplicate", duplicate, sizeof(duplicate) - 1U,
             TSVITA_PEER_CONFIG_ERROR_DUPLICATE_FIELD) ||
      expect("base64", bad_base64, sizeof(bad_base64) - 1U,
             TSVITA_PEER_CONFIG_ERROR_BASE64) ||
      expect("ipv4", bad_ip, sizeof(bad_ip) - 1U,
             TSVITA_PEER_CONFIG_ERROR_IPV4) ||
      expect("port", bad_port, sizeof(bad_port) - 1U,
             TSVITA_PEER_CONFIG_ERROR_PORT) ||
      expect("long-value", long_ip, sizeof(long_ip) - 1U,
             TSVITA_PEER_CONFIG_ERROR_VALUE_TOO_LONG))
    return 1;

  for (int error = TSVITA_PEER_CONFIG_OK;
       error >= TSVITA_PEER_CONFIG_ERROR_VALUE_TOO_LONG; --error) {
    if (strcmp(tsvita_peer_config_error_name((TsvitaPeerConfigError)error),
               "unknown") == 0) {
      fputs("FALHOU nome estavel de erro\n", stderr);
      return 1;
    }
  }
  puts("OK: parser de peer estrito e compativel");
  return 0;
}
