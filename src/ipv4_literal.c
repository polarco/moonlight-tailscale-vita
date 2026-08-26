#include "ipv4_literal.h"

#include <stddef.h>

bool tsvita_parse_ipv4_literal(const char *text, uint8_t output[4]) {
  if (text == NULL || output == NULL || *text == '\0') {
    return false;
  }

  const char *cursor = text;
  uint8_t parsed[4] = {0};
  for (size_t octet = 0; octet < 4; ++octet) {
    if (*cursor < '0' || *cursor > '9') {
      return false;
    }
    unsigned int value = 0;
    unsigned int digits = 0;
    while (*cursor >= '0' && *cursor <= '9') {
      value = value * 10U + (unsigned int)(*cursor - '0');
      ++digits;
      ++cursor;
      if (digits > 3 || value > 255U) {
        return false;
      }
    }
    parsed[octet] = (uint8_t)value;

    if (octet < 3) {
      if (*cursor != '.') {
        return false;
      }
      ++cursor;
    } else if (*cursor != '\0') {
      return false;
    }
  }

  for (size_t index = 0; index < 4; ++index) {
    output[index] = parsed[index];
  }
  return true;
}
