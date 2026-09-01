#include "peer_config.h"

#include <stdbool.h>
#include <string.h>

#include "ipv4_literal.h"

typedef struct TextSlice {
  const char *data;
  size_t size;
} TextSlice;

static TextSlice trim_slice(TextSlice value) {
  while (value.size > 0U &&
         (value.data[0] == ' ' || value.data[0] == '\t' ||
          value.data[0] == '\r')) {
    ++value.data;
    --value.size;
  }
  while (value.size > 0U &&
         (value.data[value.size - 1U] == ' ' ||
          value.data[value.size - 1U] == '\t' ||
          value.data[value.size - 1U] == '\r')) {
    --value.size;
  }
  return value;
}

static bool slice_equals(TextSlice value, const char *literal) {
  size_t literal_size = strlen(literal);
  return value.size == literal_size &&
         memcmp(value.data, literal, literal_size) == 0;
}

static int base64_value(unsigned char value) {
  if (value >= 'A' && value <= 'Z') return value - 'A';
  if (value >= 'a' && value <= 'z') return value - 'a' + 26;
  if (value >= '0' && value <= '9') return value - '0' + 52;
  if (value == '+') return 62;
  if (value == '/') return 63;
  return -1;
}

static bool decode_public_key(TextSlice encoded,
                              uint8_t output[TSVITA_PEER_PUBLIC_KEY_SIZE]) {
  if (encoded.size != 44U || encoded.data[43] != '=' ||
      encoded.data[42] == '=') {
    return false;
  }
  size_t output_offset = 0U;
  for (size_t offset = 0U; offset < encoded.size; offset += 4U) {
    int a = base64_value((unsigned char)encoded.data[offset]);
    int b = base64_value((unsigned char)encoded.data[offset + 1U]);
    int c = encoded.data[offset + 2U] == '='
                ? 0
                : base64_value((unsigned char)encoded.data[offset + 2U]);
    int d = encoded.data[offset + 3U] == '='
                ? 0
                : base64_value((unsigned char)encoded.data[offset + 3U]);
    bool last = offset + 4U == encoded.size;
    if (a < 0 || b < 0 || c < 0 || d < 0 ||
        (!last && (encoded.data[offset + 2U] == '=' ||
                   encoded.data[offset + 3U] == '=')) ||
        (encoded.data[offset + 2U] == '=' &&
         encoded.data[offset + 3U] != '=') ||
        (last && encoded.data[offset + 3U] == '=' && (d != 0 || (c & 3) != 0))) {
      return false;
    }
    unsigned int combined = (unsigned int)(a << 18) |
                            (unsigned int)(b << 12) |
                            (unsigned int)(c << 6) | (unsigned int)d;
    if (output_offset < TSVITA_PEER_PUBLIC_KEY_SIZE)
      output[output_offset++] = (uint8_t)(combined >> 16);
    if (encoded.data[offset + 2U] != '=' &&
        output_offset < TSVITA_PEER_PUBLIC_KEY_SIZE)
      output[output_offset++] = (uint8_t)(combined >> 8);
    if (encoded.data[offset + 3U] != '=' &&
        output_offset < TSVITA_PEER_PUBLIC_KEY_SIZE)
      output[output_offset++] = (uint8_t)combined;
  }
  return output_offset == TSVITA_PEER_PUBLIC_KEY_SIZE;
}

static TsvitaPeerConfigError parse_port(TextSlice value, uint16_t *port) {
  if (value.size == 0U || value.size > 5U) {
    return TSVITA_PEER_CONFIG_ERROR_PORT;
  }
  unsigned long parsed = 0U;
  for (size_t index = 0U; index < value.size; ++index) {
    if (value.data[index] < '0' || value.data[index] > '9') {
      return TSVITA_PEER_CONFIG_ERROR_PORT;
    }
    parsed = parsed * 10U + (unsigned long)(value.data[index] - '0');
  }
  if (parsed == 0U || parsed > 65535U) {
    return TSVITA_PEER_CONFIG_ERROR_PORT;
  }
  *port = (uint16_t)parsed;
  return TSVITA_PEER_CONFIG_OK;
}

TsvitaPeerConfigError tsvita_peer_config_parse(const char *text, size_t size,
                                                TsvitaPeerConfig *result) {
  if (text == NULL || result == NULL) {
    return TSVITA_PEER_CONFIG_ERROR_ARGUMENT;
  }
  memset(result, 0, sizeof(*result));
  if (size > TSVITA_PEER_CONFIG_MAX_SIZE) {
    return TSVITA_PEER_CONFIG_ERROR_TOO_LARGE;
  }
  if (memchr(text, '\0', size) != NULL) {
    return TSVITA_PEER_CONFIG_ERROR_EMBEDDED_NUL;
  }

  bool key_seen = false;
  bool ip_seen = false;
  bool port_seen = false;
  size_t offset = 0U;
  while (offset < size) {
    size_t line_end = offset;
    while (line_end < size && text[line_end] != '\n') ++line_end;
    TextSlice line = trim_slice((TextSlice){text + offset, line_end - offset});
    offset = line_end < size ? line_end + 1U : size;
    if (line.size == 0U || line.data[0] == '#') continue;

    const char *separator = memchr(line.data, '=', line.size);
    if (separator == NULL) return TSVITA_PEER_CONFIG_ERROR_SYNTAX;
    size_t separator_offset = (size_t)(separator - line.data);
    TextSlice name = trim_slice((TextSlice){line.data, separator_offset});
    TextSlice value = trim_slice((TextSlice){
        separator + 1, line.size - separator_offset - 1U});
    if (name.size == 0U) return TSVITA_PEER_CONFIG_ERROR_SYNTAX;

    if (slice_equals(name, "peer_public_key")) {
      if (key_seen) return TSVITA_PEER_CONFIG_ERROR_DUPLICATE_FIELD;
      key_seen = true;
      if (!decode_public_key(value, result->public_key))
        return TSVITA_PEER_CONFIG_ERROR_BASE64;
    } else if (slice_equals(name, "endpoint_ip")) {
      if (ip_seen) return TSVITA_PEER_CONFIG_ERROR_DUPLICATE_FIELD;
      ip_seen = true;
      if (value.size == 0U || value.size >= sizeof(result->endpoint_ip))
        return TSVITA_PEER_CONFIG_ERROR_VALUE_TOO_LONG;
      memcpy(result->endpoint_ip, value.data, value.size);
      result->endpoint_ip[value.size] = '\0';
      uint8_t octets[4];
      if (!tsvita_parse_ipv4_literal(result->endpoint_ip, octets))
        return TSVITA_PEER_CONFIG_ERROR_IPV4;
    } else if (slice_equals(name, "endpoint_port")) {
      if (port_seen) return TSVITA_PEER_CONFIG_ERROR_DUPLICATE_FIELD;
      port_seen = true;
      TsvitaPeerConfigError port_result = parse_port(value, &result->endpoint_port);
      if (port_result != TSVITA_PEER_CONFIG_OK) return port_result;
    }
  }
  if (!key_seen || !ip_seen || !port_seen)
    return TSVITA_PEER_CONFIG_ERROR_MISSING_FIELD;
  return TSVITA_PEER_CONFIG_OK;
}

const char *tsvita_peer_config_error_name(TsvitaPeerConfigError error) {
  switch (error) {
    case TSVITA_PEER_CONFIG_OK: return "ok";
    case TSVITA_PEER_CONFIG_ERROR_ARGUMENT: return "argument";
    case TSVITA_PEER_CONFIG_ERROR_TOO_LARGE: return "too-large";
    case TSVITA_PEER_CONFIG_ERROR_EMBEDDED_NUL: return "embedded-nul";
    case TSVITA_PEER_CONFIG_ERROR_SYNTAX: return "syntax";
    case TSVITA_PEER_CONFIG_ERROR_MISSING_FIELD: return "missing-field";
    case TSVITA_PEER_CONFIG_ERROR_DUPLICATE_FIELD: return "duplicate-field";
    case TSVITA_PEER_CONFIG_ERROR_BASE64: return "base64";
    case TSVITA_PEER_CONFIG_ERROR_IPV4: return "ipv4";
    case TSVITA_PEER_CONFIG_ERROR_PORT: return "port";
    case TSVITA_PEER_CONFIG_ERROR_VALUE_TOO_LONG: return "value-too-long";
  }
  return "unknown";
}
