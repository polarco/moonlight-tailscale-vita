#ifndef TSVITA_IPV4_LITERAL_H
#define TSVITA_IPV4_LITERAL_H

#include <stdbool.h>
#include <stdint.h>

bool tsvita_parse_ipv4_literal(const char *text, uint8_t output[4]);

#endif
