#ifndef TSVITA_IP_UDP_PACKET_H
#define TSVITA_IP_UDP_PACKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TSVITA_IPV4_HEADER_SIZE 20U
#define TSVITA_UDP_HEADER_SIZE 8U

size_t tsvita_build_ipv4_udp_packet(
    uint8_t *output, size_t output_capacity,
    const uint8_t source_ip[4], const uint8_t destination_ip[4],
    uint16_t source_port, uint16_t destination_port,
    uint16_t identification, const uint8_t *payload, size_t payload_size);

bool tsvita_validate_ipv4_udp_packet(
    const uint8_t *packet, size_t packet_size,
    const uint8_t expected_source_ip[4],
    const uint8_t expected_destination_ip[4],
    uint16_t expected_source_port, uint16_t expected_destination_port,
    const uint8_t *expected_payload, size_t expected_payload_size);

#endif
