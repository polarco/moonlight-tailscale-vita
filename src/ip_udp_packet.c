#include "ip_udp_packet.h"

#include <string.h>

#define IPV4_VERSION_AND_IHL 0x45U
#define IPV4_PROTOCOL_UDP 17U
#define IPV4_DONT_FRAGMENT 0x4000U

static uint16_t read_be16(const uint8_t *input) {
  return (uint16_t)(((uint16_t)input[0] << 8) | input[1]);
}

static void write_be16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)(value >> 8);
  output[1] = (uint8_t)value;
}

static uint32_t checksum_add(uint32_t sum, const uint8_t *data,
                             size_t size) {
  while (size >= 2U) {
    sum += read_be16(data);
    data += 2;
    size -= 2U;
  }
  if (size != 0U) {
    sum += (uint16_t)((uint16_t)data[0] << 8);
  }
  return sum;
}

static uint16_t checksum_finish(uint32_t sum) {
  while ((sum >> 16) != 0U) {
    sum = (sum & 0xFFFFU) + (sum >> 16);
  }
  return (uint16_t)~sum;
}

static uint16_t ipv4_checksum(const uint8_t *header) {
  return checksum_finish(checksum_add(0U, header, TSVITA_IPV4_HEADER_SIZE));
}

static uint16_t udp_checksum(const uint8_t source_ip[4],
                             const uint8_t destination_ip[4],
                             const uint8_t *udp, size_t udp_size) {
  uint32_t sum = 0U;
  sum = checksum_add(sum, source_ip, 4U);
  sum = checksum_add(sum, destination_ip, 4U);
  sum += IPV4_PROTOCOL_UDP;
  sum += (uint16_t)udp_size;
  sum = checksum_add(sum, udp, udp_size);
  return checksum_finish(sum);
}

size_t tsvita_build_ipv4_udp_packet(
    uint8_t *output, size_t output_capacity,
    const uint8_t source_ip[4], const uint8_t destination_ip[4],
    uint16_t source_port, uint16_t destination_port,
    uint16_t identification, const uint8_t *payload, size_t payload_size) {
  if (output == NULL || source_ip == NULL || destination_ip == NULL ||
      (payload == NULL && payload_size != 0U) || payload_size > 65507U) {
    return 0U;
  }
  size_t udp_size = TSVITA_UDP_HEADER_SIZE + payload_size;
  size_t packet_size = TSVITA_IPV4_HEADER_SIZE + udp_size;
  if (packet_size > 65535U || output_capacity < packet_size) {
    return 0U;
  }

  memset(output, 0, packet_size);
  output[0] = IPV4_VERSION_AND_IHL;
  output[1] = 0U;
  write_be16(output + 2, (uint16_t)packet_size);
  write_be16(output + 4, identification);
  write_be16(output + 6, IPV4_DONT_FRAGMENT);
  output[8] = 64U;
  output[9] = IPV4_PROTOCOL_UDP;
  memcpy(output + 12, source_ip, 4U);
  memcpy(output + 16, destination_ip, 4U);
  write_be16(output + 10, ipv4_checksum(output));

  uint8_t *udp = output + TSVITA_IPV4_HEADER_SIZE;
  write_be16(udp, source_port);
  write_be16(udp + 2, destination_port);
  write_be16(udp + 4, (uint16_t)udp_size);
  if (payload_size != 0U) {
    memcpy(udp + TSVITA_UDP_HEADER_SIZE, payload, payload_size);
  }
  uint16_t checksum = udp_checksum(source_ip, destination_ip, udp, udp_size);
  write_be16(udp + 6, checksum == 0U ? 0xFFFFU : checksum);
  return packet_size;
}

bool tsvita_validate_ipv4_udp_packet(
    const uint8_t *packet, size_t packet_size,
    const uint8_t expected_source_ip[4],
    const uint8_t expected_destination_ip[4],
    uint16_t expected_source_port, uint16_t expected_destination_port,
    const uint8_t *expected_payload, size_t expected_payload_size) {
  if (packet == NULL || expected_source_ip == NULL ||
      expected_destination_ip == NULL ||
      (expected_payload == NULL && expected_payload_size != 0U) ||
      packet_size < TSVITA_IPV4_HEADER_SIZE + TSVITA_UDP_HEADER_SIZE ||
      packet[0] != IPV4_VERSION_AND_IHL || packet[9] != IPV4_PROTOCOL_UDP) {
    return false;
  }

  uint16_t total_size = read_be16(packet + 2);
  uint16_t fragment = read_be16(packet + 6);
  if (total_size < TSVITA_IPV4_HEADER_SIZE + TSVITA_UDP_HEADER_SIZE ||
      total_size > packet_size || (fragment & 0x3FFFU) != 0U ||
      ipv4_checksum(packet) != 0U ||
      memcmp(packet + 12, expected_source_ip, 4U) != 0 ||
      memcmp(packet + 16, expected_destination_ip, 4U) != 0) {
    return false;
  }

  const uint8_t *udp = packet + TSVITA_IPV4_HEADER_SIZE;
  uint16_t udp_size = read_be16(udp + 4);
  if (read_be16(udp) != expected_source_port ||
      read_be16(udp + 2) != expected_destination_port ||
      udp_size != total_size - TSVITA_IPV4_HEADER_SIZE ||
      udp_size != TSVITA_UDP_HEADER_SIZE + expected_payload_size) {
    return false;
  }

  uint16_t received_checksum = read_be16(udp + 6);
  if (received_checksum != 0U &&
      udp_checksum(packet + 12, packet + 16, udp, udp_size) != 0U) {
    return false;
  }
  return memcmp(udp + TSVITA_UDP_HEADER_SIZE, expected_payload,
                expected_payload_size) == 0;
}
