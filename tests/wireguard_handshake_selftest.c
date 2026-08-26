#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "ip_udp_packet.h"
#include "ipv4_literal.h"
#include "wireguard.h"

static uint32_t test_random_state = 0x13579BDFU;

uint32_t wireguard_sys_now(void) {
  static uint32_t now = 1000;
  return now++;
}

void wireguard_random_bytes(void *bytes, size_t size) {
  uint8_t *output = bytes;
  for (size_t index = 0; index < size; ++index) {
    test_random_state = test_random_state * 1664525U + 1013904223U;
    output[index] = (uint8_t)(test_random_state >> 24);
  }
}

void wireguard_tai64n_now(uint8_t *output) {
  static uint64_t counter = 0x4000000068ULL;
  U64TO8_BIG(output, counter++);
  U32TO8_BIG(output + 8, 0);
}

bool wireguard_is_under_load(void) {
  return false;
}

static int fail(const char *message) {
  fprintf(stderr, "FALHOU: %s\n", message);
  return 1;
}

int main(void) {
  struct wireguard_keypair replay_test;
  memset(&replay_test, 0, sizeof(replay_test));
  if (!wireguard_check_replay(&replay_test, 0U) ||
      !wireguard_check_replay(&replay_test, 1000U) ||
      !wireguard_check_replay(&replay_test, 10U) ||
      wireguard_check_replay(&replay_test, 10U) ||
      !wireguard_check_replay(&replay_test, 9000U) ||
      wireguard_check_replay(&replay_test, 100U)) {
    return fail("WireGuard 8192-bit replay window");
  }

  uint8_t ipv4[4];
  if (!tsvita_parse_ipv4_literal("192.0.2.143", ipv4) ||
      ipv4[0] != 192 || ipv4[1] != 0 || ipv4[2] != 2 || ipv4[3] != 143 ||
      tsvita_parse_ipv4_literal("192.0.2.999", ipv4) ||
      tsvita_parse_ipv4_literal("192.0.2", ipv4) ||
      tsvita_parse_ipv4_literal("192.0.2.1x", ipv4)) {
    return fail("IPv4 literal parser");
  }

  static const uint8_t vita_ip[4] = {10, 77, 0, 2};
  static const uint8_t peer_ip[4] = {10, 77, 0, 1};
  static const uint8_t echo_payload[] = "TSVITA-M2-ECHO";
  uint8_t inner_packet[128];
  size_t inner_size = tsvita_build_ipv4_udp_packet(
      inner_packet, sizeof(inner_packet), vita_ip, peer_ip, 40000, 7777,
      0x5442, echo_payload, sizeof(echo_payload) - 1U);
  if (inner_size != 42U ||
      !tsvita_validate_ipv4_udp_packet(
          inner_packet, inner_size, vita_ip, peer_ip, 40000, 7777,
          echo_payload, sizeof(echo_payload) - 1U)) {
    return fail("IPv4/UDP packet build and validation");
  }
  inner_packet[inner_size - 1U] ^= 1U;
  if (tsvita_validate_ipv4_udp_packet(
          inner_packet, inner_size, vita_ip, peer_ip, 40000, 7777,
          echo_payload, sizeof(echo_payload) - 1U)) {
    return fail("IPv4/UDP checksum rejection");
  }

  uint8_t initiator_private[32] = {1};
  uint8_t responder_private[32] = {2};
  struct wireguard_device initiator;
  struct wireguard_device responder;
  memset(&initiator, 0, sizeof(initiator));
  memset(&responder, 0, sizeof(responder));

  wireguard_init();
  if (!wireguard_device_init(&initiator, initiator_private) ||
      !wireguard_device_init(&responder, responder_private)) {
    return fail("device_init");
  }

  struct wireguard_peer *initiator_peer = peer_alloc(&initiator);
  struct wireguard_peer *responder_peer = peer_alloc(&responder);
  if (initiator_peer == NULL || responder_peer == NULL ||
      !wireguard_peer_init(&initiator, initiator_peer, responder.public_key,
                           NULL) ||
      !wireguard_peer_init(&responder, responder_peer, initiator.public_key,
                           NULL)) {
    return fail("peer_init");
  }

  struct message_handshake_initiation initiation;
  if (!wireguard_create_handshake_initiation(&initiator, initiator_peer,
                                              &initiation)) {
    return fail("create initiation");
  }
  if (!wireguard_check_mac1(
          &responder, (const uint8_t *)&initiation,
          sizeof(initiation) - (2 * WIREGUARD_COOKIE_LEN), initiation.mac1)) {
    return fail("initiation mac1");
  }
  struct wireguard_peer *matched =
      wireguard_process_initiation_message(&responder, &initiation);
  if (matched != responder_peer) {
    return fail("process initiation");
  }

  struct message_handshake_response response;
  if (!wireguard_create_handshake_response(&responder, responder_peer,
                                            &response)) {
    return fail("create response");
  }
  wireguard_start_session(responder_peer, false);
  if (!wireguard_check_mac1(
          &initiator, (const uint8_t *)&response,
          sizeof(response) - (2 * WIREGUARD_COOKIE_LEN), response.mac1) ||
      response.receiver != initiation.sender ||
      !wireguard_process_handshake_response(&initiator, initiator_peer,
                                             &response)) {
    return fail("process response");
  }
  wireguard_start_session(initiator_peer, true);

  uint8_t packet[sizeof(struct message_transport_data) +
                 WIREGUARD_AUTHTAG_LEN] = {0};
  struct message_transport_data *transport =
      (struct message_transport_data *)packet;
  transport->type = MESSAGE_TRANSPORT_DATA;
  transport->receiver = initiator_peer->curr_keypair.remote_index;
  U64TO8_LITTLE(transport->counter,
                initiator_peer->curr_keypair.sending_counter);
  wireguard_encrypt_packet(transport->enc_packet, transport->enc_packet, 0,
                           &initiator_peer->curr_keypair);

  struct wireguard_keypair *receiving = get_peer_keypair_for_idx(
      responder_peer, transport->receiver);
  uint8_t empty[1] = {0};
  if (receiving == NULL ||
      !wireguard_decrypt_packet(empty, transport->enc_packet,
                                WIREGUARD_AUTHTAG_LEN, 0, receiving)) {
    return fail("encrypted keepalive");
  }

  inner_size = tsvita_build_ipv4_udp_packet(
      inner_packet, sizeof(inner_packet), vita_ip, peer_ip, 40000, 7777,
      0x5442, echo_payload, sizeof(echo_payload) - 1U);
  size_t padded_size = (inner_size + 15U) & ~(size_t)15U;
  uint8_t request[256] = {0};
  struct message_transport_data *request_transport =
      (struct message_transport_data *)request;
  request_transport->type = MESSAGE_TRANSPORT_DATA;
  request_transport->receiver = initiator_peer->curr_keypair.remote_index;
  uint64_t request_counter = initiator_peer->curr_keypair.sending_counter;
  U64TO8_LITTLE(request_transport->counter, request_counter);
  memcpy(request_transport->enc_packet, inner_packet, inner_size);
  wireguard_encrypt_packet(request_transport->enc_packet,
                           request_transport->enc_packet, padded_size,
                           &initiator_peer->curr_keypair);

  uint8_t decrypted[128] = {0};
  receiving = get_peer_keypair_for_idx(
      responder_peer, request_transport->receiver);
  if (receiving == NULL ||
      !wireguard_decrypt_packet(
          decrypted, request_transport->enc_packet,
          padded_size + WIREGUARD_AUTHTAG_LEN, request_counter, receiving) ||
      !wireguard_check_replay(receiving, request_counter) ||
      !tsvita_validate_ipv4_udp_packet(
          decrypted, padded_size, vita_ip, peer_ip, 40000, 7777,
          echo_payload, sizeof(echo_payload) - 1U)) {
    return fail("encrypted IPv4/UDP request");
  }
  keypair_update(responder_peer, receiving);

  inner_size = tsvita_build_ipv4_udp_packet(
      inner_packet, sizeof(inner_packet), peer_ip, vita_ip, 7777, 40000,
      0x5443, echo_payload, sizeof(echo_payload) - 1U);
  padded_size = (inner_size + 15U) & ~(size_t)15U;
  uint8_t reply[256] = {0};
  struct message_transport_data *reply_transport =
      (struct message_transport_data *)reply;
  reply_transport->type = MESSAGE_TRANSPORT_DATA;
  reply_transport->receiver = responder_peer->curr_keypair.remote_index;
  uint64_t reply_counter = responder_peer->curr_keypair.sending_counter;
  U64TO8_LITTLE(reply_transport->counter, reply_counter);
  memcpy(reply_transport->enc_packet, inner_packet, inner_size);
  wireguard_encrypt_packet(reply_transport->enc_packet,
                           reply_transport->enc_packet, padded_size,
                           &responder_peer->curr_keypair);

  memset(decrypted, 0, sizeof(decrypted));
  receiving = get_peer_keypair_for_idx(initiator_peer,
                                       reply_transport->receiver);
  if (receiving == NULL ||
      !wireguard_decrypt_packet(
          decrypted, reply_transport->enc_packet,
          padded_size + WIREGUARD_AUTHTAG_LEN, reply_counter, receiving) ||
      !wireguard_check_replay(receiving, reply_counter) ||
      !tsvita_validate_ipv4_udp_packet(
          decrypted, padded_size, peer_ip, vita_ip, 7777, 40000,
          echo_payload, sizeof(echo_payload) - 1U)) {
    return fail("encrypted IPv4/UDP reply");
  }

  puts("OK: Noise IK, keepalive e IPv4/UDP cifrado interoperaram no self-test");
  return 0;
}
