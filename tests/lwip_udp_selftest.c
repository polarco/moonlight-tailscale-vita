#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ip_udp_packet.h"
#include "lwip/init.h"
#include "lwip/ip4.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"

typedef struct TestContext {
  struct netif netif;
  uint8_t outgoing[128];
  size_t outgoing_size;
  bool received;
} TestContext;

uint32_t tsvita_lwip_rand(void) {
  static uint32_t state = 0x4C574950U;
  state = state * 1664525U + 1013904223U;
  return state;
}

uint32_t sys_now(void) {
  static uint32_t now;
  return ++now;
}

static err_t test_output(struct netif *netif, struct pbuf *packet,
                         const ip4_addr_t *destination) {
  (void)destination;
  TestContext *context = (TestContext *)netif->state;
  if (context == NULL || packet->tot_len > sizeof(context->outgoing) ||
      pbuf_copy_partial(packet, context->outgoing, packet->tot_len, 0) !=
          packet->tot_len) {
    return ERR_BUF;
  }
  context->outgoing_size = packet->tot_len;
  return ERR_OK;
}

static err_t test_netif_init(struct netif *netif) {
  netif->name[0] = 'w';
  netif->name[1] = 'g';
  netif->mtu = 1280;
  netif->output = test_output;
  return ERR_OK;
}

static void test_receive(void *argument, struct udp_pcb *pcb,
                         struct pbuf *packet, const ip_addr_t *source,
                         u16_t port) {
  (void)pcb;
  static const uint8_t payload[] = "TSVITA-M2-ECHO";
  TestContext *context = (TestContext *)argument;
  ip_addr_t expected;
  IP_ADDR4(&expected, 10, 77, 0, 1);
  uint8_t received[sizeof(payload) - 1U];
  if (context != NULL && packet != NULL && port == 7777 &&
      ip_addr_cmp(source, &expected) && packet->tot_len == sizeof(received) &&
      pbuf_copy_partial(packet, received, sizeof(received), 0) ==
          sizeof(received) &&
      memcmp(received, payload, sizeof(received)) == 0) {
    context->received = true;
  }
  if (packet != NULL) {
    pbuf_free(packet);
  }
}

static int fail(const char *message) {
  fprintf(stderr, "FALHOU lwIP: %s\n", message);
  return 1;
}

int main(void) {
  static const uint8_t vita_octets[4] = {10, 77, 0, 2};
  static const uint8_t vm_octets[4] = {10, 77, 0, 1};
  static const uint8_t payload[] = "TSVITA-M2-ECHO";
  TestContext context;
  memset(&context, 0, sizeof(context));

  lwip_init();
  ip4_addr_t vita_ip;
  ip4_addr_t mask;
  ip4_addr_t gateway;
  IP4_ADDR(&vita_ip, 10, 77, 0, 2);
  IP4_ADDR(&mask, 255, 255, 255, 0);
  IP4_ADDR(&gateway, 0, 0, 0, 0);
  if (netif_add(&context.netif, &vita_ip, &mask, &gateway, &context,
                test_netif_init, ip4_input) == NULL) {
    return fail("netif_add");
  }
  netif_set_default(&context.netif);
  netif_set_up(&context.netif);
  netif_set_link_up(&context.netif);

  struct udp_pcb *udp = udp_new();
  ip_addr_t vm_ip;
  IP_ADDR4(&vm_ip, 10, 77, 0, 1);
  if (udp == NULL ||
      udp_bind(udp, (const ip_addr_t *)&vita_ip, 40000) != ERR_OK ||
      udp_connect(udp, &vm_ip, 7777) != ERR_OK) {
    return fail("udp setup");
  }
  udp_bind_netif(udp, &context.netif);
  udp_recv(udp, test_receive, &context);

  struct pbuf *request =
      pbuf_alloc(PBUF_TRANSPORT, sizeof(payload) - 1U, PBUF_RAM);
  if (request == NULL ||
      pbuf_take(request, payload, sizeof(payload) - 1U) != ERR_OK ||
      udp_send(udp, request) != ERR_OK) {
    return fail("udp_send");
  }
  pbuf_free(request);
  if (!tsvita_validate_ipv4_udp_packet(
          context.outgoing, context.outgoing_size, vita_octets, vm_octets,
          40000, 7777, payload, sizeof(payload) - 1U)) {
    return fail("pacote de saida da lwIP");
  }

  uint8_t reply[128];
  size_t reply_size = tsvita_build_ipv4_udp_packet(
      reply, sizeof(reply), vm_octets, vita_octets, 7777, 40000, 0x4C57,
      payload, sizeof(payload) - 1U);
  struct pbuf *incoming = pbuf_alloc(PBUF_RAW, (u16_t)reply_size, PBUF_RAM);
  if (incoming == NULL || pbuf_take(incoming, reply, (u16_t)reply_size) !=
                              ERR_OK ||
      ip4_input(incoming, &context.netif) != ERR_OK || !context.received) {
    return fail("entrada UDP da lwIP");
  }

  udp_remove(udp);
  netif_remove(&context.netif);
  puts("OK: lwIP 2.2.1 gerou e recebeu IPv4/UDP em netif wg0 simulada");
  return 0;
}
