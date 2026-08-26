#include <psp2/ctrl.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/rng.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/sysmodule.h>
#include <vita2d.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "ip_udp_packet.h"
#include "ipv4_literal.h"
#include "lwip/init.h"
#include "lwip/ip4.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"
#include "wireguard.h"

#define APP_VERSION "0.4.0"
#define LOG_DIRECTORY "ux0:data/TailscaleVita"
#define LOG_PATH LOG_DIRECTORY "/wg-flow.log"
#define PRIVATE_KEY_PATH LOG_DIRECTORY "/wg-private.key"
#define PUBLIC_KEY_PATH LOG_DIRECTORY "/wg-public.key"
#define CONFIG_PATH LOG_DIRECTORY "/wg-peer.conf"
#define NET_MEMORY_SIZE (1024 * 1024)
#define MAX_LINES 20
#define LINE_LENGTH 180
#define UDP_TIMEOUT_US 5000000
#define M2_SOURCE_PORT 40000U
#define M2_DESTINATION_PORT 7777U
#define M2_TCP_SOURCE_PORT 40001U
#define M2_TCP_DESTINATION_PORT 7778U
#define INNER_MTU 1280U
#define LWIP_POLL_TIMEOUT_US 100000

typedef enum LineLevel {
  LEVEL_INFO,
  LEVEL_OK,
  LEVEL_WARN,
  LEVEL_ERROR
} LineLevel;

typedef struct ProbeLine {
  LineLevel level;
  char text[LINE_LENGTH];
} ProbeLine;

typedef struct PeerConfig {
  uint8_t public_key[WIREGUARD_PUBLIC_KEY_LEN];
  char endpoint_ip[48];
  uint16_t endpoint_port;
} PeerConfig;

static ProbeLine g_lines[MAX_LINES];
static int g_line_count;
static SceUID g_log_fd = -1;
static vita2d_pgf *g_font;
static void *g_net_memory;
static bool g_net_module_loaded;
static bool g_net_initialized;
static bool g_netctl_initialized;

static unsigned int color_for_level(LineLevel level) {
  switch (level) {
    case LEVEL_OK:
      return RGBA8(98, 211, 131, 255);
    case LEVEL_WARN:
      return RGBA8(248, 195, 95, 255);
    case LEVEL_ERROR:
      return RGBA8(255, 107, 107, 255);
    case LEVEL_INFO:
    default:
      return RGBA8(220, 226, 235, 255);
  }
}

static void render(void) {
  vita2d_start_drawing();
  vita2d_clear_screen();
  vita2d_draw_rectangle(0.0f, 0.0f, 960.0f, 58.0f,
                        RGBA8(24, 76, 116, 255));
  vita2d_pgf_draw_text(g_font, 24, 35, RGBA8(255, 255, 255, 255), 1.05f,
                       "Tailscale Vita - WG Flow Probe " APP_VERSION);
  vita2d_pgf_draw_text(g_font, 24, 53, RGBA8(184, 215, 238, 255), 0.70f,
                       "lwIP UDP + TCP sobre WireGuard - nenhum plugin");

  int first = g_line_count > 17 ? g_line_count - 17 : 0;
  int y = 82;
  for (int index = first; index < g_line_count; ++index) {
    vita2d_pgf_draw_text(g_font, 24, y,
                         color_for_level(g_lines[index].level), 0.69f,
                         g_lines[index].text);
    y += 24;
  }

  vita2d_draw_rectangle(0.0f, 510.0f, 960.0f, 34.0f,
                        RGBA8(18, 27, 38, 255));
  vita2d_pgf_draw_text(g_font, 24, 533, RGBA8(198, 207, 219, 255), 0.69f,
                       "X: repetir   START: sair   Log: ux0:data/TailscaleVita/wg-flow.log");
  vita2d_end_drawing();
  vita2d_swap_buffers();
  vita2d_pool_reset();
}

static void close_log(void) {
  if (g_log_fd >= 0) {
    sceIoClose(g_log_fd);
    g_log_fd = -1;
  }
}

static void reset_report(void) {
  close_log();
  memset(g_lines, 0, sizeof(g_lines));
  g_line_count = 0;
  sceIoMkdir(LOG_DIRECTORY, 0700);
  g_log_fd = sceIoOpen(LOG_PATH,
                       SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0600);
}

static void log_line(LineLevel level, const char *format, ...) {
  char text[LINE_LENGTH];
  va_list arguments;
  va_start(arguments, format);
  vsnprintf(text, sizeof(text), format, arguments);
  va_end(arguments);

  if (g_line_count < MAX_LINES) {
    g_lines[g_line_count].level = level;
    snprintf(g_lines[g_line_count].text,
             sizeof(g_lines[g_line_count].text), "%s", text);
    ++g_line_count;
  }

  if (g_log_fd >= 0) {
    static const char *prefix[] = {"INFO", "OK", "WARN", "ERROR"};
    char persisted[LINE_LENGTH + 24];
    int length = snprintf(persisted, sizeof(persisted), "[%s] %s\n",
                          prefix[level], text);
    if (length > 0) {
      unsigned int count = (unsigned int)length;
      if (count >= sizeof(persisted)) {
        count = sizeof(persisted) - 1;
      }
      sceIoWrite(g_log_fd, persisted, count);
    }
  }
  render();
}

static int write_exact_file(const char *path, const void *data,
                            unsigned int size, SceMode mode) {
  SceUID file = sceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC,
                          mode);
  if (file < 0) {
    return file;
  }
  int result = sceIoWrite(file, data, size);
  if (result == (int)size) {
    int sync_result = sceIoSyncByFd(file, 0);
    if (sync_result < 0) {
      result = sync_result;
    }
  } else if (result >= 0) {
    result = -1;
  }
  sceIoClose(file);
  return result < 0 ? result : 0;
}

static int load_or_create_private_key(uint8_t private_key[32],
                                      bool *created) {
  *created = false;
  SceUID file = sceIoOpen(PRIVATE_KEY_PATH, SCE_O_RDONLY, 0);
  if (file >= 0) {
    uint8_t stored[33];
    int count = sceIoRead(file, stored, sizeof(stored));
    sceIoClose(file);
    if (count != 32) {
      crypto_zero(stored, sizeof(stored));
      return -2;
    }
    memcpy(private_key, stored, 32);
    crypto_zero(stored, sizeof(stored));
    return 0;
  }

  SceIoStat existing;
  memset(&existing, 0, sizeof(existing));
  if (sceIoGetstat(PRIVATE_KEY_PATH, &existing) >= 0) {
    return file;
  }

  int random_result = sceKernelGetRandomNumber(private_key, 32);
  if (random_result < 0) {
    return random_result;
  }
  private_key[0] &= 248U;
  private_key[31] = (uint8_t)((private_key[31] & 127U) | 64U);

  char temporary_path[128];
  snprintf(temporary_path, sizeof(temporary_path),
           LOG_DIRECTORY "/wg-private-%llu.tmp",
           (unsigned long long)sceKernelGetProcessTimeWide());
  int result = write_exact_file(temporary_path, private_key, 32, 0600);
  if (result < 0) {
    return result;
  }
  result = sceIoRename(temporary_path, PRIVATE_KEY_PATH);
  if (result < 0) {
    sceIoRemove(temporary_path);
    return result;
  }
  *created = true;
  return 0;
}

static int export_public_key(const uint8_t public_key[32],
                             char encoded[45]) {
  size_t encoded_size = 45;
  if (!wireguard_base64_encode(public_key, 32, encoded, &encoded_size) ||
      encoded_size != 44) {
    return -1;
  }
  char persisted[46];
  snprintf(persisted, sizeof(persisted), "%s\n", encoded);
  return write_exact_file(PUBLIC_KEY_PATH, persisted,
                          (unsigned int)strlen(persisted), 0644);
}

static char *trim(char *value) {
  while (*value == ' ' || *value == '\t') {
    ++value;
  }
  char *end = value + strlen(value);
  while (end > value && (end[-1] == ' ' || end[-1] == '\t' ||
                         end[-1] == '\r' || end[-1] == '\n')) {
    --end;
  }
  *end = '\0';
  return value;
}

static int create_config_template(void) {
  static const char template_text[] =
      "# Tailscale Vita WG Flow Probe 0.4.0\n"
      "# Preencha com a chave publica e o IPv4 LAN da VM.\n"
      "peer_public_key=\n"
      "endpoint_ip=\n"
      "endpoint_port=51820\n";
  SceUID file = sceIoOpen(CONFIG_PATH,
                          SCE_O_WRONLY | SCE_O_CREAT | SCE_O_EXCL, 0600);
  if (file < 0) {
    return file;
  }
  int result = sceIoWrite(file, template_text, sizeof(template_text) - 1);
  if (result == (int)(sizeof(template_text) - 1)) {
    int sync_result = sceIoSyncByFd(file, 0);
    if (sync_result < 0) {
      result = sync_result;
    }
  } else if (result >= 0) {
    result = -1;
  }
  sceIoClose(file);
  return result < 0 ? result : 0;
}

static int load_peer_config(PeerConfig *config) {
  memset(config, 0, sizeof(*config));
  SceUID file = sceIoOpen(CONFIG_PATH, SCE_O_RDONLY, 0);
  if (file < 0) {
    int create_result = create_config_template();
    return create_result < 0 ? create_result : 1;
  }

  char contents[512];
  int length = sceIoRead(file, contents, sizeof(contents) - 1);
  sceIoClose(file);
  if (length < 0) {
    return length;
  }
  contents[length] = '\0';

  char encoded_key[80] = {0};
  char *line = strtok(contents, "\n");
  while (line != NULL) {
    char *value = trim(line);
    if (*value != '\0' && *value != '#') {
      char *separator = strchr(value, '=');
      if (separator == NULL) {
        return -3;
      }
      *separator = '\0';
      char *name = trim(value);
      char *setting = trim(separator + 1);
      if (strcmp(name, "peer_public_key") == 0) {
        snprintf(encoded_key, sizeof(encoded_key), "%s", setting);
      } else if (strcmp(name, "endpoint_ip") == 0) {
        snprintf(config->endpoint_ip, sizeof(config->endpoint_ip), "%s",
                 setting);
      } else if (strcmp(name, "endpoint_port") == 0) {
        char *end = NULL;
        long port = strtol(setting, &end, 10);
        if (end == setting || *end != '\0' || port < 1 || port > 65535) {
          return -4;
        }
        config->endpoint_port = (uint16_t)port;
      }
    }
    line = strtok(NULL, "\n");
  }

  if (encoded_key[0] == '\0' || config->endpoint_ip[0] == '\0' ||
      config->endpoint_port == 0) {
    return 1;
  }
  size_t key_size = sizeof(config->public_key);
  if (!wireguard_base64_decode(encoded_key, config->public_key, &key_size) ||
      key_size != sizeof(config->public_key)) {
    return -5;
  }
  uint8_t address[4];
  if (!tsvita_parse_ipv4_literal(config->endpoint_ip, address)) {
    return -6;
  }
  return 0;
}

static int initialize_network(void) {
  if (!g_net_module_loaded) {
    int result = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);
    if (result < 0) {
      return result;
    }
    g_net_module_loaded = true;
  }
  if (!g_net_initialized) {
    g_net_memory = malloc(NET_MEMORY_SIZE);
    if (g_net_memory == NULL) {
      return -1;
    }
    memset(g_net_memory, 0, NET_MEMORY_SIZE);
    SceNetInitParam parameters;
    parameters.memory = g_net_memory;
    parameters.size = NET_MEMORY_SIZE;
    parameters.flags = 0;
    int result = sceNetInit(&parameters);
    if (result < 0) {
      free(g_net_memory);
      g_net_memory = NULL;
      return result;
    }
    g_net_initialized = true;
  }
  if (!g_netctl_initialized) {
    int result = sceNetCtlInit();
    if (result < 0) {
      return result;
    }
    g_netctl_initialized = true;
  }
  return 0;
}

static void cleanup_network(void) {
  if (g_netctl_initialized) {
    sceNetCtlTerm();
    g_netctl_initialized = false;
  }
  if (g_net_initialized) {
    sceNetTerm();
    g_net_initialized = false;
  }
  free(g_net_memory);
  g_net_memory = NULL;
  if (g_net_module_loaded) {
    sceSysmoduleUnloadModule(SCE_SYSMODULE_NET);
    g_net_module_loaded = false;
  }
}

typedef struct LwipTunnelContext {
  int socket_id;
  SceNetSockaddrIn destination;
  SceNetInAddr expected_outer_address;
  struct wireguard_peer *peer;
  struct netif netif;
  struct udp_pcb *udp;
  struct tcp_pcb *tcp;
  bool echo_received;
  bool tcp_connected;
  bool tcp_received;
  bool tcp_closed;
  bool tcp_failed;
  int output_error;
  unsigned int inner_tx_size;
  unsigned int inner_rx_size;
  unsigned int tx_packets;
  unsigned int rx_packets;
} LwipTunnelContext;

static bool g_lwip_initialized;

static err_t lwip_tunnel_output(struct netif *netif, struct pbuf *packet,
                                const ip4_addr_t *destination_ip) {
  (void)destination_ip;
  LwipTunnelContext *context = (LwipTunnelContext *)netif->state;
  if (context == NULL || context->peer == NULL ||
      !context->peer->curr_keypair.sending_valid || packet->tot_len == 0U ||
      packet->tot_len > INNER_MTU) {
    return ERR_IF;
  }

  size_t inner_size = packet->tot_len;
  size_t padded_size = (inner_size + 15U) & ~(size_t)15U;
  uint8_t outgoing[sizeof(struct message_transport_data) + INNER_MTU + 15U +
                   WIREGUARD_AUTHTAG_LEN] __attribute__((aligned(4)));
  memset(outgoing, 0, sizeof(outgoing));
  struct message_transport_data *transport =
      (struct message_transport_data *)outgoing;
  transport->type = MESSAGE_TRANSPORT_DATA;
  transport->receiver = context->peer->curr_keypair.remote_index;
  U64TO8_LITTLE(transport->counter,
                context->peer->curr_keypair.sending_counter);
  if (pbuf_copy_partial(packet, transport->enc_packet, (u16_t)inner_size, 0) !=
      inner_size) {
    return ERR_BUF;
  }
  wireguard_encrypt_packet(transport->enc_packet, transport->enc_packet,
                           padded_size, &context->peer->curr_keypair);
  size_t outgoing_size = sizeof(struct message_transport_data) + padded_size +
                         WIREGUARD_AUTHTAG_LEN;
  int sent = sceNetSendto(context->socket_id, outgoing, outgoing_size, 0,
                          (const SceNetSockaddr *)&context->destination,
                          sizeof(context->destination));
  if (sent != (int)outgoing_size) {
    context->output_error = sent < 0 ? sent : -30;
    return ERR_IF;
  }
  context->inner_tx_size = (unsigned int)inner_size;
  ++context->tx_packets;
  return ERR_OK;
}

static err_t lwip_tunnel_netif_init(struct netif *netif) {
  netif->name[0] = 'w';
  netif->name[1] = 'g';
  netif->mtu = INNER_MTU;
  netif->output = lwip_tunnel_output;
  return ERR_OK;
}

static void lwip_echo_received(void *argument, struct udp_pcb *pcb,
                               struct pbuf *packet,
                               const ip_addr_t *source_address,
                               u16_t source_port) {
  (void)pcb;
  static const uint8_t payload[] = "TSVITA-M2-ECHO";
  LwipTunnelContext *context = (LwipTunnelContext *)argument;
  ip_addr_t expected_source;
  IP_ADDR4(&expected_source, 10, 77, 0, 1);
  uint8_t received[sizeof(payload) - 1U];
  bool valid = context != NULL && packet != NULL &&
               source_port == M2_DESTINATION_PORT &&
               ip_addr_cmp(source_address, &expected_source) &&
               packet->tot_len == sizeof(received) &&
               pbuf_copy_partial(packet, received, sizeof(received), 0) ==
                   sizeof(received) &&
               memcmp(received, payload, sizeof(received)) == 0;
  if (valid) {
    context->echo_received = true;
    context->inner_rx_size = (unsigned int)packet->tot_len;
  }
  if (packet != NULL) {
    pbuf_free(packet);
  }
}

static err_t lwip_tcp_connected(void *argument, struct tcp_pcb *pcb,
                                err_t error) {
  static const uint8_t payload[] = "TSVITA-M2-TCP";
  LwipTunnelContext *context = (LwipTunnelContext *)argument;
  if (context == NULL || error != ERR_OK ||
      tcp_write(pcb, payload, sizeof(payload) - 1U, TCP_WRITE_FLAG_COPY) !=
          ERR_OK ||
      tcp_output(pcb) != ERR_OK) {
    if (context != NULL) {
      context->tcp_failed = true;
    }
    return ERR_VAL;
  }
  context->tcp_connected = true;
  return ERR_OK;
}

static err_t lwip_tcp_received(void *argument, struct tcp_pcb *pcb,
                               struct pbuf *packet, err_t error) {
  static const uint8_t payload[] = "TSVITA-M2-TCP";
  LwipTunnelContext *context = (LwipTunnelContext *)argument;
  if (context == NULL || error != ERR_OK) {
    if (packet != NULL) {
      pbuf_free(packet);
    }
    return ERR_VAL;
  }
  if (packet == NULL) {
    context->tcp_closed = true;
    context->tcp = NULL;
    return tcp_close(pcb);
  }
  uint8_t received[sizeof(payload) - 1U];
  bool valid = packet->tot_len == sizeof(received) &&
               pbuf_copy_partial(packet, received, sizeof(received), 0) ==
                   sizeof(received) &&
               memcmp(received, payload, sizeof(received)) == 0;
  tcp_recved(pcb, packet->tot_len);
  pbuf_free(packet);
  if (!valid) {
    context->tcp_failed = true;
    return ERR_VAL;
  }
  context->tcp_received = true;
  return ERR_OK;
}

static void lwip_tcp_error(void *argument, err_t error) {
  (void)error;
  LwipTunnelContext *context = (LwipTunnelContext *)argument;
  if (context != NULL) {
    context->tcp = NULL;
    context->tcp_failed = true;
  }
}

static int lwip_process_transport(LwipTunnelContext *context,
                                  const uint8_t *incoming, size_t incoming_size,
                                  const SceNetSockaddrIn *source) {
  static const uint8_t expected_source_ip[4] = {10, 77, 0, 1};
  static const uint8_t expected_destination_ip[4] = {10, 77, 0, 2};
  if (source->sin_addr.s_addr != context->expected_outer_address.s_addr ||
      source->sin_port != context->destination.sin_port ||
      wireguard_get_message_type(incoming, incoming_size) !=
          MESSAGE_TRANSPORT_DATA) {
    return -31;
  }

  const struct message_transport_data *transport =
      (const struct message_transport_data *)incoming;
  struct wireguard_keypair *keypair =
      get_peer_keypair_for_idx(context->peer, transport->receiver);
  size_t encrypted_size =
      incoming_size - sizeof(struct message_transport_data);
  if (keypair == NULL || !keypair->receiving_valid ||
      encrypted_size < WIREGUARD_AUTHTAG_LEN ||
      encrypted_size > INNER_MTU + 15U + WIREGUARD_AUTHTAG_LEN) {
    return -32;
  }

  uint8_t plaintext[INNER_MTU + 15U] __attribute__((aligned(4)));
  memset(plaintext, 0, sizeof(plaintext));
  size_t plaintext_size = encrypted_size - WIREGUARD_AUTHTAG_LEN;
  uint64_t counter = U8TO64_LITTLE(transport->counter);
  if (!wireguard_decrypt_packet(plaintext, transport->enc_packet,
                                encrypted_size, counter, keypair) ||
      !wireguard_check_replay(keypair, counter)) {
    return -33;
  }
  if (plaintext_size < TSVITA_IPV4_HEADER_SIZE ||
      (plaintext[0] >> 4) != 4U ||
      memcmp(plaintext + 12, expected_source_ip, 4U) != 0 ||
      memcmp(plaintext + 16, expected_destination_ip, 4U) != 0) {
    return -34;
  }
  size_t ip_size = ((size_t)plaintext[2] << 8) | plaintext[3];
  if (ip_size < TSVITA_IPV4_HEADER_SIZE || ip_size > plaintext_size) {
    return -35;
  }

  struct pbuf *packet = pbuf_alloc(PBUF_RAW, (u16_t)ip_size, PBUF_RAM);
  if (packet == NULL || pbuf_take(packet, plaintext, (u16_t)ip_size) != ERR_OK) {
    if (packet != NULL) {
      pbuf_free(packet);
    }
    return -36;
  }
  err_t input_result = context->netif.input(packet, &context->netif);
  if (input_result == ERR_OK) {
    ++context->rx_packets;
  }
  return input_result == ERR_OK ? 0 : -37;
}

static int send_lwip_echo(int socket_id,
                          const SceNetSockaddrIn *destination,
                          SceNetInAddr expected_outer_address,
                          struct wireguard_peer *peer) {
  static const uint8_t payload[] = "TSVITA-M2-ECHO";
  LwipTunnelContext context;
  memset(&context, 0, sizeof(context));
  context.socket_id = socket_id;
  context.destination = *destination;
  context.expected_outer_address = expected_outer_address;
  context.peer = peer;

  SceKernelFreeMemorySizeInfo memory_before;
  memset(&memory_before, 0, sizeof(memory_before));
  memory_before.size = sizeof(memory_before);
  int memory_result = sceKernelGetFreeMemorySize(&memory_before);

  if (!g_lwip_initialized) {
    lwip_init();
    g_lwip_initialized = true;
  }
  ip4_addr_t vita_ip;
  ip4_addr_t netmask;
  ip4_addr_t gateway;
  IP4_ADDR(&vita_ip, 10, 77, 0, 2);
  IP4_ADDR(&netmask, 255, 255, 255, 0);
  IP4_ADDR(&gateway, 0, 0, 0, 0);
  if (netif_add(&context.netif, &vita_ip, &netmask, &gateway, &context,
                lwip_tunnel_netif_init, ip4_input) == NULL) {
    return -40;
  }
  netif_set_default(&context.netif);
  netif_set_up(&context.netif);
  netif_set_link_up(&context.netif);

  int result = -41;
  context.udp = udp_new();
  if (context.udp == NULL) {
    goto cleanup;
  }
  udp_bind_netif(context.udp, &context.netif);
  if (udp_bind(context.udp, (const ip_addr_t *)&vita_ip, M2_SOURCE_PORT) !=
      ERR_OK) {
    result = -42;
    goto cleanup;
  }
  ip_addr_t vm_ip;
  IP_ADDR4(&vm_ip, 10, 77, 0, 1);
  if (udp_connect(context.udp, &vm_ip, M2_DESTINATION_PORT) != ERR_OK) {
    result = -43;
    goto cleanup;
  }
  udp_recv(context.udp, lwip_echo_received, &context);

  struct pbuf *request =
      pbuf_alloc(PBUF_TRANSPORT, sizeof(payload) - 1U, PBUF_RAM);
  if (request == NULL ||
      pbuf_take(request, payload, sizeof(payload) - 1U) != ERR_OK) {
    if (request != NULL) {
      pbuf_free(request);
    }
    result = -44;
    goto cleanup;
  }
  err_t send_result = udp_send(context.udp, request);
  pbuf_free(request);
  if (send_result != ERR_OK || context.output_error < 0) {
    result = context.output_error < 0 ? context.output_error : -45;
    goto cleanup;
  }
  log_line(LEVEL_OK, "lwIP gerou IPv4/UDP: %u B internos",
           context.inner_tx_size);

  int timeout = LWIP_POLL_TIMEOUT_US;
  sceNetSetsockopt(socket_id, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVTIMEO,
                   &timeout, sizeof(timeout));
  uint64_t deadline = sceKernelGetProcessTimeWide() + UDP_TIMEOUT_US;
  while (!context.echo_received && sceKernelGetProcessTimeWide() < deadline) {
    uint8_t incoming[1600] __attribute__((aligned(4)));
    SceNetSockaddrIn source;
    unsigned int source_size = sizeof(source);
    memset(&source, 0, sizeof(source));
    int received = sceNetRecvfrom(socket_id, incoming, sizeof(incoming), 0,
                                  (SceNetSockaddr *)&source, &source_size);
    if (received > 0) {
      int process_result = lwip_process_transport(
          &context, incoming, (size_t)received, &source);
      if (process_result < 0) {
        result = process_result;
        goto cleanup;
      }
    }
    sys_check_timeouts();
  }
  if (!context.echo_received) {
    result = -46;
    goto cleanup;
  }
  log_line(LEVEL_OK, "lwIP recebeu eco UDP: %u B de payload",
           context.inner_rx_size);

  context.tcp = tcp_new();
  if (context.tcp == NULL ||
      tcp_bind(context.tcp, (const ip_addr_t *)&vita_ip,
               M2_TCP_SOURCE_PORT) != ERR_OK) {
    result = -47;
    goto cleanup;
  }
  tcp_arg(context.tcp, &context);
  tcp_recv(context.tcp, lwip_tcp_received);
  tcp_err(context.tcp, lwip_tcp_error);
  if (tcp_connect(context.tcp, (const ip_addr_t *)&vm_ip,
                  M2_TCP_DESTINATION_PORT, lwip_tcp_connected) != ERR_OK) {
    result = -48;
    goto cleanup;
  }

  deadline = sceKernelGetProcessTimeWide() + UDP_TIMEOUT_US;
  while ((!context.tcp_received || !context.tcp_closed) &&
         !context.tcp_failed && sceKernelGetProcessTimeWide() < deadline) {
    uint8_t incoming[1600] __attribute__((aligned(4)));
    SceNetSockaddrIn source;
    unsigned int source_size = sizeof(source);
    memset(&source, 0, sizeof(source));
    int received = sceNetRecvfrom(socket_id, incoming, sizeof(incoming), 0,
                                  (SceNetSockaddr *)&source, &source_size);
    if (received > 0) {
      int process_result = lwip_process_transport(
          &context, incoming, (size_t)received, &source);
      if (process_result < 0) {
        result = process_result;
        goto cleanup;
      }
    }
    sys_check_timeouts();
  }
  if (!context.tcp_connected || !context.tcp_received || context.tcp_failed) {
    result = -49;
    goto cleanup;
  }
  log_line(LEVEL_OK, "lwIP TCP eco autenticado: 13 B de payload");
  log_line(LEVEL_OK, "Fluxos lwIP: UDP + TCP, tx=%u rx=%u",
           context.tx_packets, context.rx_packets);
  log_line(LEVEL_OK, "Interface wg0 lwIP: 10.77.0.2/24 MTU %u", INNER_MTU);
  result = 0;

cleanup:
  if (context.tcp != NULL) {
    tcp_abort(context.tcp);
    context.tcp = NULL;
  }
  if (context.udp != NULL) {
    udp_remove(context.udp);
  }
  netif_set_down(&context.netif);
  netif_remove(&context.netif);
  SceKernelFreeMemorySizeInfo memory_after;
  memset(&memory_after, 0, sizeof(memory_after));
  memory_after.size = sizeof(memory_after);
  if (memory_result >= 0 && sceKernelGetFreeMemorySize(&memory_after) >= 0) {
    int delta_kib = (memory_before.size_user - memory_after.size_user) / 1024;
    log_line(LEVEL_INFO, "Memoria lwIP: antes=%d MiB depois=%d MiB delta=%d KiB",
             memory_before.size_user / (1024 * 1024),
             memory_after.size_user / (1024 * 1024), delta_kib);
  }
  return result;
}

static int send_handshake_and_ip_probe(struct wireguard_device *device,
                                       struct wireguard_peer *peer,
                                       const PeerConfig *config) {
  int state = 0;
  int state_result = sceNetCtlInetGetState(&state);
  if (state_result < 0 || state != SCE_NETCTL_STATE_CONNECTED) {
    log_line(LEVEL_ERROR, "Wi-Fi desconectado: state=%d erro=0x%08X", state,
             (unsigned int)state_result);
    return state_result < 0 ? state_result : -1;
  }
  log_line(LEVEL_OK, "Wi-Fi conectado; peer %s:%u", config->endpoint_ip,
           (unsigned int)config->endpoint_port);

  uint8_t peer_octets[4];
  if (!tsvita_parse_ipv4_literal(config->endpoint_ip, peer_octets)) {
    return -2;
  }
  SceNetInAddr peer_address;
  memcpy(&peer_address.s_addr, peer_octets, sizeof(peer_octets));
  SceNetSockaddrIn destination;
  memset(&destination, 0, sizeof(destination));
  destination.sin_len = sizeof(destination);
  destination.sin_family = SCE_NET_AF_INET;
  destination.sin_port = sceNetHtons(config->endpoint_port);
  destination.sin_addr = peer_address;

  int socket_id = sceNetSocket("tsvita_wg_hs", SCE_NET_AF_INET,
                               SCE_NET_SOCK_DGRAM, SCE_NET_IPPROTO_UDP);
  if (socket_id < 0) {
    return socket_id;
  }
  int timeout = UDP_TIMEOUT_US;
  sceNetSetsockopt(socket_id, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVTIMEO,
                   &timeout, sizeof(timeout));
  sceNetSetsockopt(socket_id, SCE_NET_SOL_SOCKET, SCE_NET_SO_SNDTIMEO,
                   &timeout, sizeof(timeout));

  struct message_handshake_initiation initiation;
  uint64_t started = sceKernelGetProcessTimeWide();
  if (!wireguard_create_handshake_initiation(device, peer, &initiation)) {
    sceNetSocketClose(socket_id);
    log_line(LEVEL_ERROR, "Falha ao criar iniciacao Noise IK");
    return -3;
  }
  int result = sceNetSendto(socket_id, &initiation, sizeof(initiation), 0,
                            (SceNetSockaddr *)&destination,
                            sizeof(destination));
  if (result != (int)sizeof(initiation)) {
    int error = result < 0 ? result : -4;
    sceNetSocketClose(socket_id);
    log_line(LEVEL_ERROR, "Envio de 148 B falhou: 0x%08X errno=%d",
             (unsigned int)result, *sceNetErrnoLoc());
    return error;
  }
  log_line(LEVEL_OK, "Iniciacao Noise IK enviada: %d B", result);

  uint8_t response_buffer[256] __attribute__((aligned(4)));
  SceNetSockaddrIn source;
  unsigned int source_size = sizeof(source);
  memset(response_buffer, 0, sizeof(response_buffer));
  memset(&source, 0, sizeof(source));
  result = sceNetRecvfrom(socket_id, response_buffer, sizeof(response_buffer),
                          0, (SceNetSockaddr *)&source, &source_size);
  if (result < 0) {
    int error_number = *sceNetErrnoLoc();
    sceNetSocketClose(socket_id);
    log_line(LEVEL_ERROR, "Sem resposta UDP: res=0x%08X errno=%d",
             (unsigned int)result, error_number);
    return result;
  }
  if (source.sin_addr.s_addr != peer_address.s_addr ||
      source.sin_port != destination.sin_port) {
    sceNetSocketClose(socket_id);
    log_line(LEVEL_ERROR, "Resposta veio de endpoint inesperado");
    return -5;
  }

  uint8_t type = wireguard_get_message_type(response_buffer, (size_t)result);
  if (type == MESSAGE_COOKIE_REPLY) {
    sceNetSocketClose(socket_id);
    log_line(LEVEL_WARN, "Peer exigiu cookie; repita o teste em alguns segundos");
    return -6;
  }
  if (type != MESSAGE_HANDSHAKE_RESPONSE ||
      result != (int)sizeof(struct message_handshake_response)) {
    sceNetSocketClose(socket_id);
    log_line(LEVEL_ERROR, "Resposta WireGuard invalida: tipo=%u tamanho=%d",
             (unsigned int)type, result);
    return -7;
  }

  struct message_handshake_response *response =
      (struct message_handshake_response *)response_buffer;
  if (response->receiver != initiation.sender) {
    sceNetSocketClose(socket_id);
    log_line(LEVEL_ERROR, "Indice receiver da resposta nao corresponde");
    return -8;
  }
  bool mac_ok = wireguard_check_mac1(
      device, response_buffer,
      sizeof(struct message_handshake_response) - (2 * WIREGUARD_COOKIE_LEN),
      response->mac1);
  if (!mac_ok || !wireguard_process_handshake_response(device, peer, response)) {
    sceNetSocketClose(socket_id);
    log_line(LEVEL_ERROR, "Autenticacao da resposta WireGuard falhou");
    return -9;
  }

  wireguard_start_session(peer, true);
  log_line(LEVEL_OK, "Resposta Noise IK autenticada: %d B",
           (int)sizeof(*response));

  result = send_lwip_echo(socket_id, &destination, peer_address, peer);
  sceNetSocketClose(socket_id);
  if (result < 0) {
    return result;
  }
  uint64_t elapsed = sceKernelGetProcessTimeWide() - started;
  log_line(LEVEL_OK, "Handshake + lwIP completos em %llu us",
           (unsigned long long)elapsed);
  return 0;
}

static void run_probe(void) {
  reset_report();
  log_line(LEVEL_INFO, "Inicio do WG Flow Probe %s", APP_VERSION);

  uint8_t private_key[WIREGUARD_PRIVATE_KEY_LEN];
  memset(private_key, 0, sizeof(private_key));
  bool created = false;
  int result = load_or_create_private_key(private_key, &created);
  if (result < 0) {
    log_line(LEVEL_ERROR, "Identidade do Vita falhou: 0x%08X",
             (unsigned int)result);
    return;
  }
  log_line(LEVEL_OK, "Chave privada %s e mantida somente no Vita",
           created ? "gerada" : "carregada");

  wireguard_init();
  struct wireguard_device device;
  memset(&device, 0, sizeof(device));
  if (!wireguard_device_init(&device, private_key)) {
    crypto_zero(private_key, sizeof(private_key));
    log_line(LEVEL_ERROR, "Nao foi possivel derivar a identidade WireGuard");
    return;
  }
  crypto_zero(private_key, sizeof(private_key));

  char public_key[45];
  memset(public_key, 0, sizeof(public_key));
  result = export_public_key(device.public_key, public_key);
  if (result < 0) {
    crypto_zero(&device, sizeof(device));
    log_line(LEVEL_ERROR, "Falha ao exportar chave publica: 0x%08X",
             (unsigned int)result);
    return;
  }
  log_line(LEVEL_OK, "Chave publica exportada em wg-public.key");
  log_line(LEVEL_INFO, "PublicKey Vita: %s", public_key);

  PeerConfig config;
  result = load_peer_config(&config);
  if (result == 1) {
    log_line(LEVEL_WARN, "Configuracao pendente: edite wg-peer.conf");
    log_line(LEVEL_INFO, "Envie wg-public.key para preparar o gateway");
    log_line(LEVEL_OK, "Fase de pareamento: PRONTA");
    crypto_zero(&device, sizeof(device));
    close_log();
    return;
  }
  if (result < 0) {
    log_line(LEVEL_ERROR, "wg-peer.conf invalido: codigo=%d", result);
    crypto_zero(&device, sizeof(device));
    close_log();
    return;
  }
  log_line(LEVEL_OK, "Configuracao do peer carregada");

  struct wireguard_peer *peer = peer_alloc(&device);
  if (peer == NULL ||
      !wireguard_peer_init(&device, peer, config.public_key, NULL)) {
    log_line(LEVEL_ERROR, "Chave publica do peer foi rejeitada");
    crypto_zero(&config, sizeof(config));
    crypto_zero(&device, sizeof(device));
    close_log();
    return;
  }

  result = initialize_network();
  if (result < 0) {
    log_line(LEVEL_ERROR, "SceNet nao inicializou: 0x%08X",
             (unsigned int)result);
  } else {
    log_line(LEVEL_OK, "SceNet inicializado para UDP WireGuard");
    result = send_handshake_and_ip_probe(&device, peer, &config);
    if (result < 0) {
      log_line(LEVEL_ERROR, "Data plane lwIP falhou: codigo=%d", result);
    }
    log_line(result == 0 ? LEVEL_OK : LEVEL_ERROR,
             "Resultado M2 UDP+TCP: %s",
             result == 0 ? "APROVADO" : "REPROVADO");
  }

  cleanup_network();
  crypto_zero(&config, sizeof(config));
  crypto_zero(&device, sizeof(device));
  close_log();
}

int main(void) {
  sceCtrlSetSamplingMode(SCE_CTRL_MODE_ANALOG);
  if (vita2d_init() < 0) {
    return -1;
  }
  vita2d_set_clear_color(RGBA8(11, 18, 27, 255));
  vita2d_set_vblank_wait(1);
  g_font = vita2d_load_default_pgf();
  if (g_font == NULL) {
    vita2d_fini();
    return -1;
  }

  run_probe();
  SceCtrlData previous;
  memset(&previous, 0, sizeof(previous));
  bool running = true;
  while (running) {
    SceCtrlData current;
    memset(&current, 0, sizeof(current));
    sceCtrlPeekBufferPositive(0, &current, 1);
    unsigned int pressed = current.buttons & ~previous.buttons;
    if ((pressed & SCE_CTRL_CROSS) != 0) {
      run_probe();
    }
    if ((pressed & SCE_CTRL_START) != 0) {
      running = false;
    }
    previous = current;
    render();
    sceKernelDelayThread(16000);
  }

  close_log();
  cleanup_network();
  vita2d_free_pgf(g_font);
  vita2d_fini();
  sceKernelExitProcess(0);
  return 0;
}
