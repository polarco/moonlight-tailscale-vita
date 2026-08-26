#include "tunnel.h"

#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/rng.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>

#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "ipv4_literal.h"
#include "lwip/ip4.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/tcpip.h"
#include "wireguard.h"

#define TSVITA_DIRECTORY "ux0:data/TailscaleVita"
#define TSVITA_PRIVATE_KEY TSVITA_DIRECTORY "/wg-private.key"
#define TSVITA_CONFIG TSVITA_DIRECTORY "/wg-peer.conf"
#define TSVITA_LOG TSVITA_DIRECTORY "/moonlight-tunnel.log"
#define TSVITA_FALLBACK_LOG "ux0:data/moonlight/tsvita-network.log"
#define TSVITA_INNER_MTU 1280U
#define TSVITA_OUTER_TIMEOUT_US 100000
#define TSVITA_HANDSHAKE_TIMEOUT_US 5000000ULL
#define TSVITA_REKEY_INTERVAL_US 100000000ULL
#define TSVITA_KEEPALIVE_INTERVAL_US 25000000ULL
#define TSVITA_OUTER_RCVBUF 262144

typedef enum TunnelState {
  TUNNEL_STOPPED = 0,
  TUNNEL_STARTING,
  TUNNEL_ONLINE,
  TUNNEL_FAILED
} TunnelState;

typedef struct PeerConfig {
  uint8_t public_key[WIREGUARD_PUBLIC_KEY_LEN];
  char endpoint_ip[48];
  uint16_t endpoint_port;
} PeerConfig;

typedef struct TunnelContext {
  int outer_socket;
  SceNetSockaddrIn endpoint;
  SceNetInAddr endpoint_address;
  struct wireguard_device device;
  struct wireguard_peer *peer;
  struct netif netif;
  pthread_t receive_thread;
  bool receive_thread_started;
  bool running;
  uint32_t pending_handshake_sender;
  uint64_t last_handshake_us;
  uint64_t last_transport_tx_us;
  uint64_t tx_packets;
  uint64_t rx_packets;
  uint64_t decrypt_rejects;
  uint64_t replay_rejects;
  uint64_t other_rejects;
} TunnelContext;

static TunnelContext g_tunnel;
static TunnelState g_state = TUNNEL_STOPPED;
static pthread_mutex_t g_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_state_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t g_peer_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_last_error[160] = "nao iniciado";

static void append_log_line(const char *path, const char *line,
                            unsigned int count) {
  SceUID file = sceIoOpen(path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND,
                          0600);
  if (file >= 0) {
    sceIoWrite(file, line, count);
    sceIoClose(file);
    return;
  }

  /*
   * The first physical Moonlight builds could read the same ux0: trees but
   * sceIoOpen() silently failed for the trace files. Moonlight itself already
   * uses newlib stdio successfully in ux0:data/moonlight, so keep an
   * independent fallback and close it immediately to survive an app crash.
   */
  FILE *fallback = fopen(path, "ab");
  if (fallback != NULL) {
    fwrite(line, 1U, count, fallback);
    fflush(fallback);
    fclose(fallback);
  }
}

void tsvita_trace(const char *component, const char *format, ...) {
  char message[256];
  va_list arguments;
  va_start(arguments, format);
  vsnprintf(message, sizeof(message), format, arguments);
  va_end(arguments);

  char line[320];
  int length = snprintf(line, sizeof(line), "[%s] %s\n", component, message);
  if (length <= 0) {
    return;
  }
  unsigned int count = (unsigned int)length;
  if (count >= sizeof(line)) {
    count = sizeof(line) - 1U;
  }

  pthread_mutex_lock(&g_log_mutex);
  sceIoMkdir(TSVITA_DIRECTORY, 0700);
  sceIoMkdir("ux0:data/moonlight", 0700);
  append_log_line(TSVITA_LOG, line, count);
  append_log_line(TSVITA_FALLBACK_LOG, line, count);
  pthread_mutex_unlock(&g_log_mutex);
}

static void tunnel_log(const char *level, const char *format, ...) {
  char message[256];
  va_list arguments;
  va_start(arguments, format);
  vsnprintf(message, sizeof(message), format, arguments);
  va_end(arguments);
  tsvita_trace(level, "%s", message);
}

static void set_error(const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  vsnprintf(g_last_error, sizeof(g_last_error), format, arguments);
  va_end(arguments);
  tunnel_log("ERROR", "%s", g_last_error);
}

static char *trim(char *value) {
  while (*value == ' ' || *value == '\t') {
    ++value;
  }
  char *end = value + strlen(value);
  while (end > value &&
         (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' ||
          end[-1] == '\n')) {
    --end;
  }
  *end = '\0';
  return value;
}

static int load_private_key(uint8_t key[WIREGUARD_PRIVATE_KEY_LEN]) {
  SceUID file = sceIoOpen(TSVITA_PRIVATE_KEY, SCE_O_RDONLY, 0);
  if (file < 0) {
    return file;
  }
  uint8_t stored[WIREGUARD_PRIVATE_KEY_LEN + 1U];
  int count = sceIoRead(file, stored, sizeof(stored));
  sceIoClose(file);
  if (count != WIREGUARD_PRIVATE_KEY_LEN) {
    crypto_zero(stored, sizeof(stored));
    return -2;
  }
  memcpy(key, stored, WIREGUARD_PRIVATE_KEY_LEN);
  crypto_zero(stored, sizeof(stored));
  return 0;
}

static int load_peer_config(PeerConfig *config) {
  memset(config, 0, sizeof(*config));
  SceUID file = sceIoOpen(TSVITA_CONFIG, SCE_O_RDONLY, 0);
  if (file < 0) {
    return file;
  }
  char contents[512];
  int length = sceIoRead(file, contents, sizeof(contents) - 1U);
  sceIoClose(file);
  if (length < 0) {
    return length;
  }
  contents[length] = '\0';

  char encoded_key[80] = {0};
  char *line = strtok(contents, "\n");
  while (line != NULL) {
    char *entry = trim(line);
    if (*entry != '\0' && *entry != '#') {
      char *separator = strchr(entry, '=');
      if (separator == NULL) {
        return -3;
      }
      *separator = '\0';
      char *name = trim(entry);
      char *value = trim(separator + 1);
      if (strcmp(name, "peer_public_key") == 0) {
        snprintf(encoded_key, sizeof(encoded_key), "%s", value);
      } else if (strcmp(name, "endpoint_ip") == 0) {
        snprintf(config->endpoint_ip, sizeof(config->endpoint_ip), "%s",
                 value);
      } else if (strcmp(name, "endpoint_port") == 0) {
        char *end = NULL;
        long port = strtol(value, &end, 10);
        if (end == value || *end != '\0' || port < 1 || port > 65535) {
          return -4;
        }
        config->endpoint_port = (uint16_t)port;
      }
    }
    line = strtok(NULL, "\n");
  }

  if (encoded_key[0] == '\0' || config->endpoint_ip[0] == '\0' ||
      config->endpoint_port == 0U) {
    return -5;
  }
  size_t key_size = sizeof(config->public_key);
  if (!wireguard_base64_decode(encoded_key, config->public_key, &key_size) ||
      key_size != sizeof(config->public_key)) {
    return -6;
  }
  uint8_t endpoint[4];
  if (!tsvita_parse_ipv4_literal(config->endpoint_ip, endpoint)) {
    return -7;
  }
  return 0;
}

static int send_transport_locked(const uint8_t *inner, size_t inner_size) {
  if (g_tunnel.peer == NULL ||
      !g_tunnel.peer->curr_keypair.sending_valid ||
      inner_size > TSVITA_INNER_MTU) {
    return -20;
  }
  size_t padded_size = (inner_size + 15U) & ~(size_t)15U;
  uint8_t outgoing[sizeof(struct message_transport_data) +
                   TSVITA_INNER_MTU + 15U + WIREGUARD_AUTHTAG_LEN]
      __attribute__((aligned(4)));
  memset(outgoing, 0, sizeof(outgoing));
  struct message_transport_data *transport =
      (struct message_transport_data *)outgoing;
  transport->type = MESSAGE_TRANSPORT_DATA;
  transport->receiver = g_tunnel.peer->curr_keypair.remote_index;
  U64TO8_LITTLE(transport->counter,
                g_tunnel.peer->curr_keypair.sending_counter);
  if (inner_size != 0U) {
    memcpy(transport->enc_packet, inner, inner_size);
  }
  wireguard_encrypt_packet(transport->enc_packet, transport->enc_packet,
                           padded_size, &g_tunnel.peer->curr_keypair);
  size_t outgoing_size = sizeof(struct message_transport_data) + padded_size +
                         WIREGUARD_AUTHTAG_LEN;
  int sent = sceNetSendto(g_tunnel.outer_socket, outgoing, outgoing_size, 0,
                          (const SceNetSockaddr *)&g_tunnel.endpoint,
                          sizeof(g_tunnel.endpoint));
  if (sent != (int)outgoing_size) {
    return sent < 0 ? sent : -21;
  }
  g_tunnel.last_transport_tx_us = sceKernelGetProcessTimeWide();
  ++g_tunnel.tx_packets;
  return 0;
}

static err_t tunnel_netif_output(struct netif *netif, struct pbuf *packet,
                                 const ip4_addr_t *destination) {
  (void)netif;
  (void)destination;
  if (packet == NULL || packet->tot_len == 0U ||
      packet->tot_len > TSVITA_INNER_MTU) {
    return ERR_BUF;
  }
  uint8_t inner[TSVITA_INNER_MTU];
  if (pbuf_copy_partial(packet, inner, packet->tot_len, 0) != packet->tot_len) {
    return ERR_BUF;
  }
  pthread_mutex_lock(&g_peer_mutex);
  int result = send_transport_locked(inner, packet->tot_len);
  pthread_mutex_unlock(&g_peer_mutex);
  if (result < 0) {
    set_error("envio WireGuard falhou: %d", result);
    return ERR_IF;
  }
  return ERR_OK;
}

static err_t tunnel_netif_init(struct netif *netif) {
  netif->name[0] = 'w';
  netif->name[1] = 'g';
  netif->mtu = TSVITA_INNER_MTU;
  netif->output = tunnel_netif_output;
  return ERR_OK;
}

static int send_handshake_locked(void) {
  struct message_handshake_initiation initiation;
  if (!wireguard_create_handshake_initiation(&g_tunnel.device,
                                              g_tunnel.peer, &initiation)) {
    return -30;
  }
  int sent = sceNetSendto(g_tunnel.outer_socket, &initiation,
                          sizeof(initiation), 0,
                          (const SceNetSockaddr *)&g_tunnel.endpoint,
                          sizeof(g_tunnel.endpoint));
  if (sent != (int)sizeof(initiation)) {
    return sent < 0 ? sent : -31;
  }
  g_tunnel.pending_handshake_sender = initiation.sender;
  return 0;
}

static int process_handshake_response_locked(const uint8_t *packet,
                                              size_t packet_size) {
  if (packet_size != sizeof(struct message_handshake_response) ||
      wireguard_get_message_type(packet, packet_size) !=
          MESSAGE_HANDSHAKE_RESPONSE) {
    return -32;
  }
  struct message_handshake_response *response =
      (struct message_handshake_response *)(uintptr_t)packet;
  if (response->receiver != g_tunnel.pending_handshake_sender ||
      !wireguard_check_mac1(
          &g_tunnel.device, packet,
          sizeof(struct message_handshake_response) -
              (2U * WIREGUARD_COOKIE_LEN),
          response->mac1) ||
      !wireguard_process_handshake_response(&g_tunnel.device, g_tunnel.peer,
                                            response)) {
    return -33;
  }
  wireguard_start_session(g_tunnel.peer, true);
  g_tunnel.last_handshake_us = sceKernelGetProcessTimeWide();
  g_tunnel.pending_handshake_sender = 0U;
  tunnel_log("OK", "handshake WireGuard autenticado");
  return 0;
}

static int process_transport_locked(const uint8_t *incoming,
                                    size_t incoming_size) {
  if (incoming_size < sizeof(struct message_transport_data) +
                          WIREGUARD_AUTHTAG_LEN ||
      incoming_size > sizeof(struct message_transport_data) +
                          TSVITA_INNER_MTU + 15U + WIREGUARD_AUTHTAG_LEN) {
    return -40;
  }
  const struct message_transport_data *transport =
      (const struct message_transport_data *)incoming;
  struct wireguard_keypair *keypair =
      get_peer_keypair_for_idx(g_tunnel.peer, transport->receiver);
  size_t encrypted_size = incoming_size - sizeof(*transport);
  if (keypair == NULL || !keypair->receiving_valid ||
      encrypted_size < WIREGUARD_AUTHTAG_LEN) {
    return -41;
  }
  uint8_t plaintext[TSVITA_INNER_MTU + 15U] __attribute__((aligned(4)));
  memset(plaintext, 0, sizeof(plaintext));
  size_t plaintext_size = encrypted_size - WIREGUARD_AUTHTAG_LEN;
  uint64_t counter = U8TO64_LITTLE(transport->counter);
  if (!wireguard_decrypt_packet(plaintext, transport->enc_packet,
                                encrypted_size, counter, keypair)) {
    return -42;
  }
  if (!wireguard_check_replay(keypair, counter)) {
    return -47;
  }
  if (plaintext_size == 0U) {
    return 0;
  }
  if (plaintext_size < 20U || (plaintext[0] >> 4) != 4U ||
      plaintext[16] != 10U || plaintext[17] != 77U ||
      plaintext[18] != 0U || plaintext[19] != 2U) {
    return -43;
  }
  size_t ip_size = ((size_t)plaintext[2] << 8U) | plaintext[3];
  if (ip_size < 20U || ip_size > plaintext_size ||
      ip_size > TSVITA_INNER_MTU) {
    return -44;
  }
  struct pbuf *packet = pbuf_alloc(PBUF_RAW, (u16_t)ip_size, PBUF_POOL);
  if (packet == NULL ||
      pbuf_take(packet, plaintext, (u16_t)ip_size) != ERR_OK) {
    if (packet != NULL) {
      pbuf_free(packet);
    }
    return -45;
  }
  err_t result = tcpip_input(packet, &g_tunnel.netif);
  if (result != ERR_OK) {
    pbuf_free(packet);
    return -46;
  }
  ++g_tunnel.rx_packets;
  return 0;
}

static bool source_is_peer(const SceNetSockaddrIn *source) {
  return source->sin_addr.s_addr == g_tunnel.endpoint_address.s_addr &&
         source->sin_port == g_tunnel.endpoint.sin_port;
}

static bool should_log_rejection(uint64_t count) {
  return count <= 4U || (count & (count - 1U)) == 0U;
}

static void record_transport_rejection(int result) {
  uint64_t *counter = &g_tunnel.other_rejects;
  const char *reason = "outro";
  if (result == -42) {
    counter = &g_tunnel.decrypt_rejects;
    reason = "autenticacao";
  } else if (result == -47) {
    counter = &g_tunnel.replay_rejects;
    reason = "replay/janela";
  }
  ++*counter;
  if (should_log_rejection(*counter)) {
    tunnel_log("WARN", "pacote WireGuard rejeitado: %d motivo=%s total=%llu",
               result, reason, (unsigned long long)*counter);
  }
}

static void *receive_thread_main(void *unused) {
  (void)unused;
  while (g_tunnel.running) {
    uint8_t incoming[1600] __attribute__((aligned(4)));
    SceNetSockaddrIn source;
    unsigned int source_size = sizeof(source);
    memset(&source, 0, sizeof(source));
    int received = sceNetRecvfrom(g_tunnel.outer_socket, incoming,
                                  sizeof(incoming), 0,
                                  (SceNetSockaddr *)&source, &source_size);
    if (received > 0 && source_is_peer(&source)) {
      uint8_t type = wireguard_get_message_type(incoming, (size_t)received);
      pthread_mutex_lock(&g_peer_mutex);
      int result = 0;
      if (type == MESSAGE_HANDSHAKE_RESPONSE) {
        result = process_handshake_response_locked(incoming,
                                                   (size_t)received);
      } else if (type == MESSAGE_TRANSPORT_DATA) {
        result = process_transport_locked(incoming, (size_t)received);
      }
      pthread_mutex_unlock(&g_peer_mutex);
      if (result < 0) {
        record_transport_rejection(result);
      }
    }

    uint64_t now = sceKernelGetProcessTimeWide();
    pthread_mutex_lock(&g_peer_mutex);
    if (g_tunnel.pending_handshake_sender == 0U &&
        now - g_tunnel.last_handshake_us >= TSVITA_REKEY_INTERVAL_US) {
      int result = send_handshake_locked();
      if (result < 0) {
        tunnel_log("WARN", "rekey nao enviado: %d", result);
      } else {
        tunnel_log("INFO", "rekey WireGuard solicitado");
      }
    }
    if (g_tunnel.peer != NULL &&
        g_tunnel.peer->curr_keypair.sending_valid &&
        now - g_tunnel.last_transport_tx_us >=
            TSVITA_KEEPALIVE_INTERVAL_US) {
      int result = send_transport_locked(NULL, 0U);
      if (result < 0) {
        tunnel_log("WARN", "keepalive nao enviado: %d", result);
      }
    }
    pthread_mutex_unlock(&g_peer_mutex);
  }
  return NULL;
}

static pthread_mutex_t g_tcpip_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_tcpip_init_cond = PTHREAD_COND_INITIALIZER;
static bool g_tcpip_ready;

static void tcpip_ready_callback(void *unused) {
  (void)unused;
  pthread_mutex_lock(&g_tcpip_init_mutex);
  g_tcpip_ready = true;
  pthread_cond_broadcast(&g_tcpip_init_cond);
  pthread_mutex_unlock(&g_tcpip_init_mutex);
}

static int initialize_lwip(void) {
  pthread_mutex_lock(&g_tcpip_init_mutex);
  g_tcpip_ready = false;
  tcpip_init(tcpip_ready_callback, NULL);
  while (!g_tcpip_ready) {
    pthread_cond_wait(&g_tcpip_init_cond, &g_tcpip_init_mutex);
  }
  pthread_mutex_unlock(&g_tcpip_init_mutex);

  ip4_addr_t vita_ip;
  ip4_addr_t netmask;
  ip4_addr_t gateway;
  IP4_ADDR(&vita_ip, 10, 77, 0, 2);
  IP4_ADDR(&netmask, 255, 255, 255, 0);
  IP4_ADDR(&gateway, 10, 77, 0, 1);
  if (netifapi_netif_add(&g_tunnel.netif, &vita_ip, &netmask, &gateway,
                         &g_tunnel, tunnel_netif_init, tcpip_input) != ERR_OK ||
      netifapi_netif_set_default(&g_tunnel.netif) != ERR_OK ||
      netifapi_netif_set_up(&g_tunnel.netif) != ERR_OK ||
      netifapi_netif_set_link_up(&g_tunnel.netif) != ERR_OK) {
    return -50;
  }
  return 0;
}

static int perform_initial_handshake(void) {
  pthread_mutex_lock(&g_peer_mutex);
  int result = send_handshake_locked();
  pthread_mutex_unlock(&g_peer_mutex);
  if (result < 0) {
    return result;
  }

  uint64_t deadline = sceKernelGetProcessTimeWide() +
                      TSVITA_HANDSHAKE_TIMEOUT_US;
  while (sceKernelGetProcessTimeWide() < deadline) {
    uint8_t incoming[256] __attribute__((aligned(4)));
    SceNetSockaddrIn source;
    unsigned int source_size = sizeof(source);
    memset(&source, 0, sizeof(source));
    int received = sceNetRecvfrom(g_tunnel.outer_socket, incoming,
                                  sizeof(incoming), 0,
                                  (SceNetSockaddr *)&source, &source_size);
    if (received > 0 && source_is_peer(&source)) {
      pthread_mutex_lock(&g_peer_mutex);
      result = process_handshake_response_locked(incoming, (size_t)received);
      pthread_mutex_unlock(&g_peer_mutex);
      if (result == 0) {
        return 0;
      }
    }
  }
  return -51;
}

static int start_tunnel(void) {
  sceIoMkdir(TSVITA_DIRECTORY, 0700);
  sceIoMkdir("ux0:data/moonlight", 0700);
  SceUID log = sceIoOpen(TSVITA_LOG,
                         SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0600);
  if (log >= 0) {
    sceIoClose(log);
  }
  log = sceIoOpen(TSVITA_FALLBACK_LOG,
                  SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0600);
  if (log >= 0) {
    sceIoClose(log);
  }
  tunnel_log("INFO", "Moonlight Tailscale Adapter 0.1.8 iniciando");
  tunnel_log("INFO", "WireGuard replay-window=%u bits",
             WIREGUARD_REPLAY_BITS_TOTAL);

  int network_state = 0;
  int result = sceNetCtlInetGetState(&network_state);
  if (result < 0 || network_state != SCE_NETCTL_STATE_CONNECTED) {
    set_error("Wi-Fi indisponivel: state=%d result=%d", network_state,
              result);
    return -60;
  }

  uint8_t private_key[WIREGUARD_PRIVATE_KEY_LEN];
  memset(private_key, 0, sizeof(private_key));
  result = load_private_key(private_key);
  if (result < 0) {
    set_error("wg-private.key ausente/invalida: %d", result);
    return result;
  }
  PeerConfig config;
  result = load_peer_config(&config);
  if (result < 0) {
    crypto_zero(private_key, sizeof(private_key));
    set_error("wg-peer.conf invalido: %d", result);
    return result;
  }

  memset(&g_tunnel, 0, sizeof(g_tunnel));
  g_tunnel.outer_socket = -1;
  wireguard_init();
  if (!wireguard_device_init(&g_tunnel.device, private_key)) {
    crypto_zero(private_key, sizeof(private_key));
    crypto_zero(&config, sizeof(config));
    set_error("identidade WireGuard rejeitada");
    return -61;
  }
  crypto_zero(private_key, sizeof(private_key));
  g_tunnel.peer = peer_alloc(&g_tunnel.device);
  if (g_tunnel.peer == NULL ||
      !wireguard_peer_init(&g_tunnel.device, g_tunnel.peer,
                           config.public_key, NULL)) {
    crypto_zero(&config, sizeof(config));
    set_error("peer WireGuard rejeitado");
    return -62;
  }

  uint8_t endpoint_octets[4];
  if (!tsvita_parse_ipv4_literal(config.endpoint_ip, endpoint_octets)) {
    crypto_zero(&config, sizeof(config));
    set_error("endpoint WireGuard invalido");
    return -63;
  }
  memcpy(&g_tunnel.endpoint_address.s_addr, endpoint_octets,
         sizeof(endpoint_octets));
  memset(&g_tunnel.endpoint, 0, sizeof(g_tunnel.endpoint));
  g_tunnel.endpoint.sin_len = sizeof(g_tunnel.endpoint);
  g_tunnel.endpoint.sin_family = SCE_NET_AF_INET;
  g_tunnel.endpoint.sin_port = sceNetHtons(config.endpoint_port);
  g_tunnel.endpoint.sin_addr = g_tunnel.endpoint_address;
  crypto_zero(&config, sizeof(config));

  g_tunnel.outer_socket =
      sceNetSocket("tsvita_moonlight_wg", SCE_NET_AF_INET,
                   SCE_NET_SOCK_DGRAM, SCE_NET_IPPROTO_UDP);
  if (g_tunnel.outer_socket < 0) {
    set_error("socket WireGuard falhou: %d", g_tunnel.outer_socket);
    return g_tunnel.outer_socket;
  }
  int timeout = TSVITA_OUTER_TIMEOUT_US;
  sceNetSetsockopt(g_tunnel.outer_socket, SCE_NET_SOL_SOCKET,
                   SCE_NET_SO_RCVTIMEO, &timeout, sizeof(timeout));
  sceNetSetsockopt(g_tunnel.outer_socket, SCE_NET_SOL_SOCKET,
                   SCE_NET_SO_SNDTIMEO, &timeout, sizeof(timeout));
  int receive_buffer = TSVITA_OUTER_RCVBUF;
  int buffer_result = sceNetSetsockopt(
      g_tunnel.outer_socket, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVBUF,
      &receive_buffer, sizeof(receive_buffer));
  tunnel_log("INFO", "socket externo rcvbuf=%d result=%d", receive_buffer,
             buffer_result);

  result = perform_initial_handshake();
  if (result < 0) {
    sceNetSocketClose(g_tunnel.outer_socket);
    g_tunnel.outer_socket = -1;
    set_error("handshake WireGuard falhou: %d", result);
    return result;
  }
  result = initialize_lwip();
  if (result < 0) {
    sceNetSocketClose(g_tunnel.outer_socket);
    g_tunnel.outer_socket = -1;
    set_error("lwIP socket mode falhou: %d", result);
    return result;
  }

  g_tunnel.running = true;
  result = pthread_create(&g_tunnel.receive_thread, NULL,
                          receive_thread_main, NULL);
  if (result != 0) {
    g_tunnel.running = false;
    set_error("thread WireGuard falhou: %d", result);
    return -64;
  }
  g_tunnel.receive_thread_started = true;
  pthread_detach(g_tunnel.receive_thread);
  tunnel_log("OK", "online: wg0=10.77.0.2/24 MTU=%u",
             TSVITA_INNER_MTU);
  snprintf(g_last_error, sizeof(g_last_error), "online");
  return 0;
}

int tsvita_tunnel_ensure_started(void) {
  pthread_mutex_lock(&g_state_mutex);
  while (g_state == TUNNEL_STARTING) {
    pthread_cond_wait(&g_state_cond, &g_state_mutex);
  }
  if (g_state == TUNNEL_ONLINE) {
    pthread_mutex_unlock(&g_state_mutex);
    return 0;
  }
  if (g_state == TUNNEL_FAILED) {
    pthread_mutex_unlock(&g_state_mutex);
    return -1;
  }
  g_state = TUNNEL_STARTING;
  pthread_mutex_unlock(&g_state_mutex);

  int result = start_tunnel();

  pthread_mutex_lock(&g_state_mutex);
  g_state = result == 0 ? TUNNEL_ONLINE : TUNNEL_FAILED;
  pthread_cond_broadcast(&g_state_cond);
  pthread_mutex_unlock(&g_state_mutex);
  return result;
}

bool tsvita_tunnel_is_online(void) {
  pthread_mutex_lock(&g_state_mutex);
  bool online = g_state == TUNNEL_ONLINE;
  pthread_mutex_unlock(&g_state_mutex);
  return online;
}

const char *tsvita_tunnel_last_error(void) {
  return g_last_error;
}
