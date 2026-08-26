#include <psp2/ctrl.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/sysmodule.h>
#include <vita2d.h>

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NET_MEMORY_SIZE (1024 * 1024)
#define MAX_LOG_LINES 64
#define LOG_LINE_LENGTH 192
#define LOG_DIRECTORY "ux0:data/TailscaleVita"
#define LOG_PATH LOG_DIRECTORY "/probe.log"
#define CONTROL_HOST "controlplane.tailscale.com"
#define BASELINE_TCP_IP "1.1.1.1"
#define STUN_HOST "stun.l.google.com"
#define STUN_PORT 19302
#define TCP_CONNECT_TIMEOUT_US 3000000
#define DUMP_BUFFER_SIZE 4096

typedef enum LogLevel {
  LOG_INFO,
  LOG_OK,
  LOG_WARN,
  LOG_ERROR
} LogLevel;

typedef struct LogLine {
  LogLevel level;
  char text[LOG_LINE_LENGTH];
} LogLine;

typedef struct TcpProbeDetail {
  const char *stage;
  int final_result;
  int connect_result;
  int connect_errno;
  int epoll_result;
  unsigned int epoll_events;
  int socket_error;
} TcpProbeDetail;

typedef struct CaptureProbeDetail {
  int create_result;
  int traffic_result;
  int read_result;
  int read_errno;
  int flags;
} CaptureProbeDetail;

static LogLine g_lines[MAX_LOG_LINES];
static int g_line_count;
static SceUID g_log_fd = -1;
static vita2d_pgf *g_font;
static bool g_ui_ready;

static void *g_net_memory;
static bool g_net_module_loaded;
static bool g_net_initialized;
static bool g_netctl_initialized;

static unsigned int color_for_level(LogLevel level) {
  switch (level) {
    case LOG_OK:
      return RGBA8(98, 211, 131, 255);
    case LOG_WARN:
      return RGBA8(248, 195, 95, 255);
    case LOG_ERROR:
      return RGBA8(255, 107, 107, 255);
    case LOG_INFO:
    default:
      return RGBA8(220, 226, 235, 255);
  }
}

static void render(void) {
  if (!g_ui_ready || g_font == NULL) {
    return;
  }

  vita2d_start_drawing();
  vita2d_clear_screen();
  vita2d_draw_rectangle(0.0f, 0.0f, 960.0f, 58.0f,
                        RGBA8(24, 76, 116, 255));
  vita2d_pgf_draw_text(g_font, 24, 35, RGBA8(255, 255, 255, 255), 1.10f,
                       "Tailscale Vita Probe " TV_PROBE_VERSION);
  vita2d_pgf_draw_text(g_font, 24, 53, RGBA8(184, 215, 238, 255), 0.72f,
                       "Diagnostico somente leitura - nenhum plugin e instalado");

  int visible_lines = 18;
  int first = g_line_count > visible_lines ? g_line_count - visible_lines : 0;
  int y = 82;
  for (int index = first; index < g_line_count; ++index) {
    vita2d_pgf_draw_text(g_font, 24, y, color_for_level(g_lines[index].level),
                         0.72f, g_lines[index].text);
    y += 23;
  }

  vita2d_draw_rectangle(0.0f, 510.0f, 960.0f, 34.0f,
                        RGBA8(18, 27, 38, 255));
  vita2d_pgf_draw_text(g_font, 24, 533, RGBA8(198, 207, 219, 255), 0.72f,
                       "X: repetir testes     START: sair     Log: ux0:data/TailscaleVita/probe.log");
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

static void open_log(void) {
  close_log();
  sceIoMkdir(LOG_DIRECTORY, 0777);
  g_log_fd = sceIoOpen(LOG_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC,
                       0666);
}

static void log_message(LogLevel level, const char *format, ...) {
  char text[LOG_LINE_LENGTH];
  va_list arguments;
  va_start(arguments, format);
  vsnprintf(text, sizeof(text), format, arguments);
  va_end(arguments);

  if (g_line_count < MAX_LOG_LINES) {
    g_lines[g_line_count].level = level;
    snprintf(g_lines[g_line_count].text, sizeof(g_lines[g_line_count].text),
             "%s", text);
    ++g_line_count;
  }

  if (g_log_fd >= 0) {
    static const char *prefixes[] = {"INFO", "OK", "WARN", "ERROR"};
    char persisted[LOG_LINE_LENGTH + 24];
    int length = snprintf(persisted, sizeof(persisted), "[%s] %s\n",
                          prefixes[level], text);
    if (length > 0) {
      unsigned int write_length = (unsigned int)length;
      if (write_length >= sizeof(persisted)) {
        write_length = sizeof(persisted) - 1;
      }
      sceIoWrite(g_log_fd, persisted, write_length);
    }
  }

  render();
}

static void reset_report(void) {
  memset(g_lines, 0, sizeof(g_lines));
  g_line_count = 0;
  open_log();
}

static const char *network_state_name(int state) {
  switch (state) {
    case SCE_NETCTL_STATE_DISCONNECTED:
      return "desconectado";
    case SCE_NETCTL_STATE_CONNECTING:
      return "conectando";
    case SCE_NETCTL_STATE_FINALIZING:
      return "finalizando";
    case SCE_NETCTL_STATE_CONNECTED:
      return "conectado";
    default:
      return "desconhecido";
  }
}

static int net_info_string(int code, char *output, size_t output_size) {
  SceNetCtlInfo info;
  memset(&info, 0, sizeof(info));
  int result = sceNetCtlInetGetInfo(code, &info);
  if (result < 0) {
    snprintf(output, output_size, "erro 0x%08X", (unsigned int)result);
    return result;
  }

  const char *value = "";
  switch (code) {
    case SCE_NETCTL_INFO_GET_IP_ADDRESS:
      value = info.ip_address;
      break;
    case SCE_NETCTL_INFO_GET_NETMASK:
      value = info.netmask;
      break;
    case SCE_NETCTL_INFO_GET_DEFAULT_ROUTE:
      value = info.default_route;
      break;
    case SCE_NETCTL_INFO_GET_PRIMARY_DNS:
      value = info.primary_dns;
      break;
    case SCE_NETCTL_INFO_GET_SECONDARY_DNS:
      value = info.secondary_dns;
      break;
    case SCE_NETCTL_INFO_GET_SSID:
      value = info.ssid;
      break;
    default:
      value = "nao suportado pelo probe";
      break;
  }
  snprintf(output, output_size, "%s", value);
  return 0;
}

static int resolve_ipv4(const char *hostname, SceNetInAddr *address,
                        char *printable, size_t printable_size) {
  int resolver = sceNetResolverCreate("tsvita_resolver", NULL, 0);
  if (resolver < 0) {
    return resolver;
  }

  memset(address, 0, sizeof(*address));
  int result = sceNetResolverStartNtoa(resolver, hostname, address, 3000000, 1,
                                       0);
  if (result >= 0 && printable != NULL) {
    if (sceNetInetNtop(SCE_NET_AF_INET, address, printable,
                       (unsigned int)printable_size) == NULL) {
      snprintf(printable, printable_size, "<conversao falhou>");
    }
  }
  sceNetResolverDestroy(resolver);
  return result;
}

static int current_net_errno(void) {
  int *location = sceNetErrnoLoc();
  return location != NULL ? *location : 0;
}

static bool connect_is_in_progress(int result, int network_errno) {
  return network_errno == SCE_NET_EINPROGRESS ||
         network_errno == SCE_NET_EWOULDBLOCK ||
         (unsigned int)result == (unsigned int)SCE_NET_ERROR_EINPROGRESS ||
         (unsigned int)result == (unsigned int)SCE_NET_ERROR_EWOULDBLOCK;
}

static int test_tcp_connect(const SceNetInAddr *address,
                            TcpProbeDetail *detail) {
  memset(detail, 0, sizeof(*detail));
  detail->stage = "socket";
  detail->connect_result = 0;
  detail->epoll_result = 0;

  int socket_id = sceNetSocket("tsvita_tcp", SCE_NET_AF_INET,
                               SCE_NET_SOCK_STREAM, SCE_NET_IPPROTO_TCP);
  if (socket_id < 0) {
    detail->final_result = socket_id;
    return socket_id;
  }

  detail->stage = "nonblocking";
  int nonblocking = 1;
  int result = sceNetSetsockopt(socket_id, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO,
                                &nonblocking, sizeof(nonblocking));
  if (result < 0) {
    detail->final_result = result;
    sceNetSocketClose(socket_id);
    return result;
  }

  SceNetSockaddrIn destination;
  memset(&destination, 0, sizeof(destination));
  destination.sin_len = sizeof(destination);
  destination.sin_family = SCE_NET_AF_INET;
  destination.sin_port = sceNetHtons(443);
  destination.sin_addr = *address;

  detail->stage = "connect";
  detail->connect_result = sceNetConnect(
      socket_id, (SceNetSockaddr *)&destination, sizeof(destination));
  detail->connect_errno = current_net_errno();
  result = detail->connect_result;
  if (result < 0 &&
      connect_is_in_progress(result, detail->connect_errno)) {
    detail->stage = "epoll-create";
    int epoll_id = sceNetEpollCreate("tsvita_epoll", 0);
    if (epoll_id < 0) {
      detail->final_result = epoll_id;
      sceNetSocketClose(socket_id);
      return epoll_id;
    }

    SceNetEpollEvent event;
    memset(&event, 0, sizeof(event));
    event.events = SCE_NET_EPOLLOUT | SCE_NET_EPOLLERR | SCE_NET_EPOLLHUP;
    event.data.fd = socket_id;
    detail->stage = "epoll-control";
    result = sceNetEpollControl(epoll_id, SCE_NET_EPOLL_CTL_ADD, socket_id,
                                &event);
    if (result >= 0) {
      SceNetEpollEvent received;
      memset(&received, 0, sizeof(received));
      detail->stage = "epoll-wait";
      result = sceNetEpollWait(epoll_id, &received, 1,
                               TCP_CONNECT_TIMEOUT_US);
      detail->epoll_result = result;
      if (result > 0) {
        detail->epoll_events = received.events;
        unsigned int error_size = sizeof(detail->socket_error);
        detail->stage = "socket-error";
        result = sceNetGetsockopt(socket_id, SCE_NET_SOL_SOCKET,
                                  SCE_NET_SO_ERROR, &detail->socket_error,
                                  &error_size);
        if (result >= 0) {
          result = detail->socket_error == 0
                       ? 0
                       : (detail->socket_error < 0 ? detail->socket_error
                                                  : -detail->socket_error);
          detail->stage = result == 0 ? "connected" : "socket-error";
        }
      } else if (result == 0) {
        detail->stage = "timeout";
        result = -(int)SCE_NET_ETIMEDOUT;
      }
    }
    sceNetEpollDestroy(epoll_id);
  } else if (result >= 0) {
    detail->stage = "connected";
    result = 0;
  }

  sceNetSocketClose(socket_id);
  detail->final_result = result;
  return result;
}

static int test_stun(char *endpoint, size_t endpoint_size) {
  SceNetInAddr stun_address;
  char stun_ip[32];
  int result = resolve_ipv4(STUN_HOST, &stun_address, stun_ip, sizeof(stun_ip));
  if (result < 0) {
    return result;
  }

  int socket_id = sceNetSocket("tsvita_stun", SCE_NET_AF_INET,
                               SCE_NET_SOCK_DGRAM, SCE_NET_IPPROTO_UDP);
  if (socket_id < 0) {
    return socket_id;
  }

  int timeout_us = 3000000;
  sceNetSetsockopt(socket_id, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVTIMEO,
                   &timeout_us, sizeof(timeout_us));
  sceNetSetsockopt(socket_id, SCE_NET_SOL_SOCKET, SCE_NET_SO_SNDTIMEO,
                   &timeout_us, sizeof(timeout_us));

  SceNetSockaddrIn destination;
  memset(&destination, 0, sizeof(destination));
  destination.sin_len = sizeof(destination);
  destination.sin_family = SCE_NET_AF_INET;
  destination.sin_port = sceNetHtons(STUN_PORT);
  destination.sin_addr = stun_address;

  uint8_t request[20] = {
      0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42,
      0x54, 0x53, 0x56, 0x49, 0x54, 0x41, 0x50, 0x52,
      0x4F, 0x42, 0x45, 0x31};
  uint64_t stamp = sceKernelGetProcessTimeWide();
  memcpy(&request[12], &stamp, sizeof(stamp));

  result = sceNetSendto(socket_id, request, sizeof(request), 0,
                        (SceNetSockaddr *)&destination, sizeof(destination));
  if (result == (int)sizeof(request)) {
    uint8_t response[512];
    SceNetSockaddrIn source;
    unsigned int source_size = sizeof(source);
    memset(&source, 0, sizeof(source));
    result = sceNetRecvfrom(socket_id, response, sizeof(response), 0,
                            (SceNetSockaddr *)&source, &source_size);
    if (result >= 20 && response[0] == 0x01 && response[1] == 0x01 &&
        memcmp(&response[8], &request[8], 12) == 0) {
      snprintf(endpoint, endpoint_size, "%s:%d", stun_ip, STUN_PORT);
      result = 0;
    } else if (result >= 0) {
      result = -2;
    }
  } else if (result >= 0) {
    result = -3;
  }

  sceNetSocketClose(socket_id);
  return result;
}

static void test_packet_capture(char *endpoint, size_t endpoint_size,
                                CaptureProbeDetail *detail) {
  memset(detail, 0, sizeof(*detail));
  detail->create_result = sceNetDumpCreate("tsvita_dump", 16384, 0);

  detail->traffic_result = test_stun(endpoint, endpoint_size);
  if (detail->create_result < 0) {
    detail->read_result = detail->create_result;
    return;
  }

  sceKernelDelayThread(100000);
  uint8_t buffer[DUMP_BUFFER_SIZE];
  memset(buffer, 0, sizeof(buffer));
  detail->flags = SCE_NET_DUMP_DONTWAIT;
  detail->read_result = sceNetDumpRead(detail->create_result, buffer,
                                       sizeof(buffer), &detail->flags);
  detail->read_errno = current_net_errno();
  sceNetDumpDestroy(detail->create_result);
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

static void run_probe(void) {
  reset_report();
  log_message(LOG_INFO, "Inicio do diagnostico; versao %s", TV_PROBE_VERSION);

  SceKernelSystemSwVersion firmware;
  memset(&firmware, 0, sizeof(firmware));
  firmware.size = sizeof(firmware);
  int result = sceKernelGetSystemSwVersion(&firmware);
  if (result >= 0) {
    log_message(LOG_INFO, "Firmware reportado: %s (pode estar spoofado)",
                firmware.versionString);
  } else {
    log_message(LOG_WARN, "Firmware: erro 0x%08X", (unsigned int)result);
  }

  SceKernelFreeMemorySizeInfo memory;
  memset(&memory, 0, sizeof(memory));
  memory.size = sizeof(memory);
  result = sceKernelGetFreeMemorySize(&memory);
  if (result >= 0) {
    log_message(LOG_INFO, "Memoria livre: user=%d MiB, cdram=%d MiB",
                memory.size_user / (1024 * 1024),
                memory.size_cdram / (1024 * 1024));
  } else {
    log_message(LOG_WARN, "Memoria livre: erro 0x%08X", (unsigned int)result);
  }
  log_message(LOG_INFO, "Modelo SDK=%d; Vita TV=%s", sceKernelGetModel(),
              sceKernelIsPSVitaTV() ? "sim" : "nao");

  result = initialize_network();
  if (result < 0) {
    log_message(LOG_ERROR, "Inicializacao de rede falhou: 0x%08X",
                (unsigned int)result);
    log_message(LOG_WARN, "Conecte o Wi-Fi e pressione X para repetir.");
    close_log();
    return;
  }
  log_message(LOG_OK, "SceNet e SceNetCtl inicializados");

  int state = -1;
  result = sceNetCtlInetGetState(&state);
  if (result < 0) {
    log_message(LOG_ERROR, "Estado Wi-Fi: erro 0x%08X", (unsigned int)result);
  } else {
    log_message(state == SCE_NETCTL_STATE_CONNECTED ? LOG_OK : LOG_WARN,
                "Estado Wi-Fi: %s (%d)", network_state_name(state), state);
  }

  char value[128];
  if (net_info_string(SCE_NETCTL_INFO_GET_SSID, value, sizeof(value)) >= 0) {
    log_message(LOG_INFO, "SSID: %s", value);
  }
  net_info_string(SCE_NETCTL_INFO_GET_IP_ADDRESS, value, sizeof(value));
  log_message(LOG_INFO, "IPv4 local: %s", value);
  net_info_string(SCE_NETCTL_INFO_GET_NETMASK, value, sizeof(value));
  log_message(LOG_INFO, "Mascara: %s", value);
  net_info_string(SCE_NETCTL_INFO_GET_DEFAULT_ROUTE, value, sizeof(value));
  log_message(LOG_INFO, "Gateway: %s", value);
  net_info_string(SCE_NETCTL_INFO_GET_PRIMARY_DNS, value, sizeof(value));
  log_message(LOG_INFO, "DNS primario: %s", value);

  SceNetCtlInfo mtu_info;
  memset(&mtu_info, 0, sizeof(mtu_info));
  result = sceNetCtlInetGetInfo(SCE_NETCTL_INFO_GET_MTU, &mtu_info);
  if (result >= 0) {
    log_message(LOG_INFO, "MTU da interface: %u", mtu_info.mtu);
  } else {
    log_message(LOG_WARN, "MTU: erro 0x%08X", (unsigned int)result);
  }

  SceNetInAddr control_address;
  char control_ip[32];
  result = resolve_ipv4(CONTROL_HOST, &control_address, control_ip,
                        sizeof(control_ip));
  if (result >= 0) {
    log_message(LOG_OK, "DNS %s -> %s", CONTROL_HOST, control_ip);
    TcpProbeDetail tcp_detail;
    result = test_tcp_connect(&control_address, &tcp_detail);
    if (result >= 0) {
      log_message(LOG_OK,
                  "TCP control: conectado (connect=%d errno=%d eventos=0x%X)",
                  tcp_detail.connect_result, tcp_detail.connect_errno,
                  tcp_detail.epoll_events);
    } else {
      log_message(LOG_WARN,
                  "TCP control: etapa=%s res=0x%08X connect=%d errno=%d "
                  "wait=%d eventos=0x%X soerr=%d",
                  tcp_detail.stage, (unsigned int)tcp_detail.final_result,
                  tcp_detail.connect_result, tcp_detail.connect_errno,
                  tcp_detail.epoll_result, tcp_detail.epoll_events,
                  tcp_detail.socket_error);
    }
  } else {
    log_message(LOG_ERROR, "DNS do control plane falhou: 0x%08X",
                (unsigned int)result);
  }

  SceNetInAddr baseline_address;
  result = sceNetInetPton(SCE_NET_AF_INET, BASELINE_TCP_IP, &baseline_address);
  if (result == 1) {
    TcpProbeDetail baseline_detail;
    result = test_tcp_connect(&baseline_address, &baseline_detail);
    if (result >= 0) {
      log_message(LOG_OK,
                  "TCP baseline %s:443 conectado (errno=%d eventos=0x%X)",
                  BASELINE_TCP_IP, baseline_detail.connect_errno,
                  baseline_detail.epoll_events);
    } else {
      log_message(LOG_ERROR,
                  "TCP baseline: etapa=%s res=0x%08X errno=%d wait=%d "
                  "eventos=0x%X soerr=%d",
                  baseline_detail.stage,
                  (unsigned int)baseline_detail.final_result,
                  baseline_detail.connect_errno, baseline_detail.epoll_result,
                  baseline_detail.epoll_events, baseline_detail.socket_error);
    }
  } else {
    log_message(LOG_ERROR, "TCP baseline: conversao do IP falhou (%d)", result);
  }

  char stun_endpoint[64];
  CaptureProbeDetail capture_detail;
  test_packet_capture(stun_endpoint, sizeof(stun_endpoint), &capture_detail);
  if (capture_detail.traffic_result >= 0) {
    log_message(LOG_OK, "UDP respondeu pelo servidor STUN %s", stun_endpoint);
  } else {
    log_message(LOG_WARN, "UDP/STUN falhou: 0x%08X",
                (unsigned int)capture_detail.traffic_result);
  }

  if (capture_detail.create_result < 0) {
    log_message(LOG_WARN, "sceNetDumpCreate falhou: 0x%08X",
                (unsigned int)capture_detail.create_result);
  } else if (capture_detail.read_result > 0) {
    log_message(LOG_OK, "sceNetDumpRead capturou %d bytes (flags=0x%X)",
                capture_detail.read_result, capture_detail.flags);
  } else {
    log_message(LOG_WARN,
                "sceNetDumpRead sem pacote: res=0x%08X errno=%d flags=0x%X",
                (unsigned int)capture_detail.read_result,
                capture_detail.read_errno, capture_detail.flags);
  }

  SceNetCtlNatInfo nat_info;
  memset(&nat_info, 0, sizeof(nat_info));
  nat_info.size = sizeof(nat_info);
  result = sceNetCtlGetNatInfo(&nat_info);
  if (result >= 0) {
    char mapped_ip[32];
    const char *converted = sceNetInetNtop(SCE_NET_AF_INET,
                                           &nat_info.mapped_addr, mapped_ip,
                                           sizeof(mapped_ip));
    log_message(LOG_INFO, "NAT: status=%d tipo=%d IP=%s", nat_info.stun_status,
                nat_info.nat_type, converted != NULL ? mapped_ip : "?");
  } else {
    log_message(LOG_WARN, "Informacao NAT indisponivel: 0x%08X",
                (unsigned int)result);
  }

  int raw_socket = sceNetSocket("tsvita_raw", SCE_NET_AF_INET,
                                SCE_NET_SOCK_RAW, SCE_NET_IPPROTO_ICMP);
  if (raw_socket >= 0) {
    log_message(LOG_OK, "Socket raw ICMP disponivel (fd=%d)", raw_socket);
    sceNetSocketClose(raw_socket);
  } else {
    log_message(LOG_WARN, "Socket raw ICMP negado: 0x%08X",
                (unsigned int)raw_socket);
  }

  log_message(LOG_OK, "Diagnostico concluido; envie o arquivo probe.log");
  close_log();
}

int main(void) {
  sceCtrlSetSamplingMode(SCE_CTRL_MODE_ANALOG);

  int result = vita2d_init();
  if (result < 0) {
    return result;
  }
  vita2d_set_clear_color(RGBA8(11, 18, 27, 255));
  vita2d_set_vblank_wait(1);

  result = sceSysmoduleLoadModule(SCE_SYSMODULE_PGF);
  if (result < 0) {
    vita2d_fini();
    return result;
  }
  g_font = vita2d_load_default_pgf();
  if (g_font == NULL) {
    sceSysmoduleUnloadModule(SCE_SYSMODULE_PGF);
    vita2d_fini();
    return -1;
  }
  g_ui_ready = true;

  run_probe();

  SceCtrlData controls;
  unsigned int previous_buttons = 0;
  bool running = true;
  while (running) {
    memset(&controls, 0, sizeof(controls));
    sceCtrlPeekBufferPositive(0, &controls, 1);
    unsigned int pressed = controls.buttons & ~previous_buttons;
    if ((pressed & SCE_CTRL_START) != 0) {
      running = false;
    } else if ((pressed & SCE_CTRL_CROSS) != 0) {
      run_probe();
    }
    previous_buttons = controls.buttons;
    render();
    sceKernelDelayThread(16000);
  }

  close_log();
  cleanup_network();
  g_ui_ready = false;
  vita2d_free_pgf(g_font);
  g_font = NULL;
  sceSysmoduleUnloadModule(SCE_SYSMODULE_PGF);
  vita2d_fini();
  sceKernelExitProcess(0);
  return 0;
}
