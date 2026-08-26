#include <psp2/ctrl.h>
#include <psp2/io/fcntl.h>
#include <psp2/io/stat.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/sysmem.h>
#include <vita2d.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "wireguard.h"

#define LOG_DIRECTORY "ux0:data/TailscaleVita"
#define LOG_PATH LOG_DIRECTORY "/wg-crypto.log"
#define MAX_LINES 20
#define LINE_LENGTH 180

typedef struct ProbeLine {
  bool ok;
  char text[LINE_LENGTH];
} ProbeLine;

static ProbeLine g_lines[MAX_LINES];
static int g_line_count;
static SceUID g_log_fd = -1;
static vita2d_pgf *g_font;

extern int tsvita_wireguard_random_error(void);

static void render(void) {
  vita2d_start_drawing();
  vita2d_clear_screen();
  vita2d_draw_rectangle(0.0f, 0.0f, 960.0f, 58.0f,
                        RGBA8(24, 76, 116, 255));
  vita2d_pgf_draw_text(g_font, 24, 36, RGBA8(255, 255, 255, 255), 1.05f,
                       "Tailscale Vita - WireGuard Crypto Probe 0.1.0");

  int y = 84;
  for (int index = 0; index < g_line_count; ++index) {
    unsigned int color = g_lines[index].ok ? RGBA8(98, 211, 131, 255)
                                            : RGBA8(255, 107, 107, 255);
    vita2d_pgf_draw_text(g_font, 24, y, color, 0.72f, g_lines[index].text);
    y += 25;
  }

  vita2d_draw_rectangle(0.0f, 510.0f, 960.0f, 34.0f,
                        RGBA8(18, 27, 38, 255));
  vita2d_pgf_draw_text(g_font, 24, 533, RGBA8(198, 207, 219, 255), 0.72f,
                       "X: repetir     START: sair     Log: ux0:data/TailscaleVita/wg-crypto.log");
  vita2d_end_drawing();
  vita2d_swap_buffers();
  vita2d_pool_reset();
}

static void log_line(bool ok, const char *format, ...) {
  if (g_line_count >= MAX_LINES) {
    return;
  }

  va_list arguments;
  va_start(arguments, format);
  vsnprintf(g_lines[g_line_count].text, LINE_LENGTH, format, arguments);
  va_end(arguments);
  g_lines[g_line_count].ok = ok;

  if (g_log_fd >= 0) {
    char persisted[LINE_LENGTH + 16];
    int length = snprintf(persisted, sizeof(persisted), "[%s] %s\n",
                          ok ? "OK" : "ERROR",
                          g_lines[g_line_count].text);
    if (length > 0) {
      unsigned int write_length = (unsigned int)length;
      if (write_length >= sizeof(persisted)) {
        write_length = sizeof(persisted) - 1;
      }
      sceIoWrite(g_log_fd, persisted, write_length);
    }
  }

  ++g_line_count;
  render();
}

static int hex_nibble(char value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }
  return -1;
}

static bool decode_hex(const char *input, uint8_t *output, size_t output_size) {
  if (strlen(input) != output_size * 2) {
    return false;
  }
  for (size_t index = 0; index < output_size; ++index) {
    int high = hex_nibble(input[index * 2]);
    int low = hex_nibble(input[index * 2 + 1]);
    if (high < 0 || low < 0) {
      return false;
    }
    output[index] = (uint8_t)((high << 4) | low);
  }
  return true;
}

static void run_probe(void) {
  memset(g_lines, 0, sizeof(g_lines));
  g_line_count = 0;
  if (g_log_fd >= 0) {
    sceIoClose(g_log_fd);
  }
  sceIoMkdir(LOG_DIRECTORY, 0777);
  g_log_fd = sceIoOpen(LOG_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC,
                       0666);

  log_line(true, "Inicio do diagnostico criptografico WireGuard");

  SceKernelFreeMemorySizeInfo before;
  memset(&before, 0, sizeof(before));
  before.size = sizeof(before);
  int memory_result = sceKernelGetFreeMemorySize(&before);

  static const uint8_t empty[1] = {0};
  static const char *blake_expected_hex =
      "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";
  uint8_t blake_expected[32];
  uint8_t blake_output[32];
  bool blake_vector_ok = decode_hex(blake_expected_hex, blake_expected,
                                    sizeof(blake_expected));
  wireguard_blake2s(blake_output, sizeof(blake_output), NULL, 0, empty, 0);
  blake_vector_ok = blake_vector_ok &&
                    memcmp(blake_output, blake_expected,
                           sizeof(blake_output)) == 0;
  log_line(blake_vector_ok, "BLAKE2s vetor vazio: %s",
           blake_vector_ok ? "OK" : "FALHOU");

  static const char *alice_private_hex =
      "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
  static const char *alice_public_hex =
      "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
  static const char *bob_public_hex =
      "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
  uint8_t alice_private[32];
  uint8_t alice_public[32];
  uint8_t bob_public[32];
  uint8_t calculated_public[32];
  bool keys_ok = decode_hex(alice_private_hex, alice_private,
                            sizeof(alice_private)) &&
                 decode_hex(alice_public_hex, alice_public,
                            sizeof(alice_public)) &&
                 decode_hex(bob_public_hex, bob_public, sizeof(bob_public));

  uint64_t x25519_started = sceKernelGetProcessTimeWide();
  int x25519_result = wireguard_x25519(calculated_public, alice_private,
                                       X25519_BASE_POINT);
  uint64_t x25519_elapsed = sceKernelGetProcessTimeWide() - x25519_started;
  bool x25519_ok = keys_ok && x25519_result == 0 &&
                   memcmp(calculated_public, alice_public,
                          sizeof(calculated_public)) == 0;
  log_line(x25519_ok, "X25519 RFC 7748: %s (%llu us)",
           x25519_ok ? "OK" : "FALHOU",
           (unsigned long long)x25519_elapsed);

  uint8_t aead_key[32];
  uint8_t plaintext[128];
  uint8_t encrypted[sizeof(plaintext) + WIREGUARD_AUTHTAG_LEN];
  uint8_t decrypted[sizeof(plaintext)];
  for (size_t index = 0; index < sizeof(aead_key); ++index) {
    aead_key[index] = (uint8_t)index;
  }
  for (size_t index = 0; index < sizeof(plaintext); ++index) {
    plaintext[index] = (uint8_t)(index ^ 0xA5U);
  }
  memset(encrypted, 0, sizeof(encrypted));
  memset(decrypted, 0, sizeof(decrypted));
  uint64_t aead_started = sceKernelGetProcessTimeWide();
  wireguard_aead_encrypt(encrypted, plaintext, sizeof(plaintext), NULL, 0, 7,
                         aead_key);
  bool aead_ok = wireguard_aead_decrypt(
      decrypted, encrypted, sizeof(encrypted), NULL, 0, 7, aead_key);
  uint64_t aead_elapsed = sceKernelGetProcessTimeWide() - aead_started;
  aead_ok = aead_ok && memcmp(decrypted, plaintext, sizeof(plaintext)) == 0;
  log_line(aead_ok, "ChaCha20-Poly1305 roundtrip 128 B: %s (%llu us)",
           aead_ok ? "OK" : "FALHOU", (unsigned long long)aead_elapsed);

  wireguard_init();
  struct wireguard_device device;
  memset(&device, 0, sizeof(device));
  struct wireguard_peer *peer = NULL;
  struct message_handshake_initiation initiation;
  memset(&initiation, 0, sizeof(initiation));

  uint64_t handshake_started = sceKernelGetProcessTimeWide();
  bool device_ok = keys_ok && wireguard_device_init(&device, alice_private);
  if (device_ok) {
    peer = peer_alloc(&device);
  }
  bool peer_ok = peer != NULL &&
                 wireguard_peer_init(&device, peer, bob_public, NULL);
  bool handshake_ok = peer_ok && wireguard_create_handshake_initiation(
                                    &device, peer, &initiation);
  uint64_t handshake_elapsed =
      sceKernelGetProcessTimeWide() - handshake_started;
  handshake_ok = handshake_ok && initiation.type == MESSAGE_HANDSHAKE_INITIATION;
  log_line(handshake_ok,
           "Noise IK iniciacao %u B: %s (%llu us)",
           (unsigned int)sizeof(initiation),
           handshake_ok ? "OK" : "FALHOU",
           (unsigned long long)handshake_elapsed);

  int random_error = tsvita_wireguard_random_error();
  log_line(random_error == 0, "RNG do kernel: %s (0x%08X)",
           random_error == 0 ? "OK" : "FALHOU",
           (unsigned int)random_error);

  SceKernelFreeMemorySizeInfo after;
  memset(&after, 0, sizeof(after));
  after.size = sizeof(after);
  if (memory_result >= 0 && sceKernelGetFreeMemorySize(&after) >= 0) {
    int delta_kib = (int)(before.size_user / 1024) -
                    (int)(after.size_user / 1024);
    log_line(true, "Memoria user: antes=%d MiB depois=%d MiB delta=%d KiB",
             before.size_user / (1024 * 1024),
             after.size_user / (1024 * 1024), delta_kib);
  }

  bool all_ok = blake_vector_ok && x25519_ok && aead_ok && handshake_ok &&
                random_error == 0;
  log_line(all_ok, "Resultado M1 crypto: %s",
           all_ok ? "APROVADO" : "REPROVADO");

  crypto_zero(alice_private, sizeof(alice_private));
  crypto_zero(aead_key, sizeof(aead_key));
  crypto_zero(&device, sizeof(device));
  if (g_log_fd >= 0) {
    sceIoClose(g_log_fd);
    g_log_fd = -1;
  }
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
  }

  if (g_log_fd >= 0) {
    sceIoClose(g_log_fd);
  }
  vita2d_free_pgf(g_font);
  vita2d_fini();
  sceKernelExitProcess(0);
  return 0;
}
