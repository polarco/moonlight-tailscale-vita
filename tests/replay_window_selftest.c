#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "replay_window.h"

typedef struct ReferenceWindow {
  bool seen[TSVITA_REPLAY_WINDOW_BITS];
  uint64_t highest;
  bool initialized;
} ReferenceWindow;

static bool reference_check(ReferenceWindow *window, uint64_t sequence) {
  if (sequence >= TSVITA_REJECT_AFTER_MESSAGES) return false;
  if (window->initialized && sequence < window->highest &&
      window->highest - sequence >= TSVITA_REPLAY_WINDOW_BITS)
    return false;
  if (!window->initialized || sequence > window->highest) {
    uint64_t advance = window->initialized ? sequence - window->highest
                                           : TSVITA_REPLAY_WINDOW_BITS;
    if (advance >= TSVITA_REPLAY_WINDOW_BITS) {
      memset(window->seen, 0, sizeof(window->seen));
    } else {
      memmove(window->seen, window->seen + advance,
              (TSVITA_REPLAY_WINDOW_BITS - advance) * sizeof(window->seen[0]));
      memset(window->seen + TSVITA_REPLAY_WINDOW_BITS - advance, 0,
             advance * sizeof(window->seen[0]));
    }
    window->highest = sequence;
    window->initialized = true;
  }
  size_t age = (size_t)(window->highest - sequence);
  size_t index = TSVITA_REPLAY_WINDOW_BITS - 1U - age;
  if (window->seen[index]) return false;
  window->seen[index] = true;
  return true;
}

static int check(TsvitaReplayWindow *actual, ReferenceWindow *reference,
                 uint64_t sequence, bool expected, const char *scenario) {
  bool actual_result = tsvita_replay_check(actual, sequence);
  bool reference_result = reference_check(reference, sequence);
  if (actual_result != expected || reference_result != expected) {
    fprintf(stderr,
            "FALHOU replay %s: seq=%llu actual=%d reference=%d expected=%d\n",
            scenario, (unsigned long long)sequence, actual_result,
            reference_result, expected);
    return 1;
  }
  return 0;
}

int main(void) {
  TsvitaReplayWindow actual;
  ReferenceWindow reference = {0};
  tsvita_replay_init(&actual);

  if (check(&actual, &reference, 0U, true, "primeiro-zero") ||
      check(&actual, &reference, 0U, false, "duplicata-zero") ||
      check(&actual, &reference, 9000U, true, "salto") ||
      check(&actual, &reference, 809U, true, "idade-8191") ||
      check(&actual, &reference, 808U, false, "idade-8192") ||
      check(&actual, &reference, 807U, false, "idade-8193") ||
      check(&actual, &reference, 8999U, true, "reordenado") ||
      check(&actual, &reference, 8999U, false, "duplicata-reordenada"))
    return 1;

  uint32_t random_state = UINT32_C(0x7a11c0de);
  for (uint64_t base = 10000U; base < 50000U; base += 97U) {
    for (unsigned int burst = 0U; burst < 64U; ++burst) {
      random_state = random_state * UINT32_C(1664525) + UINT32_C(1013904223);
      uint64_t loss_or_reorder = (random_state >> 24) % 113U;
      uint64_t sequence = base + burst;
      if ((random_state & 7U) == 0U && sequence > loss_or_reorder)
        sequence -= loss_or_reorder;
      bool expected = reference_check(&reference, sequence);
      bool got = tsvita_replay_check(&actual, sequence);
      if (got != expected) {
        fprintf(stderr, "FALHOU replay rajada: seq=%llu got=%d expected=%d\n",
                (unsigned long long)sequence, got, expected);
        return 1;
      }
    }
  }

  TsvitaReplayWindow limit;
  tsvita_replay_init(&limit);
  if (!tsvita_replay_check(&limit, TSVITA_REJECT_AFTER_MESSAGES - 1U) ||
      tsvita_replay_check(&limit, TSVITA_REJECT_AFTER_MESSAGES) ||
      tsvita_replay_check(&limit, UINT64_MAX)) {
    fputs("FALHOU replay limite REJECT_AFTER_MESSAGES\n", stderr);
    return 1;
  }

  puts("OK: janela antirreplay exata de 8192 posicoes");
  return 0;
}
