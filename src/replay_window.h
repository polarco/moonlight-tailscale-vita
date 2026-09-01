#ifndef TSVITA_REPLAY_WINDOW_H
#define TSVITA_REPLAY_WINDOW_H

#include <stdbool.h>
#include <stdint.h>

#define TSVITA_REPLAY_WINDOW_BITS 8192U
#define TSVITA_REPLAY_WORD_BITS 32U
#define TSVITA_REPLAY_WORDS \
  ((TSVITA_REPLAY_WINDOW_BITS / TSVITA_REPLAY_WORD_BITS) + 1U)
#define TSVITA_REJECT_AFTER_MESSAGES \
  (UINT64_MAX - (UINT64_C(1) << 13))

typedef struct TsvitaReplayWindow {
  uint32_t bitmap[TSVITA_REPLAY_WORDS];
  uint64_t highest;
} TsvitaReplayWindow;

void tsvita_replay_init(TsvitaReplayWindow *window);
bool tsvita_replay_check(TsvitaReplayWindow *window, uint64_t sequence);

#endif
