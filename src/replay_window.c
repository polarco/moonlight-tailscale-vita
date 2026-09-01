#include "replay_window.h"

#include <stddef.h>
#include <string.h>

void tsvita_replay_init(TsvitaReplayWindow *window) {
  if (window != NULL) {
    memset(window, 0, sizeof(*window));
  }
}

bool tsvita_replay_check(TsvitaReplayWindow *window, uint64_t sequence) {
  if (window == NULL || sequence >= TSVITA_REJECT_AFTER_MESSAGES) {
    return false;
  }

  if (sequence < window->highest &&
      window->highest - sequence >= TSVITA_REPLAY_WINDOW_BITS) {
    return false;
  }

  uint64_t word_index = sequence / TSVITA_REPLAY_WORD_BITS;
  if (sequence > window->highest) {
    uint64_t current_word = window->highest / TSVITA_REPLAY_WORD_BITS;
    uint64_t words_to_clear = word_index - current_word;
    if (words_to_clear > TSVITA_REPLAY_WORDS) {
      words_to_clear = TSVITA_REPLAY_WORDS;
    }
    for (uint64_t offset = 1; offset <= words_to_clear; ++offset) {
      window->bitmap[(current_word + offset) % TSVITA_REPLAY_WORDS] = 0U;
    }
    window->highest = sequence;
  }

  uint32_t bit = UINT32_C(1) << (sequence % TSVITA_REPLAY_WORD_BITS);
  uint32_t *word = &window->bitmap[word_index % TSVITA_REPLAY_WORDS];
  if ((*word & bit) != 0U) {
    return false;
  }
  *word |= bit;
  return true;
}
