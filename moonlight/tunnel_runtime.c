#include "tunnel_runtime.h"

#include <stdio.h>
#include <string.h>

static void scheduler_rebase_on_regression(TsvitaScheduler *scheduler,
                                           uint64_t now_us) {
  if (now_us >= scheduler->last_now_us) return;
  scheduler->last_tx_us = now_us;
  if (scheduler->handshake_accepted) scheduler->accepted_handshake_us = now_us;
  if (scheduler->handshake_pending) scheduler->pending_since_us = now_us;
  if (scheduler->retry_pending) scheduler->retry_since_us = now_us;
}

static void scheduler_observe_now(TsvitaScheduler *scheduler,
                                  uint64_t now_us) {
  scheduler_rebase_on_regression(scheduler, now_us);
  scheduler->last_now_us = now_us;
}

void tsvita_scheduler_init(TsvitaScheduler *scheduler, uint64_t now_us) {
  memset(scheduler, 0, sizeof(*scheduler));
  scheduler->last_now_us = now_us;
  scheduler->last_tx_us = now_us;
}

void tsvita_scheduler_note_tx(TsvitaScheduler *scheduler, uint64_t now_us) {
  scheduler_observe_now(scheduler, now_us);
  scheduler->last_tx_us = now_us;
}

void tsvita_scheduler_note_handshake_requested(TsvitaScheduler *scheduler,
                                               uint64_t now_us) {
  scheduler_observe_now(scheduler, now_us);
  scheduler->handshake_pending = true;
  scheduler->pending_since_us = now_us;
  scheduler->retry_pending = false;
}

void tsvita_scheduler_note_handshake_accepted(TsvitaScheduler *scheduler,
                                              uint64_t now_us) {
  scheduler_observe_now(scheduler, now_us);
  scheduler->handshake_accepted = true;
  scheduler->accepted_handshake_us = now_us;
  scheduler->handshake_pending = false;
  scheduler->retry_pending = false;
}

void tsvita_scheduler_note_handshake_failure(TsvitaScheduler *scheduler,
                                             uint64_t now_us) {
  scheduler_observe_now(scheduler, now_us);
  scheduler->handshake_pending = false;
  scheduler->retry_pending = true;
  scheduler->retry_since_us = now_us;
}

unsigned int tsvita_scheduler_tick(TsvitaScheduler *scheduler,
                                   uint64_t now_us, bool sending_valid) {
  scheduler_observe_now(scheduler, now_us);
  unsigned int actions = TSVITA_SCHEDULER_ACTION_NONE;

  if (scheduler->handshake_pending &&
      now_us - scheduler->pending_since_us >= TSVITA_HANDSHAKE_TIMEOUT_US) {
    scheduler->handshake_pending = false;
    scheduler->retry_pending = true;
    scheduler->retry_since_us = now_us;
  }

  bool rekey_due = scheduler->handshake_accepted &&
                   !scheduler->retry_pending &&
                   now_us - scheduler->accepted_handshake_us >=
                       TSVITA_REKEY_INTERVAL_US;
  bool retry_due = scheduler->retry_pending &&
                   now_us - scheduler->retry_since_us >=
                       TSVITA_HANDSHAKE_RETRY_US;
  if (!scheduler->handshake_pending && (rekey_due || retry_due)) {
    actions |= TSVITA_SCHEDULER_ACTION_HANDSHAKE;
    scheduler->handshake_pending = true;
    scheduler->pending_since_us = now_us;
    scheduler->retry_pending = false;
  }

  if (sending_valid &&
      now_us - scheduler->last_tx_us >= TSVITA_KEEPALIVE_INTERVAL_US) {
    actions |= TSVITA_SCHEDULER_ACTION_KEEPALIVE;
    scheduler->last_tx_us = now_us;
  }
  return actions;
}

static uint64_t saturated_add(uint64_t value, uint64_t amount) {
  return UINT64_MAX - value < amount ? UINT64_MAX : value + amount;
}

int tsvita_telemetry_store_init(TsvitaTelemetryStore *store) {
  if (store == NULL) return -1;
  memset(store, 0, sizeof(*store));
  return pthread_mutex_init(&store->mutex, NULL);
}

void tsvita_telemetry_store_destroy(TsvitaTelemetryStore *store) {
  if (store != NULL) pthread_mutex_destroy(&store->mutex);
}

void tsvita_telemetry_session_begin(TsvitaTelemetryStore *store,
                                    uint64_t now_us) {
  if (store == NULL) return;
  pthread_mutex_lock(&store->mutex);
  memset(&store->value, 0, sizeof(store->value));
  store->value.session_started_us = now_us;
  store->value.session_active = true;
  pthread_mutex_unlock(&store->mutex);
}

void tsvita_telemetry_session_end(TsvitaTelemetryStore *store,
                                  uint64_t now_us) {
  if (store == NULL) return;
  pthread_mutex_lock(&store->mutex);
  store->value.session_ended_us = now_us;
  store->value.session_active = false;
  pthread_mutex_unlock(&store->mutex);
}

void tsvita_telemetry_add(TsvitaTelemetryStore *store,
                          TsvitaTelemetryCounter counter, uint64_t amount) {
  if (store == NULL || counter >= TSVITA_TELEMETRY_COUNTER_COUNT)
    return;
  pthread_mutex_lock(&store->mutex);
  store->value.counters[counter] =
      saturated_add(store->value.counters[counter], amount);
  pthread_mutex_unlock(&store->mutex);
}

void tsvita_telemetry_snapshot(TsvitaTelemetryStore *store,
                               TsvitaTelemetry *snapshot) {
  if (store == NULL || snapshot == NULL) return;
  pthread_mutex_lock(&store->mutex);
  *snapshot = store->value;
  pthread_mutex_unlock(&store->mutex);
}

size_t tsvita_telemetry_format_summary(const TsvitaTelemetry *snapshot,
                                       char *output, size_t output_size) {
  if (snapshot == NULL || output == NULL || output_size == 0U) return 0U;
  uint64_t ended = snapshot->session_active ? snapshot->session_started_us
                                            : snapshot->session_ended_us;
  uint64_t duration = ended >= snapshot->session_started_us
                          ? (ended - snapshot->session_started_us) / 1000000U
                          : 0U;
  int length = snprintf(
      output, output_size,
      "session dur=%llus tx=%lluB/%llu rx=%lluB/%llu hs=%llu/%llu "
      "rk=%llu/%llu ka=%llu aead=%llu replay=%llu reject=%llu",
      (unsigned long long)duration,
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_BYTES_TX],
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_PACKETS_TX],
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_BYTES_RX],
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_PACKETS_RX],
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_HANDSHAKE_ATTEMPTS],
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_HANDSHAKE_SUCCESSES],
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_REKEY_ATTEMPTS],
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_REKEY_SUCCESSES],
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_KEEPALIVES],
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_AEAD_FAILURES],
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_REPLAY_REJECTIONS],
      (unsigned long long)snapshot->counters[TSVITA_TELEMETRY_OTHER_REJECTIONS]);
  if (length < 0) {
    output[0] = '\0';
    return 0U;
  }
  size_t written = (size_t)length;
  if (written >= output_size) written = output_size - 1U;
  if (written > TSVITA_SESSION_SUMMARY_MAX) {
    written = TSVITA_SESSION_SUMMARY_MAX;
    output[written] = '\0';
  }
  return written;
}
