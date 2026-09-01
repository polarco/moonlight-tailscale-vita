#ifndef TSVITA_TUNNEL_RUNTIME_H
#define TSVITA_TUNNEL_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#define TSVITA_KEEPALIVE_INTERVAL_US UINT64_C(25000000)
#define TSVITA_REKEY_INTERVAL_US UINT64_C(100000000)
#define TSVITA_HANDSHAKE_TIMEOUT_US UINT64_C(5000000)
#define TSVITA_HANDSHAKE_RETRY_US UINT64_C(1000000)
#define TSVITA_SESSION_SUMMARY_MAX 240U

typedef enum TsvitaSchedulerAction {
  TSVITA_SCHEDULER_ACTION_NONE = 0,
  TSVITA_SCHEDULER_ACTION_KEEPALIVE = 1 << 0,
  TSVITA_SCHEDULER_ACTION_HANDSHAKE = 1 << 1
} TsvitaSchedulerAction;

typedef struct TsvitaScheduler {
  uint64_t last_now_us;
  uint64_t last_tx_us;
  uint64_t accepted_handshake_us;
  uint64_t pending_since_us;
  uint64_t retry_since_us;
  bool handshake_accepted;
  bool handshake_pending;
  bool retry_pending;
} TsvitaScheduler;

void tsvita_scheduler_init(TsvitaScheduler *scheduler, uint64_t now_us);
void tsvita_scheduler_note_tx(TsvitaScheduler *scheduler, uint64_t now_us);
void tsvita_scheduler_note_handshake_requested(TsvitaScheduler *scheduler,
                                               uint64_t now_us);
void tsvita_scheduler_note_handshake_accepted(TsvitaScheduler *scheduler,
                                              uint64_t now_us);
void tsvita_scheduler_note_handshake_failure(TsvitaScheduler *scheduler,
                                             uint64_t now_us);
unsigned int tsvita_scheduler_tick(TsvitaScheduler *scheduler,
                                   uint64_t now_us, bool sending_valid);

typedef enum TsvitaTelemetryCounter {
  TSVITA_TELEMETRY_BYTES_TX = 0,
  TSVITA_TELEMETRY_BYTES_RX,
  TSVITA_TELEMETRY_PACKETS_TX,
  TSVITA_TELEMETRY_PACKETS_RX,
  TSVITA_TELEMETRY_HANDSHAKE_ATTEMPTS,
  TSVITA_TELEMETRY_HANDSHAKE_SUCCESSES,
  TSVITA_TELEMETRY_REKEY_ATTEMPTS,
  TSVITA_TELEMETRY_REKEY_SUCCESSES,
  TSVITA_TELEMETRY_KEEPALIVES,
  TSVITA_TELEMETRY_AEAD_FAILURES,
  TSVITA_TELEMETRY_REPLAY_REJECTIONS,
  TSVITA_TELEMETRY_OTHER_REJECTIONS,
  TSVITA_TELEMETRY_COUNTER_COUNT
} TsvitaTelemetryCounter;

typedef struct TsvitaTelemetry {
  uint64_t counters[TSVITA_TELEMETRY_COUNTER_COUNT];
  uint64_t session_started_us;
  uint64_t session_ended_us;
  bool session_active;
} TsvitaTelemetry;

typedef struct TsvitaTelemetryStore {
  pthread_mutex_t mutex;
  TsvitaTelemetry value;
} TsvitaTelemetryStore;

int tsvita_telemetry_store_init(TsvitaTelemetryStore *store);
void tsvita_telemetry_store_destroy(TsvitaTelemetryStore *store);
void tsvita_telemetry_session_begin(TsvitaTelemetryStore *store,
                                    uint64_t now_us);
void tsvita_telemetry_session_end(TsvitaTelemetryStore *store,
                                  uint64_t now_us);
void tsvita_telemetry_add(TsvitaTelemetryStore *store,
                          TsvitaTelemetryCounter counter, uint64_t amount);
void tsvita_telemetry_snapshot(TsvitaTelemetryStore *store,
                               TsvitaTelemetry *snapshot);
size_t tsvita_telemetry_format_summary(const TsvitaTelemetry *snapshot,
                                       char *output, size_t output_size);

#endif
