#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tunnel_runtime.h"

static int require(int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FALHOU runtime: %s\n", message);
    return 1;
  }
  return 0;
}

typedef struct WriterContext {
  TsvitaTelemetryStore *store;
  unsigned int iterations;
} WriterContext;

static void *counter_writer(void *argument) {
  WriterContext *context = argument;
  for (unsigned int index = 0U; index < context->iterations; ++index)
    tsvita_telemetry_add(context->store, TSVITA_TELEMETRY_PACKETS_TX, 1U);
  return NULL;
}

int main(void) {
  TsvitaScheduler scheduler;
  tsvita_scheduler_init(&scheduler, 0U);
  if (require(tsvita_scheduler_tick(&scheduler, 24999999U, true) == 0U,
              "keepalive precoce") ||
      require((tsvita_scheduler_tick(&scheduler, 25000000U, true) &
               TSVITA_SCHEDULER_ACTION_KEEPALIVE) != 0U,
              "keepalive em 25s"))
    return 1;

  tsvita_scheduler_note_handshake_requested(&scheduler, 30000000U);
  tsvita_scheduler_note_handshake_accepted(&scheduler, 31000000U);
  if (require((tsvita_scheduler_tick(&scheduler, 130999999U, false) &
               TSVITA_SCHEDULER_ACTION_HANDSHAKE) == 0U,
              "rekey precoce") ||
      require((tsvita_scheduler_tick(&scheduler, 131000000U, false) &
               TSVITA_SCHEDULER_ACTION_HANDSHAKE) != 0U,
              "rekey em 100s"))
    return 1;

  if (require(tsvita_scheduler_tick(&scheduler, 136000000U, false) == 0U,
              "timeout pendente nao tenta imediatamente") ||
      require((tsvita_scheduler_tick(&scheduler, 137000000U, false) &
               TSVITA_SCHEDULER_ACTION_HANDSHAKE) != 0U,
              "retry 1s apos timeout"))
    return 1;
  tsvita_scheduler_note_handshake_failure(&scheduler, 137000000U);
  if (require((tsvita_scheduler_tick(&scheduler, 138000000U, false) &
               TSVITA_SCHEDULER_ACTION_HANDSHAKE) != 0U,
              "retry 1s apos falha"))
    return 1;

  tsvita_scheduler_note_handshake_accepted(&scheduler, 200000000U);
  unsigned int rollback = tsvita_scheduler_tick(&scheduler, 1000U, true);
  if (require(rollback == 0U, "relogio regressivo sem tempestade") ||
      require(tsvita_scheduler_tick(&scheduler, 25001000U, true) ==
                  TSVITA_SCHEDULER_ACTION_KEEPALIVE,
              "prazo recalculado apos regressao"))
    return 1;

  tsvita_scheduler_note_handshake_accepted(&scheduler, UINT64_MAX - 100U);
  if (require(tsvita_scheduler_tick(&scheduler, 50U, false) == 0U,
              "rollover tratado como regressao"))
    return 1;

  TsvitaScheduler two_rekeys;
  tsvita_scheduler_init(&two_rekeys, 0U);
  tsvita_scheduler_note_handshake_requested(&two_rekeys, 0U);
  tsvita_scheduler_note_handshake_accepted(&two_rekeys, 0U);
  if (require((tsvita_scheduler_tick(&two_rekeys, 100000000U, false) &
               TSVITA_SCHEDULER_ACTION_HANDSHAKE) != 0U,
              "primeiro rekey em 100s")) return 1;
  tsvita_scheduler_note_handshake_accepted(&two_rekeys, 100000000U);
  if (require((tsvita_scheduler_tick(&two_rekeys, 200000000U, false) &
               TSVITA_SCHEDULER_ACTION_HANDSHAKE) != 0U,
              "segundo rekey em 200s")) return 1;

  TsvitaTelemetryStore store;
  if (tsvita_telemetry_store_init(&store) != 0) return 1;
  tsvita_telemetry_session_begin(&store, 1000000U);
  tsvita_telemetry_add(&store, TSVITA_TELEMETRY_BYTES_TX, UINT64_MAX);
  tsvita_telemetry_add(&store, TSVITA_TELEMETRY_BYTES_TX, 1U);
  WriterContext writer = {&store, 10000U};
  pthread_t threads[4];
  for (size_t index = 0U; index < 4U; ++index)
    if (pthread_create(&threads[index], NULL, counter_writer, &writer) != 0)
      return 1;
  TsvitaTelemetry concurrent_snapshot;
  for (unsigned int index = 0U; index < 100U; ++index)
    tsvita_telemetry_snapshot(&store, &concurrent_snapshot);
  for (size_t index = 0U; index < 4U; ++index) pthread_join(threads[index], NULL);
  tsvita_telemetry_session_end(&store, 201000000U);
  TsvitaTelemetry snapshot;
  tsvita_telemetry_snapshot(&store, &snapshot);
  if (require(snapshot.counters[TSVITA_TELEMETRY_BYTES_TX] == UINT64_MAX,
              "contador saturado") ||
      require(snapshot.counters[TSVITA_TELEMETRY_PACKETS_TX] == 40000U,
              "snapshot concorrente"))
    return 1;
  char summary[TSVITA_SESSION_SUMMARY_MAX + 1U];
  size_t length = tsvita_telemetry_format_summary(&snapshot, summary,
                                                  sizeof(summary));
  static const char *forbidden[] = {
      "private", "peer_public_key", "endpoint", "certificate", "payload",
      "192.", "10.77.", "BEGIN "};
  if (require(length <= TSVITA_SESSION_SUMMARY_MAX,
              "resumo limitado a 240") ||
      require(strstr(summary, "dur=200s") != NULL, "duracao 200s"))
    return 1;
  for (size_t index = 0U; index < sizeof(forbidden) / sizeof(forbidden[0]); ++index)
    if (require(strstr(summary, forbidden[index]) == NULL,
                "resumo sem segredos"))
      return 1;
  tsvita_telemetry_store_destroy(&store);
  puts("OK: scheduler monotonicamente seguro e telemetria saturada");
  return 0;
}
