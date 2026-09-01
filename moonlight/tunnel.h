#ifndef TSVITA_MOONLIGHT_TUNNEL_H
#define TSVITA_MOONLIGHT_TUNNEL_H

#include <stdbool.h>

int tsvita_tunnel_ensure_started(void);
bool tsvita_tunnel_is_online(void);
const char *tsvita_tunnel_last_error(void);
void tsvita_trace(const char *component, const char *format, ...);
void tsvita_session_begin(void);
void tsvita_session_end(void);

#endif
