#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socket_shim_host_compat.h"
#include "tunnel.h"

int __wrap_socket(int, int, int);
int __wrap_connect(int, const struct sockaddr *, socklen_t);
int __wrap_bind(int, const struct sockaddr *, socklen_t);
int __wrap_listen(int, int);
int __wrap_accept(int, struct sockaddr *, socklen_t *);
ssize_t __wrap_send(int, const void *, size_t, int);
ssize_t __wrap_recv(int, void *, size_t, int);
ssize_t __wrap_sendto(int, const void *, size_t, int,
                      const struct sockaddr *, socklen_t);
ssize_t __wrap_recvfrom(int, void *, size_t, int, struct sockaddr *,
                        socklen_t *);
int __wrap_shutdown(int, int);
int __wrap_close(int);
ssize_t __wrap_read(int, void *, size_t);
ssize_t __wrap_write(int, const void *, size_t);
int __wrap_fcntl(int, int, ...);
int __wrap_setsockopt(int, int, int, const void *, socklen_t);
int __wrap_getsockopt(int, int, int, void *, socklen_t *);
int __wrap_getsockname(int, struct sockaddr *, socklen_t *);
int __wrap_getpeername(int, struct sockaddr *, socklen_t *);
int __wrap_poll(struct pollfd *, nfds_t, int);
int __wrap_select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int __wrap_getaddrinfo(const char *, const char *, const struct addrinfo *,
                       struct addrinfo **);
void __wrap_freeaddrinfo(struct addrinfo *);

static bool g_tunnel_ok = true;
static bool g_tunnel_online = true;
static uint64_t g_now_us;
static int g_lwip_socket_result = 128;
static int g_connect_result;
static int g_connect_errno;
static int g_socket_error;
static int g_virtual_flags;
static int g_lwip_poll_calls;
static int g_lwip_poll_ready_after;
static short g_lwip_poll_revents = POLLOUT;
static int g_real_poll_calls;
static int g_real_poll_ready_after;
static short g_real_poll_revents = POLLIN;
static int g_lwip_select_calls;
static int g_lwip_select_ready_after;
static int g_real_select_calls;
static int g_real_select_ready_after;
static int g_real_calls;
static int g_lwip_calls;
static int g_lwip_freed;
static int g_real_freed;
static bool g_lwip_fail;
static struct sockaddr_in g_resolved_address;
static struct addrinfo g_resolved_info;

static void reset_fakes(void) {
  g_tunnel_ok = true;
  g_tunnel_online = true;
  g_now_us = 0U;
  g_lwip_socket_result = 128;
  g_connect_result = 0;
  g_connect_errno = 0;
  g_socket_error = 0;
  g_virtual_flags = 0;
  g_lwip_poll_calls = 0;
  g_lwip_poll_ready_after = 1;
  g_lwip_poll_revents = POLLOUT;
  g_real_poll_calls = 0;
  g_real_poll_ready_after = 1;
  g_real_poll_revents = POLLIN;
  g_lwip_select_calls = 0;
  g_lwip_select_ready_after = 1;
  g_real_select_calls = 0;
  g_real_select_ready_after = 1;
  g_real_calls = 0;
  g_lwip_calls = 0;
  g_lwip_freed = 0;
  g_real_freed = 0;
  g_lwip_fail = false;
  memset(&g_resolved_address, 0, sizeof(g_resolved_address));
  memset(&g_resolved_info, 0, sizeof(g_resolved_info));
  g_resolved_info.ai_family = AF_INET;
  g_resolved_info.ai_addr = (struct sockaddr *)&g_resolved_address;
  g_resolved_info.ai_addrlen = sizeof(struct sockaddr_storage);
}

static int require(bool condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FALHOU socket shim: %s (errno=%d)\n", message, errno);
    return 1;
  }
  return 0;
}

int tsvita_tunnel_ensure_started(void) { return g_tunnel_ok ? 0 : -1; }
bool tsvita_tunnel_is_online(void) { return g_tunnel_online; }
const char *tsvita_tunnel_last_error(void) { return "host-test"; }
void tsvita_trace(const char *component, const char *format, ...) {
  (void)component;
  (void)format;
}
void tsvita_session_begin(void) {}
void tsvita_session_end(void) {}
uint64_t sceKernelGetProcessTimeWide(void) { return g_now_us; }
int sceKernelDelayThread(unsigned int microseconds) {
  g_now_us += microseconds;
  return 0;
}

int lwip_socket(int domain, int type, int protocol) {
  (void)domain; (void)type; (void)protocol; ++g_lwip_calls;
  if (g_lwip_fail) { errno = EMFILE; return -1; }
  return g_lwip_socket_result;
}
int lwip_connect(int fd, const struct sockaddr *address, socklen_t length) {
  (void)fd; (void)address; (void)length; ++g_lwip_calls;
  errno = g_connect_errno;
  return g_connect_result;
}
#define SIMPLE_LWIP_INT(name, args, ignored) \
  int name args { \
    ignored; ++g_lwip_calls; \
    if (g_lwip_fail) { errno = EIO; return -1; } \
    return 0; \
  }
SIMPLE_LWIP_INT(lwip_bind,
                (int fd, const struct sockaddr *address, socklen_t length),
                (void)fd; (void)address; (void)length)
SIMPLE_LWIP_INT(lwip_listen, (int fd, int backlog),
                (void)fd; (void)backlog)
SIMPLE_LWIP_INT(lwip_accept,
                (int fd, struct sockaddr *address, socklen_t *length),
                (void)fd; (void)address; (void)length)
SIMPLE_LWIP_INT(lwip_shutdown, (int fd, int how), (void)fd; (void)how)
SIMPLE_LWIP_INT(lwip_close, (int fd), (void)fd)
ssize_t lwip_send(int fd, const void *buffer, size_t length, int flags) {
  (void)fd; (void)buffer; (void)flags; ++g_lwip_calls;
  if (g_lwip_fail) { errno = EIO; return -1; }
  return (ssize_t)length;
}
ssize_t lwip_recv(int fd, void *buffer, size_t length, int flags) {
  (void)fd; (void)flags; ++g_lwip_calls;
  if (g_lwip_fail) { errno = EIO; return -1; }
  if (length > 0U) ((char *)buffer)[0] = 'R';
  return length > 0U ? 1 : 0;
}
ssize_t lwip_sendto(int fd, const void *buffer, size_t length, int flags,
                    const struct sockaddr *destination, socklen_t dest_length) {
  (void)fd; (void)buffer; (void)flags; (void)destination; (void)dest_length;
  ++g_lwip_calls; if (g_lwip_fail) { errno = EIO; return -1; }
  return (ssize_t)length;
}
ssize_t lwip_recvfrom(int fd, void *buffer, size_t length, int flags,
                      struct sockaddr *source, socklen_t *source_length) {
  (void)fd; (void)flags; (void)source; (void)source_length; ++g_lwip_calls;
  if (g_lwip_fail) { errno = EIO; return -1; }
  if (length > 0U) ((char *)buffer)[0] = 'U';
  return length > 0U ? 1 : 0;
}
ssize_t lwip_read(int fd, void *buffer, size_t length) {
  return lwip_recv(fd, buffer, length, 0);
}
ssize_t lwip_write(int fd, const void *buffer, size_t length) {
  return lwip_send(fd, buffer, length, 0);
}
int lwip_fcntl(int fd, int command, int value) {
  (void)fd; ++g_lwip_calls;
  if (g_lwip_fail) { errno = EIO; return -1; }
  if (command == F_GETFL) return g_virtual_flags;
  if (command == F_SETFL) { g_virtual_flags = value; return 0; }
  errno = EINVAL; return -1;
}
int lwip_ioctl(int fd, long command, void *value) {
  (void)fd; (void)command; (void)value; ++g_lwip_calls;
  if (g_lwip_fail) { errno = EIO; return -1; }
  return 0;
}
int lwip_setsockopt(int fd, int level, int option, const void *value,
                    socklen_t length) {
  (void)fd; (void)level; (void)option; (void)value; (void)length;
  ++g_lwip_calls; if (g_lwip_fail) { errno = EIO; return -1; }
  return 0;
}
int lwip_getsockopt(int fd, int level, int option, void *value,
                    socklen_t *length) {
  (void)fd; (void)level; (void)option; ++g_lwip_calls;
  if (g_lwip_fail) { errno = EIO; return -1; }
  if (value != NULL && length != NULL && *length >= sizeof(int)) {
    *(int *)value = g_socket_error;
    *length = sizeof(int);
  }
  return 0;
}
SIMPLE_LWIP_INT(lwip_getsockname,
                (int fd, struct sockaddr *address, socklen_t *length),
                (void)fd; (void)address; (void)length)
SIMPLE_LWIP_INT(lwip_getpeername,
                (int fd, struct sockaddr *address, socklen_t *length),
                (void)fd; (void)address; (void)length)

static int poll_fake(struct pollfd *descriptors, nfds_t count,
                     int *calls, int ready_after, short revents) {
  ++*calls;
  for (nfds_t index = 0; index < count; ++index) descriptors[index].revents = 0;
  if (ready_after < 0 || *calls < ready_after) return 0;
  int ready = 0;
  for (nfds_t index = 0; index < count; ++index) {
    if (descriptors[index].fd >= 0) {
      descriptors[index].revents = revents;
      ++ready;
    }
  }
  return ready;
}
int lwip_poll(struct pollfd *descriptors, nfds_t count, int timeout) {
  ++g_lwip_calls;
  if (g_lwip_fail) { errno = EIO; return -1; }
  int result = poll_fake(descriptors, count, &g_lwip_poll_calls,
                         g_lwip_poll_ready_after, g_lwip_poll_revents);
  if (result == 0 && timeout > 0) g_now_us += (uint64_t)timeout * 1000U;
  return result;
}

static int select_fake(fd_set *read_set, fd_set *write_set, fd_set *error_set,
                       int *calls, int ready_after, int descriptor) {
  ++*calls;
  bool read_wanted = read_set != NULL && FD_ISSET(descriptor, read_set);
  bool write_wanted = write_set != NULL && FD_ISSET(descriptor, write_set);
  bool error_wanted = error_set != NULL && FD_ISSET(descriptor, error_set);
  if (read_set != NULL) FD_ZERO(read_set);
  if (write_set != NULL) FD_ZERO(write_set);
  if (error_set != NULL) FD_ZERO(error_set);
  if (ready_after < 0 || *calls < ready_after) return 0;
  if (read_wanted) FD_SET(descriptor, read_set);
  if (write_wanted) FD_SET(descriptor, write_set);
  if (error_wanted) FD_SET(descriptor, error_set);
  return read_wanted || write_wanted || error_wanted ? 1 : 0;
}
int lwip_select(int maxfd, fd_set *read_set, fd_set *write_set,
                fd_set *error_set, struct timeval *timeout) {
  (void)maxfd; (void)timeout; ++g_lwip_calls;
  if (g_lwip_fail) { errno = EIO; return -1; }
  return select_fake(read_set, write_set, error_set, &g_lwip_select_calls,
                     g_lwip_select_ready_after, 128);
}
int lwip_getaddrinfo(const char *node, const char *service,
                     const struct addrinfo *hints, struct addrinfo **result) {
  (void)node; (void)service; (void)hints; ++g_lwip_calls;
  if (g_lwip_fail) return EAI_FAIL;
  *result = &g_resolved_info; return 0;
}
void lwip_freeaddrinfo(struct addrinfo *result) {
  (void)result; ++g_lwip_freed;
}

int __real_socket(int domain, int type, int protocol) {
  (void)domain; (void)type; (void)protocol; ++g_real_calls; return 7;
}
int __real_connect(int fd, const struct sockaddr *address, socklen_t length) {
  (void)fd; (void)address; (void)length; ++g_real_calls; errno = ECONNREFUSED;
  return -1;
}
#define SIMPLE_REAL_INT(name, args, ignored) \
  int name args { ignored; ++g_real_calls; return 0; }
SIMPLE_REAL_INT(__real_bind,
                (int fd, const struct sockaddr *address, socklen_t length),
                (void)fd; (void)address; (void)length)
SIMPLE_REAL_INT(__real_listen, (int fd, int backlog),
                (void)fd; (void)backlog)
SIMPLE_REAL_INT(__real_accept,
                (int fd, struct sockaddr *address, socklen_t *length),
                (void)fd; (void)address; (void)length)
SIMPLE_REAL_INT(__real_shutdown, (int fd, int how), (void)fd; (void)how)
SIMPLE_REAL_INT(__real_close, (int fd), (void)fd)
ssize_t __real_send(int fd, const void *buffer, size_t length, int flags) {
  (void)fd; (void)buffer; (void)flags; ++g_real_calls; return (ssize_t)length;
}
ssize_t __real_recv(int fd, void *buffer, size_t length, int flags) {
  (void)fd; (void)buffer; (void)length; (void)flags; ++g_real_calls; return -1;
}
ssize_t __real_sendto(int fd, const void *buffer, size_t length, int flags,
                      const struct sockaddr *destination, socklen_t dest_length) {
  (void)fd; (void)buffer; (void)flags; (void)destination; (void)dest_length;
  ++g_real_calls; return (ssize_t)length;
}
ssize_t __real_recvfrom(int fd, void *buffer, size_t length, int flags,
                        struct sockaddr *source, socklen_t *source_length) {
  (void)fd; (void)buffer; (void)length; (void)flags; (void)source;
  (void)source_length; ++g_real_calls; return -1;
}
ssize_t __real_read(int fd, void *buffer, size_t length) {
  return __real_recv(fd, buffer, length, 0);
}
ssize_t __real_write(int fd, const void *buffer, size_t length) {
  return __real_send(fd, buffer, length, 0);
}
int __real_fcntl(int fd, int command, ...) {
  (void)fd; (void)command; ++g_real_calls; return 0;
}
SIMPLE_REAL_INT(__real_setsockopt,
                (int fd, int level, int option, const void *value,
                 socklen_t length),
                (void)fd; (void)level; (void)option; (void)value; (void)length)
int __real_getsockopt(int fd, int level, int option, void *value,
                      socklen_t *length) {
  (void)fd; (void)level; (void)option; ++g_real_calls;
  if (value != NULL && length != NULL && *length >= sizeof(int)) *(int *)value = 0;
  return 0;
}
SIMPLE_REAL_INT(__real_getsockname,
                (int fd, struct sockaddr *address, socklen_t *length),
                (void)fd; (void)address; (void)length)
SIMPLE_REAL_INT(__real_getpeername,
                (int fd, struct sockaddr *address, socklen_t *length),
                (void)fd; (void)address; (void)length)
int __real_poll(struct pollfd *descriptors, nfds_t count, int timeout) {
  (void)timeout; ++g_real_calls;
  return poll_fake(descriptors, count, &g_real_poll_calls,
                   g_real_poll_ready_after, g_real_poll_revents);
}
int __real_select(int maxfd, fd_set *read_set, fd_set *write_set,
                  fd_set *error_set, struct timeval *timeout) {
  (void)maxfd; (void)timeout; ++g_real_calls;
  return select_fake(read_set, write_set, error_set, &g_real_select_calls,
                     g_real_select_ready_after, 7);
}
int __real_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints, struct addrinfo **result) {
  (void)node; (void)service; (void)hints; ++g_real_calls;
  *result = &g_resolved_info; return 0;
}
void __real_freeaddrinfo(struct addrinfo *result) {
  (void)result; ++g_real_freed;
}

int main(void) {
  reset_fakes();
  struct sockaddr_in address = {.sin_family = AF_INET};
  char buffer[8] = {0};
  socklen_t address_length = sizeof(address);
  if (require(__wrap_socket(AF_INET, SOCK_STREAM, 0) == 128,
              "socket virtual") ||
      require(__wrap_socket(AF_UNIX, SOCK_STREAM, 0) == 7,
              "socket nativo") ||
      require(__wrap_connect(128, (struct sockaddr *)&address,
                             sizeof(address)) == 0,
              "connect imediato")) return 1;

  g_virtual_flags = O_NONBLOCK;
  g_connect_result = -1;
  g_connect_errno = EINPROGRESS;
  g_lwip_poll_ready_after = 1;
  if (require(__wrap_connect(128, (struct sockaddr *)&address,
                             sizeof(address)) == 0,
              "connect assincrono") ||
      require((g_virtual_flags & O_NONBLOCK) != 0,
              "restaura nonblocking")) return 1;
  g_socket_error = ECONNREFUSED;
  g_lwip_poll_calls = 0;
  g_lwip_poll_ready_after = 1;
  errno = 0;
  if (require(__wrap_connect(128, (struct sockaddr *)&address,
                             sizeof(address)) == -1 && errno == ECONNREFUSED,
              "connect erro SO_ERROR")) return 1;
  g_socket_error = 0;
  g_lwip_poll_calls = 0;
  g_lwip_poll_ready_after = -1;
  errno = 0;
  if (require(__wrap_connect(128, (struct sockaddr *)&address,
                             sizeof(address)) == -1 && errno == ETIMEDOUT &&
                  g_now_us >= 5000000U,
              "connect timeout com relogio falso")) return 1;
  g_connect_result = 0;
  g_connect_errno = 0;

  if (require(__wrap_bind(128, (struct sockaddr *)&address, sizeof(address)) == 0,
              "bind virtual") ||
      require(__wrap_listen(128, 1) == 0, "listen virtual") ||
      require(__wrap_accept(128, (struct sockaddr *)&address, &address_length) == 0,
              "accept virtual") ||
      require(__wrap_send(128, "x", 1U, 0) == 1, "send virtual") ||
      require(__wrap_recv(128, buffer, sizeof(buffer), 0) == 1, "recv virtual") ||
      require(__wrap_sendto(128, "x", 1U, 0, (struct sockaddr *)&address,
                            sizeof(address)) == 1,
              "sendto virtual") ||
      require(__wrap_recvfrom(128, buffer, sizeof(buffer), 0,
                              (struct sockaddr *)&address, &address_length) == 1,
              "recvfrom virtual") ||
      require(__wrap_read(128, buffer, sizeof(buffer)) == 1, "read virtual") ||
      require(__wrap_write(128, "x", 1U) == 1, "write virtual") ||
      require(__wrap_shutdown(128, SHUT_RDWR) == 0, "shutdown virtual")) return 1;

  if (require(__wrap_fcntl(128, F_SETFD, FD_CLOEXEC) == 0 &&
                  __wrap_fcntl(128, F_GETFD) == FD_CLOEXEC,
              "fcntl CLOEXEC") ||
      require(__wrap_fcntl(128, F_SETFD, FD_CLOEXEC | 8) == -1 && errno == EINVAL,
              "fcntl rejeita flag") ||
      require(__wrap_fcntl(128, F_SETFL, O_NONBLOCK) == 0,
              "fcntl nonblocking")) return 1;

  int enabled = 1;
  int option_value = -1;
  socklen_t option_length = sizeof(option_value);
  if (require(__wrap_setsockopt(128, SOL_SOCKET, SO_NONBLOCK, &enabled,
                               sizeof(enabled)) == 0,
              "SO_NONBLOCK ioctl") ||
      require(__wrap_getsockopt(128, SOL_SOCKET, SO_ERROR, &option_value,
                               &option_length) == 0,
              "getsockopt virtual") ||
      require(__wrap_getsockname(128, (struct sockaddr *)&address,
                                 &address_length) == 0,
              "getsockname virtual") ||
      require(__wrap_getpeername(128, (struct sockaddr *)&address,
                                 &address_length) == 0,
              "getpeername virtual")) return 1;

  g_lwip_socket_result = 129;
  if (require(__wrap_socket(AF_INET, SOCK_DGRAM, 0) == 129, "socket UDP") ||
      require(__wrap_setsockopt(129, SOL_SOCKET, SO_RCVTIMEO, &enabled,
                               sizeof(enabled)) == -1 && errno == ENOPROTOOPT,
              "UDP SO_RCVTIMEO fallback")) return 1;

  struct pollfd virtual_poll = {.fd = 128, .events = POLLIN};
  g_lwip_poll_calls = 0;
  g_lwip_poll_ready_after = 3;
  g_lwip_poll_revents = POLLIN | POLLHUP;
  if (require(__wrap_poll(&virtual_poll, 1U, 10) == 1 &&
                  (virtual_poll.revents & POLLHUP) != 0,
              "EOF tardio em poll")) return 1;
  struct pollfd mixed[2] = {{.fd = 128, .events = POLLIN},
                            {.fd = 7, .events = POLLIN}};
  g_lwip_poll_calls = 0; g_real_poll_calls = 0;
  g_lwip_poll_ready_after = -1; g_real_poll_ready_after = 2;
  if (require(__wrap_poll(mixed, 2U, 10) == 1 && mixed[1].revents != 0,
              "poll misto")) return 1;

  fd_set read_set;
  FD_ZERO(&read_set); FD_SET(128, &read_set);
  struct timeval timeout = {.tv_sec = 0, .tv_usec = 10000};
  g_lwip_select_calls = 0; g_lwip_select_ready_after = 2;
  if (require(__wrap_select(129, &read_set, NULL, NULL, &timeout) == 1 &&
                  FD_ISSET(128, &read_set),
              "select virtual")) return 1;
  FD_ZERO(&read_set); FD_SET(128, &read_set); FD_SET(7, &read_set);
  g_lwip_select_calls = 0; g_real_select_calls = 0;
  g_lwip_select_ready_after = -1; g_real_select_ready_after = 2;
  if (require(__wrap_select(129, &read_set, NULL, NULL, &timeout) == 1 &&
                  FD_ISSET(7, &read_set),
              "select misto")) return 1;

  struct addrinfo *resolved = NULL;
  if (require(__wrap_getaddrinfo("example.invalid", "80", NULL, &resolved) == 0 &&
                  resolved->ai_addrlen == sizeof(struct sockaddr_in),
              "resolucao lwIP normaliza tamanho")) return 1;
  __wrap_freeaddrinfo(resolved);
  if (require(g_lwip_freed == 1, "freeaddrinfo lwIP")) return 1;
  g_tunnel_ok = false; g_tunnel_online = false; resolved = NULL;
  if (require(__wrap_getaddrinfo("example.invalid", "80", NULL, &resolved) == 0,
              "resolucao nativa fallback")) return 1;
  __wrap_freeaddrinfo(resolved);
  if (require(g_real_freed == 1, "freeaddrinfo nativo") ||
      require(__wrap_connect(7, (struct sockaddr *)&address,
                             sizeof(address)) == -1 && errno == ECONNREFUSED,
              "connect nativo erro") ||
      require(__wrap_close(128) == 0 && __wrap_close(7) == 0,
              "close virtual e nativo") ||
      require(g_lwip_calls > 20 && g_real_calls > 3,
              "wrappers reais e virtuais exercitados")) return 1;

  g_tunnel_ok = true;
  g_tunnel_online = true;
  g_lwip_fail = true;
  g_connect_result = -1;
  g_connect_errno = EIO;
  struct pollfd failing_poll = {.fd = 128, .events = POLLIN};
  FD_ZERO(&read_set); FD_SET(128, &read_set);
  if (require(__wrap_socket(AF_INET, SOCK_STREAM, 0) == -1,
              "socket virtual erro") ||
      require(__wrap_connect(128, (struct sockaddr *)&address,
                             sizeof(address)) == -1,
              "connect virtual erro") ||
      require(__wrap_bind(128, (struct sockaddr *)&address, sizeof(address)) == -1,
              "bind virtual erro") ||
      require(__wrap_listen(128, 1) == -1, "listen virtual erro") ||
      require(__wrap_accept(128, (struct sockaddr *)&address, &address_length) == -1,
              "accept virtual erro") ||
      require(__wrap_send(128, "x", 1U, 0) == -1, "send virtual erro") ||
      require(__wrap_recv(128, buffer, sizeof(buffer), 0) == -1,
              "recv virtual erro") ||
      require(__wrap_sendto(128, "x", 1U, 0, (struct sockaddr *)&address,
                            sizeof(address)) == -1,
              "sendto virtual erro") ||
      require(__wrap_recvfrom(128, buffer, sizeof(buffer), 0,
                              (struct sockaddr *)&address, &address_length) == -1,
              "recvfrom virtual erro") ||
      require(__wrap_shutdown(128, SHUT_RDWR) == -1,
              "shutdown virtual erro") ||
      require(__wrap_read(128, buffer, sizeof(buffer)) == -1,
              "read virtual erro") ||
      require(__wrap_write(128, "x", 1U) == -1, "write virtual erro") ||
      require(__wrap_fcntl(128, F_SETFL, O_NONBLOCK) == -1,
              "fcntl virtual erro") ||
      require(__wrap_setsockopt(128, SOL_SOCKET, SO_KEEPALIVE, &enabled,
                               sizeof(enabled)) == -1,
              "setsockopt virtual erro") ||
      require(__wrap_getsockopt(128, SOL_SOCKET, SO_ERROR, &option_value,
                               &option_length) == -1,
              "getsockopt virtual erro") ||
      require(__wrap_getsockname(128, (struct sockaddr *)&address,
                                 &address_length) == -1,
              "getsockname virtual erro") ||
      require(__wrap_getpeername(128, (struct sockaddr *)&address,
                                 &address_length) == -1,
              "getpeername virtual erro") ||
      require(__wrap_poll(&failing_poll, 1U, 0) == -1,
              "poll virtual erro") ||
      require(__wrap_select(129, &read_set, NULL, NULL, &timeout) == -1,
              "select virtual erro") ||
      require(__wrap_getaddrinfo("example.invalid", "80", NULL, &resolved) ==
                  EAI_FAIL,
              "getaddrinfo virtual erro")) return 1;
  if (require(__wrap_close(128) == -1, "close virtual erro")) return 1;

  puts("OK: socket_shim real coberto com lwIP/Vita falsos");
  return 0;
}
