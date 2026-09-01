#include "tunnel.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#ifndef TSVITA_HOST_TEST
#include <psp2/kernel/processmgr.h>
#include <psp2/kernel/threadmgr.h>
#endif
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef TSVITA_HOST_TEST
#include "socket_shim_host_compat.h"
#else
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#endif

#define TSVITA_LWIP_FD_FIRST 128
#define TSVITA_LWIP_FD_LAST 191
#define TSVITA_MUX_SLICE_US 1000U
#define TSVITA_TRACE_LIMIT 256U
#define TSVITA_CONNECT_WAIT_MS 5000

int __real_socket(int domain, int type, int protocol);
int __real_connect(int socket_id, const struct sockaddr *address,
                   socklen_t address_length);
int __real_bind(int socket_id, const struct sockaddr *address,
                socklen_t address_length);
int __real_listen(int socket_id, int backlog);
int __real_accept(int socket_id, struct sockaddr *address,
                  socklen_t *address_length);
ssize_t __real_send(int socket_id, const void *buffer, size_t length,
                    int flags);
ssize_t __real_recv(int socket_id, void *buffer, size_t length, int flags);
ssize_t __real_sendto(int socket_id, const void *buffer, size_t length,
                      int flags, const struct sockaddr *destination,
                      socklen_t destination_length);
ssize_t __real_recvfrom(int socket_id, void *buffer, size_t length, int flags,
                        struct sockaddr *source, socklen_t *source_length);
int __real_shutdown(int socket_id, int how);
int __real_close(int descriptor);
ssize_t __real_read(int descriptor, void *buffer, size_t length);
ssize_t __real_write(int descriptor, const void *buffer, size_t length);
int __real_fcntl(int descriptor, int command, ...);
int __real_setsockopt(int socket_id, int level, int option,
                      const void *value, socklen_t value_length);
int __real_getsockopt(int socket_id, int level, int option, void *value,
                      socklen_t *value_length);
int __real_getsockname(int socket_id, struct sockaddr *address,
                       socklen_t *address_length);
int __real_getpeername(int socket_id, struct sockaddr *address,
                       socklen_t *address_length);
int __real_poll(struct pollfd *descriptors, nfds_t count, int timeout);
int __real_select(int max_descriptor, fd_set *read_set, fd_set *write_set,
                  fd_set *error_set, struct timeval *timeout);
int __real_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **result);
void __real_freeaddrinfo(struct addrinfo *result);

static bool is_virtual_socket(int descriptor) {
  return descriptor >= TSVITA_LWIP_FD_FIRST &&
         descriptor <= TSVITA_LWIP_FD_LAST;
}

static unsigned int g_trace_events;
static int g_virtual_fd_flags[TSVITA_LWIP_FD_LAST -
                              TSVITA_LWIP_FD_FIRST + 1];
static int g_virtual_socket_types[TSVITA_LWIP_FD_LAST -
                                  TSVITA_LWIP_FD_FIRST + 1];

static int virtual_socket_index(int descriptor) {
  return descriptor - TSVITA_LWIP_FD_FIRST;
}

static void trace_socket_event(const char *format, ...) {
  if (g_trace_events >= TSVITA_TRACE_LIMIT) {
    return;
  }
  ++g_trace_events;
  char message[192];
  va_list arguments;
  va_start(arguments, format);
  vsnprintf(message, sizeof(message), format, arguments);
  va_end(arguments);
  tsvita_trace("SOCKET", "%s", message);
}

static bool poll_has_virtual(const struct pollfd *descriptors, nfds_t count) {
  for (nfds_t index = 0; index < count; ++index) {
    if (is_virtual_socket(descriptors[index].fd)) {
      return true;
    }
  }
  return false;
}

int __wrap_socket(int domain, int type, int protocol) {
  if (domain == AF_INET && tsvita_tunnel_ensure_started() == 0) {
    int result = lwip_socket(domain, type, protocol);
    int saved_errno = errno;
    if (is_virtual_socket(result)) {
      g_virtual_fd_flags[virtual_socket_index(result)] = 0;
      g_virtual_socket_types[virtual_socket_index(result)] = type;
    }
    trace_socket_event("socket domain=%d type=%d proto=%d -> %d errno=%d",
                       domain, type, protocol, result, saved_errno);
    errno = saved_errno;
    return result;
  }
  return __real_socket(domain, type, protocol);
}

int __wrap_connect(int socket_id, const struct sockaddr *address,
                   socklen_t address_length) {
  if (is_virtual_socket(socket_id)) {
    const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
    const unsigned char *octets =
        (const unsigned char *)&ipv4->sin_addr.s_addr;
    trace_socket_event("connect fd=%d %u.%u.%u.%u:%u len=%u", socket_id,
                       octets[0], octets[1], octets[2], octets[3],
                       (unsigned int)ntohs(ipv4->sin_port),
                       (unsigned int)address_length);
    int socket_flags = lwip_fcntl(socket_id, F_GETFL, 0);
    int flags_errno = errno;
    bool restore_nonblocking =
        socket_flags >= 0 && (socket_flags & O_NONBLOCK) != 0;
    if (restore_nonblocking) {
      int blocking_result =
          lwip_fcntl(socket_id, F_SETFL, socket_flags & ~O_NONBLOCK);
      int blocking_errno = errno;
      trace_socket_event(
          "connect-mode fd=%d flags=0x%x blocking=%d errno=%d", socket_id,
          socket_flags, blocking_result, blocking_errno);
      if (blocking_result != 0) {
        restore_nonblocking = false;
      }
    } else {
      trace_socket_event("connect-mode fd=%d flags=0x%x errno=%d", socket_id,
                         socket_flags, flags_errno);
    }

    /*
     * VitaSDK's cURL requests a nonblocking socket, but lwIP's poll waiter
     * does not receive the connect-completion event on the Vita pthread port.
     * Complete only the handshake in blocking mode, then restore O_NONBLOCK
     * before returning the connected socket to cURL.
     */
    int result = lwip_connect(socket_id, address, address_length);
    int saved_errno = errno;
    if (restore_nonblocking) {
      int restore_result = lwip_fcntl(socket_id, F_SETFL, socket_flags);
      int restore_errno = errno;
      trace_socket_event(
          "connect-mode fd=%d restore=0x%x result=%d errno=%d", socket_id,
          socket_flags, restore_result, restore_errno);
      if (result == 0 && restore_result != 0) {
        result = -1;
        saved_errno = restore_errno;
      }
    }
    if (result < 0 && saved_errno == EINPROGRESS) {
      /*
       * Finish the asynchronous lwIP connect before returning to VitaSDK's
       * libcurl. The socket remains nonblocking for subsequent I/O.
       */
      struct pollfd descriptor = {
          .fd = socket_id,
          .events = POLLOUT | POLLERR | POLLHUP,
          .revents = 0,
      };
      int poll_result = lwip_poll(&descriptor, 1U, TSVITA_CONNECT_WAIT_MS);
      int poll_errno = errno;
      int socket_error = 0;
      socklen_t error_length = sizeof(socket_error);
      int option_result = -1;
      if (poll_result > 0) {
        option_result = lwip_getsockopt(socket_id, SOL_SOCKET, SO_ERROR,
                                        &socket_error, &error_length);
      }
      trace_socket_event(
          "connect-wait fd=%d poll=%d revents=0x%x poll_errno=%d "
          "getsockopt=%d so_error=%d",
          socket_id, poll_result, descriptor.revents, poll_errno,
          option_result, socket_error);
      if (poll_result > 0 && option_result == 0 && socket_error == 0) {
        result = 0;
        saved_errno = 0;
      } else if (socket_error != 0) {
        saved_errno = socket_error;
      } else if (poll_result == 0) {
        saved_errno = ETIMEDOUT;
      } else {
        saved_errno = poll_errno;
      }
    }
    trace_socket_event("connect fd=%d -> %d errno=%d", socket_id, result,
                       saved_errno);
    errno = saved_errno;
    return result;
  }
  return __real_connect(socket_id, address, address_length);
}

int __wrap_bind(int socket_id, const struct sockaddr *address,
                socklen_t address_length) {
  if (is_virtual_socket(socket_id)) {
    return lwip_bind(socket_id, address, address_length);
  }
  return __real_bind(socket_id, address, address_length);
}

int __wrap_listen(int socket_id, int backlog) {
  return is_virtual_socket(socket_id) ? lwip_listen(socket_id, backlog)
                                      : __real_listen(socket_id, backlog);
}

int __wrap_accept(int socket_id, struct sockaddr *address,
                  socklen_t *address_length) {
  return is_virtual_socket(socket_id)
             ? lwip_accept(socket_id, address, address_length)
             : __real_accept(socket_id, address, address_length);
}

ssize_t __wrap_send(int socket_id, const void *buffer, size_t length,
                    int flags) {
  if (!is_virtual_socket(socket_id)) {
    return __real_send(socket_id, buffer, length, flags);
  }
  ssize_t result = lwip_send(socket_id, buffer, length, flags);
  int saved_errno = errno;
  trace_socket_event("send fd=%d want=%u -> %d errno=%d", socket_id,
                     (unsigned int)length, (int)result, saved_errno);
  errno = saved_errno;
  return result;
}

ssize_t __wrap_recv(int socket_id, void *buffer, size_t length, int flags) {
  if (!is_virtual_socket(socket_id)) {
    return __real_recv(socket_id, buffer, length, flags);
  }
  ssize_t result = lwip_recv(socket_id, buffer, length, flags);
  int saved_errno = errno;
  trace_socket_event("recv fd=%d want=%u -> %d errno=%d", socket_id,
                     (unsigned int)length, (int)result, saved_errno);
  errno = saved_errno;
  return result;
}

ssize_t __wrap_sendto(int socket_id, const void *buffer, size_t length,
                      int flags, const struct sockaddr *destination,
                      socklen_t destination_length) {
  return is_virtual_socket(socket_id)
             ? lwip_sendto(socket_id, buffer, length, flags, destination,
                           destination_length)
             : __real_sendto(socket_id, buffer, length, flags, destination,
                             destination_length);
}

ssize_t __wrap_recvfrom(int socket_id, void *buffer, size_t length, int flags,
                        struct sockaddr *source, socklen_t *source_length) {
  return is_virtual_socket(socket_id)
             ? lwip_recvfrom(socket_id, buffer, length, flags, source,
                             source_length)
             : __real_recvfrom(socket_id, buffer, length, flags, source,
                               source_length);
}

int __wrap_shutdown(int socket_id, int how) {
  if (!is_virtual_socket(socket_id)) {
    return __real_shutdown(socket_id, how);
  }
  int result = lwip_shutdown(socket_id, how);
  int saved_errno = errno;
  trace_socket_event("shutdown fd=%d how=%d -> %d errno=%d", socket_id, how,
                     result, saved_errno);
  errno = saved_errno;
  return result;
}

int __wrap_close(int descriptor) {
  if (!is_virtual_socket(descriptor)) {
    return __real_close(descriptor);
  }
  int result = lwip_close(descriptor);
  int saved_errno = errno;
  if (result == 0) {
    g_virtual_fd_flags[virtual_socket_index(descriptor)] = 0;
    g_virtual_socket_types[virtual_socket_index(descriptor)] = 0;
  }
  trace_socket_event("close fd=%d -> %d errno=%d", descriptor, result,
                     saved_errno);
  errno = saved_errno;
  return result;
}

ssize_t __wrap_read(int descriptor, void *buffer, size_t length) {
  return is_virtual_socket(descriptor)
             ? lwip_read(descriptor, buffer, length)
             : __real_read(descriptor, buffer, length);
}

ssize_t __wrap_write(int descriptor, const void *buffer, size_t length) {
  return is_virtual_socket(descriptor)
             ? lwip_write(descriptor, buffer, length)
             : __real_write(descriptor, buffer, length);
}

int __wrap_fcntl(int descriptor, int command, ...) {
  int value = 0;
  bool has_argument = command != F_GETFL;
#ifdef F_GETFD
  has_argument = has_argument && command != F_GETFD;
#endif
#ifdef F_GETOWN
  has_argument = has_argument && command != F_GETOWN;
#endif
  if (has_argument) {
    va_list arguments;
    va_start(arguments, command);
    value = va_arg(arguments, int);
    va_end(arguments);
  }
  if (is_virtual_socket(descriptor)) {
    if (command == F_GETFD) {
      int result = g_virtual_fd_flags[virtual_socket_index(descriptor)];
      trace_socket_event("fcntl fd=%d F_GETFD -> %d", descriptor, result);
      errno = 0;
      return result;
    }
    if (command == F_SETFD) {
      /* Vita processes do not exec, but libcurl still requires CLOEXEC. */
      if ((value & ~FD_CLOEXEC) != 0) {
        trace_socket_event("fcntl fd=%d F_SETFD arg=%d -> -1 errno=%d",
                           descriptor, value, EINVAL);
        errno = EINVAL;
        return -1;
      }
      g_virtual_fd_flags[virtual_socket_index(descriptor)] = value;
      trace_socket_event("fcntl fd=%d F_SETFD arg=%d -> 0", descriptor,
                         value);
      errno = 0;
      return 0;
    }
    int result = lwip_fcntl(descriptor, command, value);
    int saved_errno = errno;
    trace_socket_event("fcntl fd=%d cmd=%d arg=%d -> %d errno=%d",
                       descriptor, command, value, result, saved_errno);
    errno = saved_errno;
    return result;
  }
  return has_argument ? __real_fcntl(descriptor, command, value)
                      : __real_fcntl(descriptor, command);
}

int __wrap_setsockopt(int socket_id, int level, int option,
                      const void *value, socklen_t value_length) {
  if (!is_virtual_socket(socket_id)) {
    return __real_setsockopt(socket_id, level, option, value, value_length);
  }
  if (level == SOL_SOCKET && option == SO_NONBLOCK &&
      value != NULL && value_length >= sizeof(int)) {
    unsigned long enabled = *(const int *)value != 0;
    return lwip_ioctl(socket_id, FIONBIO, &enabled);
  }
  if (level == SOL_SOCKET && option == SO_RCVTIMEO &&
      g_virtual_socket_types[virtual_socket_index(socket_id)] == SOCK_DGRAM) {
    /*
     * On Vita, lwIP's Unix sys_arch timed condition wait expires almost
     * immediately instead of honoring the requested 100 ms UDP receive
     * timeout. Moonlight then counts 100 false timeouts in a few milliseconds,
     * tears down a live stream, and races its connection-start callback.
     * Reporting SO_RCVTIMEO as unsupported is an intentional API contract:
     * Moonlight falls back to poll(), whose sliced monotonic timeout is
     * implemented above and has been validated on physical hardware.
     */
    trace_socket_event(
        "setsockopt fd=%d SO_RCVTIMEO udp-fallback -> -1 errno=%d",
        socket_id, ENOPROTOOPT);
    errno = ENOPROTOOPT;
    return -1;
  }
  return lwip_setsockopt(socket_id, level, option, value, value_length);
}

int __wrap_getsockopt(int socket_id, int level, int option, void *value,
                      socklen_t *value_length) {
  if (!is_virtual_socket(socket_id)) {
    return __real_getsockopt(socket_id, level, option, value, value_length);
  }
  int result = lwip_getsockopt(socket_id, level, option, value, value_length);
  int saved_errno = errno;
  int option_value = value != NULL && value_length != NULL &&
                             *value_length >= sizeof(int)
                         ? *(const int *)value
                         : 0;
  trace_socket_event(
      "getsockopt fd=%d level=0x%x option=0x%x -> %d value=%d errno=%d",
      socket_id, level, option, result, option_value, saved_errno);
  errno = saved_errno;
  return result;
}

int __wrap_getsockname(int socket_id, struct sockaddr *address,
                       socklen_t *address_length) {
  return is_virtual_socket(socket_id)
             ? lwip_getsockname(socket_id, address, address_length)
             : __real_getsockname(socket_id, address, address_length);
}

int __wrap_getpeername(int socket_id, struct sockaddr *address,
                       socklen_t *address_length) {
  return is_virtual_socket(socket_id)
             ? lwip_getpeername(socket_id, address, address_length)
             : __real_getpeername(socket_id, address, address_length);
}

int __wrap_poll(struct pollfd *descriptors, nfds_t count, int timeout) {
  if (!poll_has_virtual(descriptors, count)) {
    return __real_poll(descriptors, count, timeout);
  }
  bool has_real = false;
  for (nfds_t index = 0; index < count; ++index) {
    if (descriptors[index].fd >= 0 && !is_virtual_socket(descriptors[index].fd)) {
      has_real = true;
      break;
    }
  }
  if (!has_real) {
    /*
     * The Vita pthread port can miss a notification while blocked inside
     * lwip_poll(). TCP state and queued data are still correct, as confirmed
     * by packet capture, so sample readiness without blocking and yield in
     * short slices. This covers both connect completion, data arrival, and a
     * FIN/EOF that arrives after poll begins. The latter is required because
     * Moonlight reads each RTSP response until Sunshine closes the socket.
     */
    uint64_t started = sceKernelGetProcessTimeWide();
    trace_socket_event("poll lwip-fatiado count=%u timeout=%d",
                       (unsigned int)count, timeout);
    for (;;) {
      int result = lwip_poll(descriptors, count, 0);
      int saved_errno = errno;
      if (result != 0 || timeout == 0) {
        trace_socket_event(
            "poll lwip-fatiado count=%u timeout=%d -> %d revents0=0x%x "
            "errno=%d",
            (unsigned int)count, timeout, result,
            count > 0 ? descriptors[0].revents : 0, saved_errno);
        errno = saved_errno;
        return result;
      }
      uint64_t elapsed = sceKernelGetProcessTimeWide() - started;
      if (timeout > 0 && elapsed >= (uint64_t)timeout * 1000ULL) {
        return 0;
      }
      sceKernelDelayThread(TSVITA_MUX_SLICE_US);
    }
  }

  struct pollfd *virtual_set = calloc(count, sizeof(*virtual_set));
  struct pollfd *real_set = calloc(count, sizeof(*real_set));
  if (virtual_set == NULL || real_set == NULL) {
    free(virtual_set);
    free(real_set);
    errno = ENOMEM;
    return -1;
  }
  for (nfds_t index = 0; index < count; ++index) {
    virtual_set[index] = descriptors[index];
    real_set[index] = descriptors[index];
    if (is_virtual_socket(descriptors[index].fd)) {
      real_set[index].fd = -1;
    } else {
      virtual_set[index].fd = -1;
    }
  }

  trace_socket_event("poll misto count=%u timeout=%d", (unsigned int)count,
                     timeout);
  uint64_t started = sceKernelGetProcessTimeWide();
  for (;;) {
    int virtual_ready = lwip_poll(virtual_set, count, 0);
    int virtual_errno = errno;
    int real_ready = __real_poll(real_set, count, 0);
    int real_errno = errno;
    if (virtual_ready < 0 || real_ready < 0) {
      free(virtual_set);
      free(real_set);
      errno = virtual_ready < 0 ? virtual_errno : real_errno;
      return -1;
    }
    int ready = 0;
    for (nfds_t index = 0; index < count; ++index) {
      descriptors[index].revents =
          virtual_set[index].revents | real_set[index].revents;
      if (descriptors[index].revents != 0) {
        ++ready;
      }
    }
    if (ready > 0 || timeout == 0) {
      free(virtual_set);
      free(real_set);
      return ready;
    }
    uint64_t elapsed = sceKernelGetProcessTimeWide() - started;
    if (timeout > 0 && elapsed >= (uint64_t)timeout * 1000ULL) {
      free(virtual_set);
      free(real_set);
      return 0;
    }
    sceKernelDelayThread(TSVITA_MUX_SLICE_US);
  }
}

int __wrap_select(int max_descriptor, fd_set *read_set, fd_set *write_set,
                  fd_set *error_set, struct timeval *timeout) {
  bool has_virtual = false;
  bool has_real = false;
  for (int descriptor = 0; descriptor < max_descriptor; ++descriptor) {
    bool selected = (read_set != NULL && FD_ISSET(descriptor, read_set)) ||
                    (write_set != NULL && FD_ISSET(descriptor, write_set)) ||
                    (error_set != NULL && FD_ISSET(descriptor, error_set));
    if (selected) {
      if (is_virtual_socket(descriptor)) {
        has_virtual = true;
      } else {
        has_real = true;
      }
    }
  }
  if (!has_virtual) {
    return __real_select(max_descriptor, read_set, write_set, error_set,
                         timeout);
  }
  if (!has_real) {
    fd_set original_read;
    fd_set original_write;
    fd_set original_error;
    if (read_set != NULL) original_read = *read_set;
    if (write_set != NULL) original_write = *write_set;
    if (error_set != NULL) original_error = *error_set;
    uint64_t timeout_us = UINT64_MAX;
    if (timeout != NULL) {
      timeout_us = (uint64_t)timeout->tv_sec * 1000000ULL +
                   (uint64_t)timeout->tv_usec;
    }
    uint64_t started = sceKernelGetProcessTimeWide();
    trace_socket_event("select lwip-fatiado maxfd=%d", max_descriptor);
    for (;;) {
      if (read_set != NULL) *read_set = original_read;
      if (write_set != NULL) *write_set = original_write;
      if (error_set != NULL) *error_set = original_error;
      struct timeval zero = {0, 0};
      int result = lwip_select(max_descriptor, read_set, write_set, error_set,
                               &zero);
      int saved_errno = errno;
      if (result != 0 || timeout_us == 0) {
        trace_socket_event("select lwip-fatiado maxfd=%d -> %d errno=%d",
                           max_descriptor, result, saved_errno);
        errno = saved_errno;
        return result;
      }
      if (timeout_us != UINT64_MAX &&
          sceKernelGetProcessTimeWide() - started >= timeout_us) {
        return 0;
      }
      sceKernelDelayThread(TSVITA_MUX_SLICE_US);
    }
  }

  fd_set original_read;
  fd_set original_write;
  fd_set original_error;
  if (read_set != NULL) original_read = *read_set;
  if (write_set != NULL) original_write = *write_set;
  if (error_set != NULL) original_error = *error_set;
  uint64_t timeout_us = UINT64_MAX;
  if (timeout != NULL) {
    timeout_us = (uint64_t)timeout->tv_sec * 1000000ULL +
                 (uint64_t)timeout->tv_usec;
  }
  uint64_t started = sceKernelGetProcessTimeWide();
  trace_socket_event("select misto maxfd=%d", max_descriptor);

  for (;;) {
    fd_set virtual_read, virtual_write, virtual_error;
    fd_set real_read, real_write, real_error;
    FD_ZERO(&virtual_read); FD_ZERO(&virtual_write); FD_ZERO(&virtual_error);
    FD_ZERO(&real_read); FD_ZERO(&real_write); FD_ZERO(&real_error);
    for (int descriptor = 0; descriptor < max_descriptor; ++descriptor) {
      bool virtual_fd = is_virtual_socket(descriptor);
      if (read_set != NULL && FD_ISSET(descriptor, &original_read))
        FD_SET(descriptor, virtual_fd ? &virtual_read : &real_read);
      if (write_set != NULL && FD_ISSET(descriptor, &original_write))
        FD_SET(descriptor, virtual_fd ? &virtual_write : &real_write);
      if (error_set != NULL && FD_ISSET(descriptor, &original_error))
        FD_SET(descriptor, virtual_fd ? &virtual_error : &real_error);
    }
    struct timeval zero = {0, 0};
    int virtual_ready = lwip_select(max_descriptor,
                                    read_set ? &virtual_read : NULL,
                                    write_set ? &virtual_write : NULL,
                                    error_set ? &virtual_error : NULL, &zero);
    int virtual_errno = errno;
    int real_ready = __real_select(max_descriptor,
                                   read_set ? &real_read : NULL,
                                   write_set ? &real_write : NULL,
                                   error_set ? &real_error : NULL, &zero);
    int real_errno = errno;
    if (virtual_ready < 0 || real_ready < 0) {
      errno = virtual_ready < 0 ? virtual_errno : real_errno;
      return -1;
    }
    int ready = 0;
    if (read_set != NULL) FD_ZERO(read_set);
    if (write_set != NULL) FD_ZERO(write_set);
    if (error_set != NULL) FD_ZERO(error_set);
    for (int descriptor = 0; descriptor < max_descriptor; ++descriptor) {
      bool descriptor_ready = false;
      if (read_set != NULL &&
          (FD_ISSET(descriptor, &virtual_read) ||
           FD_ISSET(descriptor, &real_read))) {
        FD_SET(descriptor, read_set); descriptor_ready = true;
      }
      if (write_set != NULL &&
          (FD_ISSET(descriptor, &virtual_write) ||
           FD_ISSET(descriptor, &real_write))) {
        FD_SET(descriptor, write_set); descriptor_ready = true;
      }
      if (error_set != NULL &&
          (FD_ISSET(descriptor, &virtual_error) ||
           FD_ISSET(descriptor, &real_error))) {
        FD_SET(descriptor, error_set); descriptor_ready = true;
      }
      if (descriptor_ready) ++ready;
    }
    if (ready > 0 || timeout_us == 0) return ready;
    if (timeout_us != UINT64_MAX &&
        sceKernelGetProcessTimeWide() - started >= timeout_us) return 0;
    sceKernelDelayThread(TSVITA_MUX_SLICE_US);
  }
}

int __wrap_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **result) {
  if (tsvita_tunnel_ensure_started() == 0) {
    int lookup_result = lwip_getaddrinfo(node, service, hints, result);
    if (lookup_result == 0 && result != NULL) {
      /*
       * lwIP assumes sockaddr_storage is the same size as sockaddr_in in an
       * IPv4-only build. VitaSDK uses the BSD 128-byte storage structure, so
       * passing ai_addrlen through unchanged makes lwip_connect() reject the
       * address even though the sockaddr_in at ai_addr is valid.
       */
      for (struct addrinfo *entry = *result; entry != NULL;
           entry = entry->ai_next) {
        if (entry->ai_family == AF_INET) {
          entry->ai_addrlen = sizeof(struct sockaddr_in);
        }
      }
    }
    trace_socket_event("getaddrinfo node=%s service=%s -> %d len=%u",
                       node != NULL ? node : "(null)",
                       service != NULL ? service : "(null)", lookup_result,
                       lookup_result == 0 && result != NULL && *result != NULL
                           ? (unsigned int)(*result)->ai_addrlen : 0U);
    return lookup_result;
  }
  return __real_getaddrinfo(node, service, hints, result);
}

void __wrap_freeaddrinfo(struct addrinfo *result) {
  if (tsvita_tunnel_is_online()) {
    lwip_freeaddrinfo(result);
  } else {
    __real_freeaddrinfo(result);
  }
}
