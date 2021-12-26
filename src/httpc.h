#ifndef HTTPC_H
#define HTTPC_H
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>      // errno
#include <fcntl.h>      // fcntl, F_GETFL, F_SETFL, O_NONBLOCK
#include <netinet/in.h> // htons, sockaddr_in, INADDR_ANY
#include <stdbool.h>    // bool
#include <stdint.h>     // uint8_t
#include <stdio.h>      // STDERR, STDOUT, fprintf
#include <stdlib.h>     // size_t
#include <string.h>
#include <sys/epoll.h>  // epoll_create1(), epoll_ctl(), struct epoll_event
#include <sys/socket.h> // socket, AF_UNIX, SOCK_STREAM, SOCK_DGRAM
#include <time.h>       // strftime(), time(), time_t, struct tm,
#include <unistd.h>     // close, read, write

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

#define HTTPC_LOG_AND_THEN(execution_code)                                     \
  do                                                                           \
  {                                                                            \
    time_t rawtime;                                                            \
    struct tm *timeinfo;                                                       \
    time(&rawtime);                                                            \
    timeinfo = localtime(&rawtime);                                            \
    char buffer[80];                                                           \
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);                       \
    if (isatty(fileno(stderr)))                                                \
    {                                                                          \
      fprintf(stderr, ANSI_COLOR_CYAN "[%s]" ANSI_COLOR_RESET, buffer);        \
      fprintf(stderr, " " ANSI_COLOR_YELLOW "%s:%d" ANSI_COLOR_RESET,          \
              __FILE__, __LINE__);                                             \
      fprintf(stderr, " " ANSI_COLOR_GREEN "%s()" ANSI_COLOR_RESET " - ",      \
              __func__);                                                       \
    } else                                                                     \
    {                                                                          \
      fprintf(stderr, "[%s] %s:%d %s() - ", buffer, __FILE__, __LINE__,        \
              __func__);                                                       \
    }                                                                          \
    execution_code;                                                            \
    fprintf(stderr, "\n");                                                     \
  } while (0)

void httpc_print_socket_peer_info(FILE *stream, struct sockaddr_in *peer_addr,
                                  int use_ansi)
{
  char ip_str[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &peer_addr->sin_addr, ip_str, sizeof(ip_str)) == NULL)
  {
    fprintf(stream, "Could not convert the IP address to string");
    return;
  }
  int port = ntohs(peer_addr->sin_port);

  if (use_ansi)
  {
    fprintf(stream, "peer address %s%s:%d%s", ANSI_COLOR_CYAN, ip_str, port,
            ANSI_COLOR_RESET);
  } else
  {
    fprintf(stream, "peer address %s:%d", ip_str, port);
  }
}

void httpc_print_epoll_event_flags(FILE *stream, struct epoll_event event,
                                   int use_ansi)
{
  uint32_t events = event.events;
  fprintf(stream, "epoll events " ANSI_COLOR_CYAN "fd=%d" ANSI_COLOR_RESET " ",
          event.data.fd);

  if (events & EPOLLIN)
  {
    fprintf(stream, "%sEPOLLIN%s ", use_ansi ? ANSI_COLOR_CYAN : "",
            use_ansi ? ANSI_COLOR_RESET : "");
  }
  if (events & EPOLLOUT)
  {
    fprintf(stream, "%sEPOLLOUT%s ", use_ansi ? ANSI_COLOR_CYAN : "",
            use_ansi ? ANSI_COLOR_RESET : "");
  }
  if (events & EPOLLPRI)
  {
    fprintf(stream, "%sEPOLLPRI%s ", use_ansi ? ANSI_COLOR_CYAN : "",
            use_ansi ? ANSI_COLOR_RESET : "");
  }
  if (events & EPOLLERR)
  {
    fprintf(stream, "%sEPOLLERR%s ", use_ansi ? ANSI_COLOR_RED : "",
            use_ansi ? ANSI_COLOR_RESET : "");
  }
  if (events & EPOLLHUP)
  {
    fprintf(stream, "%sEPOLLHUP%s ", use_ansi ? ANSI_COLOR_RED : "",
            use_ansi ? ANSI_COLOR_RESET : "");
  }
  if (events & EPOLLRDHUP)
  {
    fprintf(stream, "%sEPOLLRDHUP%s ", use_ansi ? ANSI_COLOR_RED : "",
            use_ansi ? ANSI_COLOR_RESET : "");
  }
  if (events & EPOLLONESHOT)
  {
    fprintf(stream, "%sEPOLLONESHOT%s ", use_ansi ? ANSI_COLOR_MAGENTA : "",
            use_ansi ? ANSI_COLOR_RESET : "");
  }
  if (events & EPOLLET)
  {
    fprintf(stream, "%sEPOLLET%s ", use_ansi ? ANSI_COLOR_MAGENTA : "",
            use_ansi ? ANSI_COLOR_RESET : "");
  }
#ifdef EPOLLWAKEUP
  if (events & EPOLLWAKEUP)
  {
    fprintf(stream, "%sEPOLLWAKEUP%s ", use_ansi ? ANSI_COLOR_BLUE : "",
            use_ansi ? ANSI_COLOR_RESET : "");
  }
#endif
#ifdef EPOLLEXCLUSIVE
  if (events & EPOLLEXCLUSIVE)
  {
    fprintf(stream, "%sEPOLLEXCLUSIVE%s ", use_ansi ? ANSI_COLOR_BLUE : "",
            use_ansi ? ANSI_COLOR_RESET : "");
  }
#endif
}

#define HTTPC_LOG(fmt, ...)                                                    \
  do                                                                           \
  {                                                                            \
    time_t rawtime;                                                            \
    struct tm *timeinfo;                                                       \
    time(&rawtime);                                                            \
    timeinfo = localtime(&rawtime);                                            \
    char buffer[80];                                                           \
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);                       \
    if (isatty(fileno(stderr)))                                                \
    {                                                                          \
      fprintf(stderr, ANSI_COLOR_CYAN "[%s]" ANSI_COLOR_RESET, buffer);        \
      fprintf(stderr, " " ANSI_COLOR_YELLOW "%s:%d" ANSI_COLOR_RESET,          \
              __FILE__, __LINE__);                                             \
      fprintf(stderr, " " ANSI_COLOR_GREEN "%s()" ANSI_COLOR_RESET " - ",      \
              __func__);                                                       \
      fprintf(stderr, fmt "\n", ##__VA_ARGS__);                                \
    } else                                                                     \
    {                                                                          \
      fprintf(stderr, "[%s] %s:%d %s() - " fmt "\n", buffer, __FILE__,         \
              __LINE__, __func__, ##__VA_ARGS__);                              \
    }                                                                          \
  } while (0)

/// a view or slice type that does not own the underlying data only stores a
/// pointer and size
struct httpc_bytes_view
{
  uint8_t *data;
  size_t size;
};

struct httpc_session_t
{
  int fd;

  bool _usable;

  uint8_t *_send_buf;
  size_t _send_buf_size;

  uint8_t *_recv_buf;
  size_t _recv_buf_size;
};

struct httpc_request_t
{
  struct httpc_bytes_view path;
};

struct httpc_list_t
{
  void *restrict ptr;
  size_t elem_size;
  size_t length;
  size_t capacity;
};

size_t next_power_of_two(size_t x)
{
  if (x <= 1)
    return 1;

  // For 32-bit size_t, if you're working with 64-bit size, use __builtin_clzll
  const int bits_in_size_t = sizeof(size_t) * 8;
  if (x > ((size_t)1 << (bits_in_size_t - 2)))
  {
    // Handle overflow case
    return (size_t)0;
  }

  // Subtract 1 to handle cases where x is already a power of 2
  size_t p = x - 1;

  // Using clz to find leading zeros and then shifting to get next power of two
  // Adjust for size_t bit count if different from 32
  size_t next_pow2 = (size_t)1 << (bits_in_size_t - __builtin_clzl(p) - 1);

  return next_pow2 < x ? next_pow2 << 1 : next_pow2;
}

void *httpc_recalloc(void *ptr, size_t old_num, size_t new_num, size_t size)
{
  if (new_num == 0)
  {
    free(ptr);
    HTTPC_LOG("new_num is 0");
    return NULL;
  } else if (!ptr)
  {
    // Behave like calloc for NULL ptr
    void *p = calloc(new_num, size);
    HTTPC_LOG("calloc result is %p", p);
    return p;
  } else if (new_num > old_num)
  {
    // Need to grow the memory block
    HTTPC_LOG("ptr=%p %zu %zu size=%zu", ptr, new_num, size, new_num * size);
    void *new_ptr = realloc(ptr, new_num * size);
    if (new_ptr)
    {
      // Zero the new portion
      size_t old_size = old_num * size;
      size_t new_size = new_num * size;
      memset((char *)new_ptr + old_size, 0, new_size - old_size);
    }
    HTTPC_LOG("grow result is %p", new_ptr);
    return new_ptr;
  } else
  {
    // Shrinking or same size, just realloc
    return realloc(ptr, new_num * size);
  }
}

void httpc_list_reserve(struct httpc_list_t *lst, size_t n)
{
  if (lst == NULL)
  {
    return;
  }

  if (lst->ptr == NULL)
  {
    HTTPC_LOG("allocating list with capacity %zu", next_power_of_two(n));
    void *ptr = calloc(next_power_of_two(n), lst->elem_size);
    if (ptr == NULL)
    {
      return;
    }
    lst->ptr = ptr;
    lst->capacity = next_power_of_two(n);
    lst->length = 0;
    return;
  }

  if (lst->length == lst->capacity)
  {
    HTTPC_LOG("list has reached length=%zu of capacity=%zu", lst->length,
              lst->capacity);
    lst->ptr =
        httpc_recalloc(lst->ptr, lst->capacity,
                       next_power_of_two(lst->capacity + 1), lst->elem_size);
    HTTPC_LOG("recalloc now a %p", lst->ptr);
    lst->capacity = next_power_of_two(lst->capacity + 1);
  } else
  {
    size_t n_remaining = lst->capacity - lst->length;
    // HTTPC_LOG("%zu, %zu, %zu", n_remaining, lst->capacity,
    // next_power_of_two(lst->capacity + 1));
    if (n < n_remaining)
    {

      HTTPC_LOG("recalloc now a %p", lst->ptr);
      lst->ptr =
          httpc_recalloc(lst->ptr, lst->capacity,
                         next_power_of_two(lst->capacity + 1), lst->elem_size);
      lst->capacity = next_power_of_two(lst->capacity + 1);
    }
  }
}

void *httpc_list_emplace(struct httpc_list_t *lst)
{
  if (lst == NULL)
  {
    return NULL;
  } else
  {

    httpc_list_reserve(lst, 1);
  }

  return &lst->ptr[(lst->length++ * lst->elem_size)];
}

void *httpc_list_nth(struct httpc_list_t *lst, size_t nth)
{
  if (lst == NULL)
  {
    return NULL;
  }

  if (nth >= lst->length)
  {
    return NULL;
  } else
  {
    return &lst->ptr[nth * lst->elem_size];
  }
}

struct httpc_server_t
{
  int epoll_fd;
  int listen_fd;
  // list of events
  struct httpc_list_t events;
  // list of sessions
  struct httpc_list_t sessions;
  // dynamicall sized array of httpc_request_t to be processed
  struct httpc_request_t *pending_requests;
  size_t pending_requests_size;
};

enum httpc_status_t
{
  HTTPC_STATUS_OK = 200,
  HTTPC_STATUS_NOT_FOUND = 404,
};

enum HTTPC_RESPONSE_BODY_TYPE_STRING
{
  HTTPC_RESPONSE_BODY_TYPE_STRING = 0,
  HTTPC_RESPONSE_BODY_TYPE_STRING_VIEW,
};

struct httpc_response_body_t
{
  enum HTTPC_RESPONSE_BODY_TYPE_STRING type;
  union {
    const char *string;
    struct
    {
      const char *data;
      size_t size;
    } string_view;
  };
};

struct httpc_response_t
{
  enum httpc_status_t status;
  struct httpc_response_body_t body;
};

struct httpc_callback_args_t
{
  struct httpc_session_t *session;
  struct httpc_server_t *server;
  void *context;
};

typedef struct httpc_response_t (*httpc_route_callback_t)(
    struct httpc_callback_args_t *);

struct httpc_route_t
{
  const char *path;
  httpc_route_callback_t callback;
};

struct httpc_response_body_t httpc_response_string_owned(const char *buf)
{
  struct httpc_response_body_t body = {};

  body.type = HTTPC_RESPONSE_BODY_TYPE_STRING;
  body.string = buf;

  return body;
}

/// A naive way of finding the associated session for a given file descriptor.
struct httpc_session_t *
httpc_server_get_session_by_fd(struct httpc_server_t *server, int fd)
{
  for (size_t i = 0; i < server->sessions.length; i++)
  {
    struct httpc_session_t *s = httpc_list_nth(&server->sessions, i);
    if (s == NULL)
    {
      return NULL;
    }

    if (s->_usable == 0)
    {
      continue;
    }

    if (s->fd == fd)
    {
      return s;
    }
  }

  return NULL;
}

/// try and set a socket to non-blocking mode.
int httpc_set_non_blocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1)
  {
    return -1;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
  {
    return -2;
  }

  return 0;
}

/// Release this servers resources and terminate active sessions.
void httpc_server_close(struct httpc_server_t *restrict server)
{
  if (server == NULL)
  {
    return;
  }

  close(server->listen_fd);
  close(server->epoll_fd);
}

/// Create and bind a server to `*:<port>` and start listening for connections.
int httpc_server_new(int port, struct httpc_server_t *restrict server)
{
  if (server == NULL)
  {
    return -1;
  }

  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd == -1)
  {
    return -1;
  }

  if (httpc_set_non_blocking(listen_fd) != 0)
  {
    close(listen_fd);
    return -1;
  }

  int opt = 1;
  if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
  {
    close(listen_fd);
    return -1;
  }

  struct sockaddr_in serv_addr = {0};

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(port);

  if (bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    close(listen_fd);
    return -1;
  }

  if (listen(listen_fd, 1) < 0)
  {
    close(listen_fd);
    return -1;
  }

  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1)
  {
    close(listen_fd);
    close(epoll_fd);
    return -1;
  }

  struct epoll_event event = {0};
  event.events = EPOLLIN;
  event.data.fd = listen_fd;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event) == -1)
  {
    close(listen_fd);
    close(epoll_fd);
    return -1;
  };

  server->epoll_fd = epoll_fd;
  server->listen_fd = listen_fd;
  server->events.elem_size = sizeof(struct epoll_event);
  server->sessions.elem_size = sizeof(struct httpc_session_t);

  return 0;
}

int httpc_fd_read_into_buffer(int fd, uint8_t *restrict buf, size_t buf_size)
{
  if (fd == -1 || buf == NULL || buf_size == 0)
  {
    return -1;
  }

  int n = read(fd, buf, buf_size);
  if (n == -1)
  {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
    {
      return 0;
    }

    return -1;
  }

  return n;
}

int httpc_server_accept(struct httpc_server_t *restrict server)
{
  if (server == NULL)
  {
    return -1;
  }

  struct sockaddr_in peer_addr;
  socklen_t peer_addr_len = sizeof(peer_addr);
  int conn_fd =
      accept(server->listen_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);

  if (conn_fd == -1)
  {
    if (errno != EAGAIN && errno != EWOULDBLOCK)
    {
      // in the extremely unlikely event that EAGAIN or EWOULDBLOCK shows up, do
      // nothing.
      return 0;
    } else
    {
      return -1;
    }
  } else
  {
    if (httpc_set_non_blocking(conn_fd) != 0)
    {
      close(conn_fd);
      return -1;
    }

    struct epoll_event event = {0};
    event.events = EPOLLIN;
    event.data.fd = conn_fd;

    if (epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, conn_fd, &event) == -1)
    {
      close(conn_fd);
      return -1;
    }

    HTTPC_LOG("accepting connection fd=%d", conn_fd);
    HTTPC_LOG_AND_THEN(httpc_print_socket_peer_info(stderr, &peer_addr,
                                                    isatty(fileno(stderr))));

    struct httpc_session_t *session = httpc_list_emplace(&server->sessions);
    if (session == NULL)
    {
      HTTPC_LOG("could not allocate seat for session");
      close(conn_fd);
      return -3;
    }
    HTTPC_LOG("emplaced session onto list at %p", session);
    session->_recv_buf = NULL;
    session->_recv_buf_size = 0;
    session->_send_buf = NULL;
    session->_send_buf_size = 0;
    session->_usable = true;
    session->fd = conn_fd;

    for (int i = 0; i != server->sessions.length; i++)
    {
      fprintf(
          stderr, "session[%d]: fd=%d\n", i,
          ((struct httpc_session_t *)httpc_list_nth(&server->sessions, i))->fd);
    }
  }

  return 0;
}

int httpc_server_handle_epoll_event(struct httpc_server_t *restrict server,
                                    struct epoll_event *event_in)
{
  if (server == NULL)
  {
    return -1;
  }

  if (event_in == NULL)
  {
    return -1;
  }

  bool closed = false;

  struct epoll_event event = {0};
  event.data.fd = event_in->data.fd;
  event.events = EPOLLIN;

  if (event_in->events & EPOLLIN)
  {
    uint8_t buf[1024] = {0};

    int n = httpc_fd_read_into_buffer(event_in->data.fd, (uint8_t *)&buf,
                                      sizeof(buf) - 1);
    if (n == -1)
    {
      return -1;
    } else if (n == 0)
    {
      closed = true;
    }

    HTTPC_LOG("%d: %s", event_in->data.fd, &buf);
    if (closed)
    {
      HTTPC_LOG("connection closed");
    }

    // TODO: parse the data
  } else if (event_in->events & EPOLLOUT)
  {
    struct httpc_session_t *session =
        httpc_server_get_session_by_fd(server, event_in->data.fd);

    if (session == NULL)
    {
      closed = true;
      return 0;
    }

    if (session->_send_buf_size > 0 && session->_send_buf != NULL)
    {
      int n = send(event_in->data.fd, session->_send_buf,
                   session->_send_buf_size, 0);
      if (n == -1)
      {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
          return -1;
        }
      } else if (n == session->_send_buf_size)
      {
        session->_send_buf_size = 0;
        free(session->_send_buf);
        session->_send_buf = NULL;
      } else if (n > 0)
      {
        session->_send_buf_size -= n;
        session->_send_buf =
            realloc(session->_send_buf, session->_send_buf_size);

        if (session->_send_buf == NULL)
        {
          return -1;
        }
      }
    }
  }

  if (epoll_ctl(server->epoll_fd, (closed ? EPOLL_CTL_DEL : EPOLL_CTL_MOD),
                event_in->data.fd, (closed ? NULL : &event)) == -1)
  {
    return -1;
  }

  return 0;
}

/// Wait for a maximum of `timeout_ms` milliseconds and handle any events that
/// occur once.
int httpc_server_await_timeout(struct httpc_server_t *restrict server,
                               int timeout_ms)
{
  if (server == NULL)
  {
    return -1;
  }

  httpc_list_reserve(&server->events, 16);
  // HTTPC_LOG("server event list is ready at %p with capcity of %zu",
  // server->events.ptr, server->events.capacity);
  int n_ready =
      epoll_wait(server->epoll_fd, (struct epoll_event *)server->events.ptr,
                 server->events.capacity, timeout_ms);
  if (n_ready == -1)
  {
    return -1;
  } else
  {
    // HTTPC_LOG("processing epoll events %d", n_ready);
  }

  for (int ix = 0; ix != n_ready; ix++)
  {
    struct epoll_event *event =
        &((struct epoll_event *)(server->events.ptr))[ix];
    if (event == NULL)
    {
      HTTPC_LOG("event at index %d is null", ix);
      return 0;
    }
    HTTPC_LOG_AND_THEN(
        httpc_print_epoll_event_flags(stderr, *event, isatty(fileno(stderr))));

    bool is_listen_fd = event->data.fd == server->listen_fd;

    if (event->events & EPOLLERR)
    {
      if (is_listen_fd)
      {
        return -1;
      } else
      {
        close(event->data.fd);
        continue;
      }
    }

    if (is_listen_fd)
    {
      httpc_server_accept(server);
    } else
    {
      httpc_server_handle_epoll_event(server, event);
    }
  }

  return 0;
}

struct httpc_route_t httpc_route(const char *path,
                                 httpc_route_callback_t callback)
{
  struct httpc_route_t route = {0};

  route.path = path;
  route.callback = callback;

  return route;
}

int httpc_invoke_route_handlers(struct httpc_server_t *server,
                                struct httpc_route_t *routes,
                                size_t routes_size)
{
  return -1;
}

#endif // HTTPC_H
