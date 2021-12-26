#include <stdio.h>  // for STDERR, STDOUT, fprintf
#include <fcntl.h>  // for fcntl, F_GETFL, F_SETFL, O_NONBLOCK
#include <unistd.h> // for close, read, write
#include <errno.h>  // for errno

#include <sys/epoll.h>  // for epoll_create1(), epoll_ctl(), struct epoll_event
#include <sys/socket.h> // for socket, AF_UNIX, SOCK_STREAM, SOCK_DGRAM

#include <netinet/in.h>

#include "httpc.h"

/// A naive way of finding the associated session for a given file descriptor.
struct httpc_session_t *httpc_server_get_session(struct httpc_server_t *server, int fd)
{
    for (size_t i = 0; i < server->sessions_size; i++)
    {
        if (server->sessions[i]._usable == 0)
        {
            continue;
        }

        if (server->sessions[i].fd == fd)
        {
            return &server->sessions[i];
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

    if (server->events != NULL)
    {
        free(server->events);
    }
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
    server->events = NULL;
    server->events_size = 0;

    return 0;
}

int httpc_recv(int fd, uint8_t *restrict buf, size_t buf_size)
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
    int conn_fd = accept(server->listen_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);

    if (conn_fd == -1)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            // in the extremely unlikely event that EAGAIN or EWOULDBLOCK shows up, do nothing.
            return 0;
        }
        else
        {
            return -1;
        }
    }
    else
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
    }

    return 0;
}

int httpc_server_handle_epoll_event(struct httpc_server_t *restrict server, struct epoll_event *event_in)
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

        int n = httpc_recv(event_in->data.fd, (uint8_t *)&buf, sizeof(buf) - 1);
        if (n == -1)
        {
            return -1;
        }
        else if (n == 0)
        {
            closed = true;
        }

        // TODO: parse the data
    }
    else if (event_in->events & EPOLLOUT)
    {
        struct httpc_session_t *session = httpc_server_get_session(server, event_in->data.fd);

        if (session == NULL)
        {
            closed = true;
            return 0;
        }

        if (session->_send_buf_size > 0 && session->_send_buf != NULL)
        {
            int n = send(event_in->data.fd, session->_send_buf, session->_send_buf_size, 0);
            if (n == -1)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    return -1;
                }
            }
            else if (n == session->_send_buf_size)
            {
                session->_send_buf_size = 0;
                free(session->_send_buf);
                session->_send_buf = NULL;
            }
            else if (n > 0)
            {
                session->_send_buf_size -= n;
                session->_send_buf = realloc(session->_send_buf, session->_send_buf_size);

                if (session->_send_buf == NULL)
                {
                    return -1;
                }
            }
        }
    }

    if (epoll_ctl(server->epoll_fd, (closed ? EPOLL_CTL_DEL : EPOLL_CTL_MOD), event_in->data.fd, (closed ? NULL : &event)) == -1)
    {
        return -1;
    }

    return 0;
}

/// Wait for a maximum of `timeout_ms` milliseconds and handle any events that occur once.
int httpc_server_await_io(struct httpc_server_t *restrict server, int timeout_ms)
{
    if (server == NULL)
    {
        return -1;
    }

    if (server->events == NULL)
    {
        server->events_size = 16;
        server->events = calloc(server->events_size, sizeof(struct epoll_event));

        if (server->events == NULL)
        {
            return -1;
        }
    }

    int n_ready = epoll_wait(server->epoll_fd, server->events, server->events_size, timeout_ms);
    if (n_ready == -1)
    {
        return -1;
    }

    for (int ix = 0; ix < n_ready; ix++)
    {
        fprintf(stdout, "event: %d\n", server->events[ix].data.fd);

        struct epoll_event event = server->events[ix];
        bool is_listen_fd = event.data.fd == server->listen_fd;

        if (event.events & EPOLLERR)
        {
            if (is_listen_fd)
            {
                return -1;
            }
            else
            {
                close(event.data.fd);
                continue;
            }
        }

        if (is_listen_fd)
        {
            httpc_server_accept(server);
        }
        else
        {
            httpc_server_handle_epoll_event(server, &event);
        }
    }

    if (n_ready == server->events_size)
    {
        server->events_size = server->events_size << 1;
        server->events = realloc(server->events, server->events_size * sizeof(struct epoll_event));

        if (server->events == NULL)
        {
            return -1;
        }
    }

    return 0;
}

struct httpc_route_t httpc_route(const char *path, httpc_route_callback_t callback)
{
    struct httpc_route_t route = {0};

    route.path = path;
    route.callback = callback;

    return route;
}

int httpc_invoke_route_handlers(struct httpc_server_t *server, struct httpc_route_t *routes, size_t routes_size)
{
    return -1;
}
