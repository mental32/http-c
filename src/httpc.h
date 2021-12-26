#ifndef HTTPC_H
#define HTTPC_H

#include <stdint.h>  // for uint8_t
#include <stdlib.h>  // for size_t
#include <stdbool.h> // for bool

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

struct httpc_server_t
{
    int epoll_fd;
    int listen_fd;

    struct epoll_event *events;
    size_t events_size;

    struct httpc_session_t *sessions;
    size_t sessions_size;

    struct httpc_request_t *pending_requests;
    size_t pending_requests_size;
};

enum httpc_status_t
{
    HTTPC_STATUS_OK = 200,
    HTTPC_STATUS_NOT_FOUND = 404,
};

enum httpc_response_body_type_t
{
    HTTPC_RESPONSE_BODY_TYPE_STRING = 0,
    HTTPC_RESPONSE_BODY_TYPE_STRING_VIEW,
};

struct httpc_response_body_t
{
    enum httpc_response_body_type_t type;
    union
    {
        char *string;
        struct
        {
            char *data;
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

typedef struct httpc_response_t (*httpc_route_callback_t)(struct httpc_callback_args_t *);

struct httpc_route_t
{
    const char *path;
    httpc_route_callback_t callback;
};

int httpc_server_new(int port, struct httpc_server_t *server);
void httpc_server_close(struct httpc_server_t *server);

struct httpc_route_t httpc_route(const char *path, httpc_route_callback_t callback);

int httpc_server_await_io(struct httpc_server_t *server, int epoll_timeout_ms);
int httpc_invoke_route_handlers(struct httpc_server_t *server, struct httpc_route_t *routes, size_t routes_size);

struct httpc_response_body_t httpc_response_string_owned(const char *restrict buf)
{
    struct httpc_response_body_t body = {0};

    body.type = HTTPC_RESPONSE_BODY_TYPE_STRING;
    body.string = buf;

    return body;
}

#endif // HTTPC_H
