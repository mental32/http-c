#include <stdio.h>
#include "httpc.h"

struct httpc_response_body_t httpc_response_string_owned(const char *restrict buf)
{
    struct httpc_response_body_t body = {0};

    body.type = HTTPC_RESPONSE_BODY_TYPE_STRING;
    body.string = buf;

    return body;
}

struct httpc_response_t ticker(struct httpc_callback_args_t *args)
{
    struct httpc_response_t response = {0};
    response.status = HTTPC_STATUS_OK;

    size_t n_hit = args->context;
    args->context = n_hit + 1;

    uint8_t *buf = calloc(1024, sizeof(uint8_t));
    int n_trunc = snprintf(buf, 1024, "Hello, World! %zu\n", n_hit);

    response.body = httpc_response_string_owned(buf);

    return response;
}

int main(int argc, const char **argv)
{
    // httpc does not take any arguments, so lets report an error if any were given.
    if (argc > 1)
    {
        int n_args = argc - 1;
        char *s_args;

        if (n_args == 1)
        {
            s_args = "argument was";
        }
        else
        {
            s_args = "arguments were";
        }

        fprintf(stderr, "fatal: %d %s provided but this program does not accept any.\n", n_args, s_args);

        return EXIT_FAILURE;
    }

    struct httpc_server_t server = {0};
    if (httpc_server_new(8080, &server) != 0)
    {
        perror("fatal: failed to create server");
        return EXIT_FAILURE;
    }

    struct httpc_route_t routes[] = {
        httpc_route("/", &ticker), // note: index is already defined in string.h so just suffix our index with _r
    };

    for (;;)
    {
        if (httpc_server_await_io(&server, 1) != 0) // epoll timeout is 1 millisecond.
        {
            perror("fatal: while waiting on httpc server to handle I/O");
            httpc_server_close(&server);
            return EXIT_FAILURE;
        }

        httpc_invoke_route_handlers(&server, (struct httpc_route_t *)&routes, sizeof(routes) / sizeof(routes[0]));
    }

    httpc_server_close(&server);

    return EXIT_SUCCESS;
}
