# http-c

This is a short, hopefully comprehensible, HTTP server written in C intended to be used as example code for students.

Some notable characteristics about this implementation:

* The code has been written to run on Linux, using epoll (learn about select, poll, kqueue, io_uring somewhere else.)
* This is an implementation of HTTP 1.0
* This is a single-process, single-threaded, co-operative implementation, we wont be using fork, pthreads, tracing gc's nor any off-brand continouations library.
* We are using c11 (c17) not c98.
* We are not hiding any business logic behind macros or global variables.

## Requirements

* bear
* clang

## Building

Use Bear to generate a `compile_commands.json` this is used by clangd for development.

```
bear -- clang -std=c17  -I./http-c/src  -o ./httpc-server ./src/main.c
```

If you do not want to install bear or configure clangd then running the cc command which is given to the bear command will compile the example for you

## Example

```c
#include <stdio.h>
#include "httpc.h"

struct httpc_response_t index(struct httpc_request_t *req)
{
    struct httpc_response_t response = httpc_response_ok();

    size_t n_hit = (size_t)(req->context);
    req->context = (void *)(n_hit + 1);

    uint8_t *buf = calloc(1024, sizof(uint8_t));
    int n_trunc = snprintf(buf, 1024, "Hello, World! %d", n_hit);

    response->body = httpc_response_string_owned(buf);

    return response;
}

int main()
{
    struct httpc_server_t server = {0};
    if (httpc_server_new(8080, &server) != 0)
    {
        perror("fatal: failed to create server");
        return EXIT_FAILURE;
    }

    size_t hits = 0;
    httpc_server_add_route_with_context("/", &index, &hits);

    for (;;)
    {
        if (httpc_server_await_once(&server, 1) != 0) // timeout is 1 millisecond.
        {
            perror("fatal: while waiting on httpc server to handle I/O");
            httpc_server_close(&server);
            return EXIT_FAILURE;
        }
    }

    httpc_server_close(&server);

    return EXIT_SUCCESS;
}
```
