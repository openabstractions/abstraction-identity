#include <abstraction/ipc/client.h>
#include "../../../xpc_native.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char service[128];
    snprintf(service, sizeof(service), "com.openabstractions.test.unregistered.%d", getpid());
    setenv("XPC_SERVICE_NAME", "forged.nonempty.job", 1);
    oa_xpc_listener* listener = NULL;
    oa_xpc_status status = oa_xpc_listener_open(service, 1024, &listener);
    if (status != OA_XPC_OK || !listener) {
        fprintf(stderr, "open: %s\n", oa_xpc_error_text(status));
        return 1;
    }
    oa_xpc_request* request = NULL;
    status = oa_xpc_listener_next(listener, oa_xpc_now_ns() + 2000000000ull, NULL, &request);
    oa_xpc_listener_close(listener);
    oa_xpc_listener_free(listener);
    if (request) {
        oa_xpc_request_free(request);
        fputs("unregistered listener accepted a request\n", stderr);
        return 1;
    }
    if (status != OA_XPC_CLOSED) {
        fprintf(stderr, "accept: %s\n", oa_xpc_error_text(status));
        return 1;
    }
    puts("PASS unregistered XPC listener closes and wakes accept");
    return 0;
}
