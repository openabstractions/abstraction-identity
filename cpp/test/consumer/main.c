#include <abstraction/ipc/client.h>
#include <stdio.h>
#include <string.h>
const char* fixture_start(void);
int fixture_finish(void);
static int failures;
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); ++failures; } } while (0)
int main(void) {
    oa_ipc_connection* c = NULL;
    size_t moved = 42;
    unsigned char data[] = {0, 10, 255, 65, 0, 13, 10};
    unsigned char result[sizeof data];
    size_t total = 0;
    CHECK(oa_ipc_version() == 1);
    CHECK(oa_ipc_open(NULL, 0, 10, &c) == OA_IPC_INVALID_ARGUMENT && c == NULL);
    CHECK(oa_ipc_open("bad", 3, 10, NULL) == OA_IPC_INVALID_ARGUMENT);
    CHECK(oa_ipc_open("a\0b", 3, 10, &c) == OA_IPC_INVALID_ARGUMENT && c == NULL);
    CHECK(oa_ipc_write(NULL, data, sizeof data, &moved) == OA_IPC_INVALID_ARGUMENT && moved == 0);
    CHECK(oa_ipc_read(NULL, result, sizeof result, &moved) == OA_IPC_INVALID_ARGUMENT && moved == 0);
    CHECK(oa_ipc_open("missing-local-endpoint", sizeof "missing-local-endpoint" - 1, 10, &c) == OA_IPC_IO_ERROR && c == NULL);
    oa_ipc_close(NULL);
    {
        const char* endpoint = fixture_start();
        CHECK(oa_ipc_open(endpoint, strlen(endpoint), 0, &c) == OA_IPC_TIMEOUT && c == NULL);
        CHECK(oa_ipc_open(endpoint, strlen(endpoint), 2000, &c) == OA_IPC_OK && c != NULL);
    }
    CHECK(oa_ipc_write(c, data, sizeof data, NULL) == OA_IPC_INVALID_ARGUMENT);
    CHECK(oa_ipc_read(c, result, sizeof result, NULL) == OA_IPC_INVALID_ARGUMENT);
    CHECK(oa_ipc_write(c, NULL, 1, &moved) == OA_IPC_INVALID_ARGUMENT && moved == 0);
    CHECK(oa_ipc_read(c, NULL, 1, &moved) == OA_IPC_INVALID_ARGUMENT && moved == 0);
    CHECK(oa_ipc_read(c, result, 0, &moved) == OA_IPC_INVALID_ARGUMENT && moved == 0);
    CHECK(oa_ipc_write(c, NULL, 0, &moved) == OA_IPC_OK && moved == 0);
    CHECK(oa_ipc_write(c, data, sizeof data, &moved) == OA_IPC_OK && moved == sizeof data);
    while (total < sizeof result) {
        oa_ipc_status status = oa_ipc_read(c, result + total, 1, &moved);
        CHECK(status == OA_IPC_OK && moved == 1);
        if (status != OA_IPC_OK) break;
        total += moved;
    }
    CHECK(total == sizeof data && memcmp(data, result, sizeof data) == 0);
    CHECK(oa_ipc_write(c, "!", 1, &moved) == OA_IPC_OK);
    CHECK(oa_ipc_read(c, result, sizeof result, &moved) == OA_IPC_DISCONNECTED && moved == 0);
    oa_ipc_close(c);
    CHECK(fixture_finish());
    return failures ? 1 : 0;
}
