#include <abstraction/ipc/client.h>
#include <stdio.h>
#include <string.h>

extern const char* fixture_begin(int respond);
extern size_t fixture_finish(void);
extern const char* fixture_principal(void);
extern const char* fixture_program(void);
extern size_t fixture_handles(void);
extern void fixture_cancel_after(oa_ipc_cancellation* cancellation);
extern void fixture_cancel_join(void);

#define CHECK(condition) do { if (!(condition)) { fprintf(stderr,"failed at line %d: %s\n",__LINE__,#condition); return 1; } } while(0)

int main(void) {
    oa_ipc_server_expectation expected = {0};
    expected.struct_size = sizeof(expected);
    expected.version = 1;
#ifdef _WIN32
    expected.principal_kind = OA_IPC_PRINCIPAL_WINDOWS_SID;
#else
    expected.principal_kind = OA_IPC_PRINCIPAL_POSIX_UID;
#endif
    expected.principal = fixture_principal();
    expected.principal_length = strlen(expected.principal);
    expected.program = fixture_program();
    expected.program_length = strlen(expected.program);
    oa_ipc_connection* connection = NULL;
    oa_ipc_cancellation* cancel = NULL;
    CHECK(oa_ipc_cancellation_create(&cancel) == OA_IPC_OK);
    oa_ipc_cancellation_signal(cancel);
    CHECK(oa_ipc_open_verified("absent",6,1000,cancel,&expected,&connection) == OA_IPC_CANCELLED);
    CHECK(connection == NULL);
    oa_ipc_cancellation_release(cancel);
    expected.version = 2;
    CHECK(oa_ipc_open_verified("absent",6,1000,NULL,&expected,&connection) == OA_IPC_INVALID_ARGUMENT);
    expected.version = 1;

    const char* endpoint = fixture_begin(1);
    char copied_program[32769];
    memcpy(copied_program,expected.program,expected.program_length);
    oa_ipc_server_expectation temporary = expected;
    temporary.program = copied_program;
    oa_ipc_status status = oa_ipc_open_verified(endpoint,strlen(endpoint),2000,NULL,&temporary,&connection);
    memset(copied_program,'x',expected.program_length); /* open copied its evidence */
#if !defined(_WIN32) && !defined(__linux__)
    CHECK(status == OA_IPC_PROOF_UNAVAILABLE && connection == NULL);
    CHECK(fixture_finish() == 0);
    puts("PASS: unsupported server proof explicitly refused");
    return 0;
#else
    CHECK(status == OA_IPC_OK && connection != NULL);
    size_t moved = 0;
    CHECK(oa_ipc_write(connection,"payload",7,&moved) == OA_IPC_OK && moved == 7);
    char reply[7]; size_t used = 0;
    while (used < sizeof reply) {
        CHECK(oa_ipc_read(connection,reply+used,sizeof(reply)-used,&moved) == OA_IPC_OK && moved > 0);
        used += moved;
    }
    CHECK(memcmp(reply,"payload",7) == 0);
    oa_ipc_close(connection);
    CHECK(fixture_finish() == 7);

    /* After warmup, repeated refusals and ordinary closure release retained
       process handles/pidfds as well as connection and fixture handles. */
    const size_t handles = fixture_handles();
    for (int i=0; i<12; ++i) {
        oa_ipc_server_expectation wrong = expected;
        if (i%2 == 0) {
#ifdef _WIN32
            wrong.program = "C:\\untrusted\\other.exe";
#else
            wrong.program = "/untrusted/other";
#endif
            wrong.program_length = strlen(wrong.program);
        } else {
#ifdef _WIN32
            wrong.principal = "S-1-0-0";
#else
            wrong.principal = strcmp(expected.principal,"0") == 0 ? "1" : "0";
#endif
            wrong.principal_length = strlen(wrong.principal);
        }
        endpoint = fixture_begin(0);
        connection = NULL;
        CHECK(oa_ipc_open_verified(endpoint,strlen(endpoint),1000,NULL,&wrong,&connection) == OA_IPC_UNTRUSTED);
        CHECK(connection == NULL);
        CHECK(fixture_finish() == 0);
    }
    CHECK(fixture_handles() == handles);

    /* Cancel a waiting read while the peer is alive and quiet. Work cancellation
       is absent from this byte-transport API. Closing releases the native guard. */
    CHECK(oa_ipc_cancellation_create(&cancel) == OA_IPC_OK);
    endpoint = fixture_begin(0);
    CHECK(oa_ipc_open_verified(endpoint,strlen(endpoint),1000,cancel,&expected,&connection) == OA_IPC_OK);
    CHECK(oa_ipc_write(connection,"payload",7,&moved) == OA_IPC_OK);
    fixture_cancel_after(cancel);
    CHECK(oa_ipc_read(connection,reply,sizeof reply,&moved) == OA_IPC_CANCELLED && moved == 0);
    fixture_cancel_join();
    oa_ipc_close(connection);
    oa_ipc_cancellation_release(cancel);
    CHECK(fixture_finish() == 7);
    CHECK(fixture_handles() == handles);

    endpoint = fixture_begin(0);
    CHECK(oa_ipc_open_verified(endpoint,strlen(endpoint),80,NULL,&expected,&connection) == OA_IPC_OK);
    CHECK(oa_ipc_read(connection,reply,sizeof reply,&moved) == OA_IPC_TIMEOUT && moved == 0);
    oa_ipc_close(connection);
    CHECK(fixture_finish() == 0);
    CHECK(fixture_handles() == handles);
    puts("PASS: installed C ABI verified open, exact bytes, zero-byte refusals, cancellation, deadline, retained-handle cleanup");
    return 0;
#endif
}
