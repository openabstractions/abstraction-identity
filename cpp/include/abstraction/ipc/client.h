#ifndef ABSTRACTION_IPC_CLIENT_H
#define ABSTRACTION_IPC_CLIENT_H
#include <stddef.h>
#include <stdint.h>
#if defined(_WIN32) && defined(ABSTRACTION_IPC_SHARED)
# if defined(ABSTRACTION_IPC_BUILD)
#  define OA_IPC_API __declspec(dllexport)
# else
#  define OA_IPC_API __declspec(dllimport)
# endif
#else
# define OA_IPC_API
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct oa_ipc_connection oa_ipc_connection;
typedef int32_t oa_ipc_status;
enum { OA_IPC_OK = 0, OA_IPC_TIMEOUT = 1, OA_IPC_DISCONNECTED = 2,
       OA_IPC_IO_ERROR = 3, OA_IPC_INVALID_ARGUMENT = 4,
       OA_IPC_NO_MEMORY = 5, OA_IPC_INTERNAL_ERROR = 6 };
/* ABI version 1. No framing, discovery or server functions. */
OA_IPC_API uint32_t oa_ipc_version(void);
/* Establish ONE monotonic deadline, consumed by connect and every later I/O.
   endpoint is an explicit byte span (no embedded NUL). Windows accepts local
   ASCII named-pipe paths only; POSIX accepts Unix socket filesystem paths.
   On failure *out is NULL. timeout_ms=0 expires immediately. */
OA_IPC_API oa_ipc_status oa_ipc_open(const char* endpoint, size_t length,
                                    uint32_t timeout_ms, oa_ipc_connection** out);
/* Write all bytes or return failure and the confirmed completed prefix.
   On cancellation an additional prefix may have reached the peer; the count
   is not proof of the total received by it. Never retry
   the whole message after a partial write. Empty writes permit NULL bytes.
   I/O failure is terminal. A connection must not be used concurrently. */
OA_IPC_API oa_ipc_status oa_ipc_write(oa_ipc_connection*, const void* bytes,
                                     size_t length, size_t* transferred);
/* Read at least one byte on success. capacity must be positive; buffer and
   transferred are caller-owned. EOF is DISCONNECTED. Invalid arguments do not
   perform I/O. All functions catch C++ exceptions before returning to C. */
OA_IPC_API oa_ipc_status oa_ipc_read(oa_ipc_connection*, void* buffer,
                                    size_t capacity, size_t* transferred);
/* NULL is allowed. Frees in the allocating library; other uses of the handle
   after close, or pointers not returned by open, are invalid. */
OA_IPC_API void oa_ipc_close(oa_ipc_connection*);
#ifdef __cplusplus
}
#endif
#endif
