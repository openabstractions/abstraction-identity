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
typedef struct oa_ipc_cancellation oa_ipc_cancellation;
typedef struct oa_ipc_runtime_selection oa_ipc_runtime_selection;
typedef int32_t oa_ipc_status;
enum { OA_IPC_OK = 0, OA_IPC_TIMEOUT = 1, OA_IPC_DISCONNECTED = 2,
       OA_IPC_IO_ERROR = 3, OA_IPC_INVALID_ARGUMENT = 4,
       OA_IPC_NO_MEMORY = 5, OA_IPC_INTERNAL_ERROR = 6, OA_IPC_CANCELLED = 7,
       OA_IPC_UNTRUSTED = 8, OA_IPC_PROOF_UNAVAILABLE = 9 };
/* ABI version 1: shared native client primitives and local bootstrap. */
OA_IPC_API uint32_t oa_ipc_version(void);
/* Additive ABI-1 bootstrap extension; no connection or service activation.
   required receives byte size INCLUDING trailing NUL. Query with NULL,0.
   On success a supplied buffer contains that NUL-terminated endpoint; the
   caller owns all memory. Insufficient capacity returns INVALID_ARGUMENT and
   leaves buffer untouched, with required updated. Other failures set required
   to zero. Nonzero capacity requires buffer; required must be non-NULL.
   Each call observes current environment/process identity independently; if
   configuration changes between query and copy, retry using the new size.
   Keep environment mutation synchronized with callers. */
OA_IPC_API oa_ipc_status oa_ipc_runtime_endpoint(char* buffer, size_t capacity,
                                               size_t* required);
/* Establish ONE monotonic deadline, consumed by connect and every later I/O.
   endpoint is an explicit byte span (no embedded NUL). Windows accepts local
   ASCII named-pipe paths only; POSIX accepts Unix socket filesystem paths.
   On failure *out is NULL. timeout_ms=0 expires immediately. */
OA_IPC_API oa_ipc_status oa_ipc_open(const char* endpoint, size_t length,
                                    uint32_t timeout_ms, oa_ipc_connection** out);
/* Additive ABI-1 cancellation extension. A signal is monotonic and may be
   shared by multiple connections. Signal is idempotent and thread-safe.
   Release must not race calls using the same cancellation handle. Connections
   retain the native signal independently once open_cancelable returns.
   NULL signals mean uncancelable. Waiting cancellation does not cancel work
   already accepted by a peer; reconcile uncertain submissions explicitly. */
OA_IPC_API oa_ipc_status oa_ipc_cancellation_create(oa_ipc_cancellation** out);
OA_IPC_API void oa_ipc_cancellation_signal(oa_ipc_cancellation*);
OA_IPC_API void oa_ipc_cancellation_release(oa_ipc_cancellation*);
OA_IPC_API oa_ipc_status oa_ipc_open_cancelable(const char* endpoint, size_t length,
    uint32_t timeout_ms, oa_ipc_cancellation*, oa_ipc_connection** out);
/* Additive ABI-1 verified-open extension. Independent caller/installation
   evidence; never derive it from a server's response or provider identifier.
   principal is a Windows SID (kind=1) or decimal POSIX uid (kind=2).
   program is the absolute executable image path (UTF-8 on Windows, filesystem
   bytes on POSIX). Byte spans exclude NUL; embedded NUL is refused. Windows
   drive-absolute paths use ordinal case-insensitive comparison. POSIX paths
   compare exactly. Paths describe OS process identity, not signed code.
   Version 1 requires struct_size=sizeof(oa_ipc_server_expectation), version=1.
   Input spans are copied during open and need only remain valid for that call.
   A Windows retained process handle binds PID, creation time, image and primary
   token SID. Linux requires SO_PEERPIDFD and rechecks the retained image.
   macOS/unsupported kernels return PROOF_UNAVAILABLE. No weaker fallback.
   On refusal *out=NULL and no application byte is sent. Verified connections
   retain/recheck evidence before I/O and after reads, within the same waiting
   budget. Existing open functions retain their unverified compatibility mode. */
enum { OA_IPC_PRINCIPAL_WINDOWS_SID = 1, OA_IPC_PRINCIPAL_POSIX_UID = 2 };
typedef struct oa_ipc_server_expectation {
    uint32_t struct_size;
    uint32_t version;
    uint32_t principal_kind;
    uint32_t reserved;
    const char* principal;
    size_t principal_length;
    const char* program;
    size_t program_length;
} oa_ipc_server_expectation;
/* Select independent installed-runtime identity, without connecting or activating.
   The returned immutable snapshot owns its strings. Its expectation remains valid
   until release and may be passed to open_verified, which copies it.
   Windows reads the exact registered MSI product under the current account;
   Linux reads the loaded user runtime unit through a bounded native manager
   query and selects its executable/current uid. Missing/ambiguous installation
   is UNTRUSTED. Unsupported platform facilities are PROOF_UNAVAILABLE.
   No endpoint environment override supplies trust.
   Cancellation/deadline are checked around synchronous OS metadata calls; those
   native calls cannot be interrupted individually. Failure sets *out=NULL. */
OA_IPC_API oa_ipc_status oa_ipc_select_runtime(uint32_t timeout_ms,
    oa_ipc_cancellation*, oa_ipc_runtime_selection** out);
OA_IPC_API const oa_ipc_server_expectation* oa_ipc_selected_server(
    const oa_ipc_runtime_selection*);
OA_IPC_API void oa_ipc_runtime_selection_release(oa_ipc_runtime_selection*);
OA_IPC_API oa_ipc_status oa_ipc_open_verified(const char* endpoint, size_t length,
    uint32_t timeout_ms, oa_ipc_cancellation*,
    const oa_ipc_server_expectation*, oa_ipc_connection** out);

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
