#ifndef OPENABSTRACTIONS_OA_XPC_H
#define OPENABSTRACTIONS_OA_XPC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum oa_xpc_status {
    OA_XPC_OK = 0,
    OA_XPC_CLOSED = 1,
    OA_XPC_TIMEOUT = 2,
    OA_XPC_CANCELLED = 3,
    OA_XPC_INVALID_ARGUMENT = 4,
    OA_XPC_UNTRUSTED = 5,
    OA_XPC_PROTOCOL = 6,
    OA_XPC_SYSTEM = 7,
    OA_XPC_UNAVAILABLE = 8,
    OA_XPC_CALLER_PROOF_UNMET = 9
} oa_xpc_status;

typedef struct oa_xpc_listener oa_xpc_listener;
typedef struct oa_xpc_request oa_xpc_request;
typedef struct oa_xpc_client oa_xpc_client;
typedef struct oa_xpc_cancel oa_xpc_cancel;

/* Borrowed strings remain valid until the request is freed. Connection
   credentials and message code are separate evidence sources. */
typedef struct oa_xpc_identity {
    int32_t connection_pid;
    uint32_t connection_euid;
    uint32_t connection_egid;
    uint32_t message_pid;
    uint32_t message_pidversion;
    uint32_t message_audit_session;
    const char *message_path;
    const char *signing_identifier;
    const char *team_identifier;
    const char *cdhash;
    const char *signing_status;
    uint8_t message_code_valid;
    uint8_t connection_path_matches_message;
    uint8_t connection_principal_message_coherent;
} oa_xpc_identity;

const char *oa_xpc_error_text(oa_xpc_status status);
uint64_t oa_xpc_now_ns(void);
uint8_t oa_xpc_available(void);

oa_xpc_status oa_xpc_cancel_create(oa_xpc_cancel **out);
void oa_xpc_cancel_fire(oa_xpc_cancel *cancel);
void oa_xpc_cancel_free(oa_xpc_cancel *cancel);

oa_xpc_status oa_xpc_listener_open(const char *service, size_t max_frame,
                                   oa_xpc_listener **out);
oa_xpc_status oa_xpc_listener_next(oa_xpc_listener *listener,
                                   uint64_t deadline_ns,
                                   oa_xpc_cancel *cancel,
                                   oa_xpc_request **out);
void oa_xpc_listener_close(oa_xpc_listener *listener);
void oa_xpc_listener_free(oa_xpc_listener *listener);

oa_xpc_status oa_xpc_request_bytes(oa_xpc_request *request,
                                   const void **bytes, size_t *length);
oa_xpc_status oa_xpc_request_identity(oa_xpc_request *request,
                                      oa_xpc_identity *identity);
oa_xpc_status oa_xpc_request_reply(oa_xpc_request *request,
                                   const void *bytes, size_t length);
oa_xpc_status oa_xpc_request_refuse_unmet_proof(oa_xpc_request *request,
                                                uint8_t attribute,
                                                uint8_t required);
oa_xpc_status oa_xpc_request_wait(oa_xpc_request *request,
                                  uint64_t deadline_ns,
                                  oa_xpc_cancel *cancel);
uint8_t oa_xpc_request_active(oa_xpc_request *request);
void oa_xpc_request_cancel(oa_xpc_request *request);
void oa_xpc_request_free(oa_xpc_request *request);

oa_xpc_status oa_xpc_client_open(const char *service,
                                 const char *expected_program,
                                 uint32_t expected_euid,
                                 size_t max_reply,
                                 uint64_t deadline_ns,
                                 oa_xpc_cancel *cancel,
                                 oa_xpc_client **out);
oa_xpc_status oa_xpc_client_call(oa_xpc_client *client,
                                 const void *request, size_t request_length,
                                 uint8_t one_way,
                                 uint64_t deadline_ns,
                                 oa_xpc_cancel *cancel,
                                 size_t *sent,
                                 void **reply, size_t *reply_length,
                                 uint8_t *proof_attribute,
                                 uint8_t *proof_required);
void oa_xpc_client_close(oa_xpc_client *client);
void oa_xpc_client_free(oa_xpc_client *client);
void oa_xpc_bytes_free(void *bytes);

#ifdef __cplusplus
}
#endif
#endif
