#ifndef OA_STARTED_PROCESS_NATIVE_H
#define OA_STARTED_PROCESS_NATIVE_H
#include "sealed_resource_native.h"
typedef struct oa_started_process oa_started_process;
typedef struct oa_started_identity {
  int32_t pid;
  uint32_t uid, gid, generation, audit_session;
  char path[4096];
} oa_started_identity;
oa_xpc_status oa_started_process_create(int32_t, oa_started_process **, oa_started_identity *, int32_t *);
oa_xpc_status oa_started_process_check(oa_started_process *, int32_t *);
oa_xpc_status oa_started_process_retain(oa_started_process *, oa_started_process **, int32_t *);
void oa_started_process_free(oa_started_process *);
#ifdef __APPLE__
oa_xpc_status oa_started_process_code(oa_started_process *, SecCodeRef *, int32_t *);
oa_xpc_status oa_started_process_request_code(oa_started_process *, oa_xpc_request *, SecCodeRef *, int32_t *);
#endif
#endif
