//go:build darwin && cgo

#include "started_process_native.h"
#include <mach/mach.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct oa_started_process { mach_port_t task; audit_token_t token; };

static oa_xpc_status token_check(oa_started_process *p, int32_t *detail) {
  if (!p || !detail) return OA_XPC_INVALID_ARGUMENT;
  audit_token_t now = {0}; mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  kern_return_t k = task_info(p->task, TASK_AUDIT_TOKEN, (task_info_t)&now, &count);
  *detail = k;
  /* This private right already passed this fixed flavor/count at capture.
     XNU task_info also returns INVALID_ARGUMENT for a now-inactive task. */
  if (k == MACH_SEND_INVALID_DEST || k == KERN_INVALID_TASK || k == KERN_INVALID_ARGUMENT) return OA_XPC_OCCURRENCE_ENDED;
  if (k != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT) return OA_XPC_SYSTEM;
  if (memcmp(&now, &p->token, sizeof(now))) return OA_XPC_OCCURRENCE_ENDED;
  return OA_XPC_OK;
}
static oa_xpc_status security_status(OSStatus s, int32_t *detail) {
  *detail = s;
  if (!s) return OA_XPC_OK;
  return s == errSecCSNoSuchCode ? OA_XPC_OCCURRENCE_ENDED : OA_XPC_SYSTEM;
}
oa_xpc_status oa_started_process_code(oa_started_process *p, SecCodeRef *out, int32_t *detail) {
  if (!out || !detail) return OA_XPC_INVALID_ARGUMENT;
  *out = NULL; oa_xpc_status result = token_check(p, detail); if (result) return result;
  CFDataRef audit = CFDataCreate(NULL, (const UInt8 *)&p->token, sizeof(p->token));
  if (!audit) { *detail = errSecAllocate; return OA_XPC_SYSTEM; }
  const void *key = kSecGuestAttributeAudit, *value = audit;
  CFDictionaryRef attrs = CFDictionaryCreate(NULL, &key, &value, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFRelease(audit);
  if (!attrs) { *detail = errSecAllocate; return OA_XPC_SYSTEM; }
  SecCodeRef code = NULL;
  result = security_status(SecCodeCopyGuestWithAttributes(NULL, attrs, 0, &code), detail); CFRelease(attrs);
  if (!result && !code) { *detail = errSecInternalComponent; result = OA_XPC_SYSTEM; }
  if (!result) result = security_status(SecCodeCheckValidity(code, kSecCSNoNetworkAccess, NULL), detail);
  if (!result) result = token_check(p, detail);
  if (result) { if (code) CFRelease(code); return result; }
  *out = code; return OA_XPC_OK;
}
oa_xpc_status oa_started_process_check(oa_started_process *p, int32_t *detail) {
  SecCodeRef code = NULL; oa_xpc_status result = oa_started_process_code(p, &code, detail);
  if (code) CFRelease(code); return result;
}
void oa_started_process_free(oa_started_process *p) {
  if (p) { if (p->task) mach_port_deallocate(mach_task_self(), p->task); free(p); }
}
oa_xpc_status oa_started_process_create(int32_t pid, oa_started_process **out, oa_started_identity *info, int32_t *detail) {
  if (!out || !info || !detail || pid <= 0) return OA_XPC_INVALID_ARGUMENT;
  *out = NULL; *detail = 0; memset(info, 0, sizeof(*info));
  struct proc_bsdinfo b = {0};
  if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &b, sizeof(b)) != sizeof(b) || b.pbi_ppid != getpid()) return OA_XPC_UNTRUSTED;
  oa_started_process *p = calloc(1, sizeof(*p)); if (!p) { *detail = errSecAllocate; return OA_XPC_SYSTEM; }
  kern_return_t k = task_name_for_pid(mach_task_self(), pid, &p->task);
  if (k) { *detail = k; oa_started_process_free(p); return OA_XPC_SYSTEM; }
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  k = task_info(p->task, TASK_AUDIT_TOKEN, (task_info_t)&p->token, &count);
  if (k || count != TASK_AUDIT_TOKEN_COUNT) { *detail = k; oa_started_process_free(p); return OA_XPC_SYSTEM; }
  if (audit_token_to_pid(p->token) != pid) { oa_started_process_free(p); return OA_XPC_UNTRUSTED; }
  SecCodeRef code = NULL; oa_xpc_status result = oa_started_process_code(p, &code, detail);
  if (result) { oa_started_process_free(p); return result; }
  CFDictionaryRef signing = NULL; OSStatus s = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &signing); CFRelease(code);
  if (s || !signing) { if (signing) CFRelease(signing); *detail = s ?: errSecInternalComponent; oa_started_process_free(p); return OA_XPC_SYSTEM; }
  CFTypeRef path = CFDictionaryGetValue(signing, kSecCodeInfoMainExecutable);
  int gotPath = path && CFGetTypeID(path) == CFURLGetTypeID() && CFURLGetFileSystemRepresentation((CFURLRef)path, true, (UInt8 *)info->path, sizeof(info->path));
  CFRelease(signing);
  result = token_check(p, detail);
  if (result || !gotPath || proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &b, sizeof(b)) != sizeof(b) || b.pbi_ppid != getpid()) { oa_started_process_free(p); return result ?: OA_XPC_UNTRUSTED; }
  info->pid = pid; info->uid = audit_token_to_euid(p->token); info->gid = audit_token_to_egid(p->token);
  info->generation = (uint32_t)audit_token_to_pidversion(p->token); info->audit_session = audit_token_to_asid(p->token);
  *out = p; return OA_XPC_OK;
}
oa_xpc_status oa_started_process_retain(oa_started_process *p, oa_started_process **out, int32_t *detail) {
  if (!out) return OA_XPC_INVALID_ARGUMENT; *out = NULL;
  oa_xpc_status result = oa_started_process_check(p, detail); if (result) return result;
  oa_started_process *copy = calloc(1, sizeof(*copy)); if (!copy) { *detail = errSecAllocate; return OA_XPC_SYSTEM; }
  kern_return_t k = mach_port_mod_refs(mach_task_self(), p->task, MACH_PORT_RIGHT_SEND, 1);
  if (k) { *detail = k; free(copy); return OA_XPC_SYSTEM; }
  *copy = *p; result = oa_started_process_check(copy, detail);
  if (result) { oa_started_process_free(copy); return result; } *out = copy; return OA_XPC_OK;
}
oa_xpc_status oa_started_process_request_code(oa_started_process *p, oa_xpc_request *request, SecCodeRef *out, int32_t *detail) {
  if (!out || !request || !detail) return OA_XPC_INVALID_ARGUMENT; *out = NULL;
  oa_xpc_status result = oa_started_process_check(p, detail); if (result) return result;
  oa_xpc_identity sender = {0}; result = oa_xpc_request_identity(request, &sender); if (result) return result;
  if (!sender.connection_principal_message_coherent || sender.connection_pid != audit_token_to_pid(p->token) || sender.connection_euid != audit_token_to_euid(p->token) || sender.connection_egid != audit_token_to_egid(p->token)) return OA_XPC_UNTRUSTED;
  oa_xpc_process *message = NULL; result = oa_xpc_request_retain_process(request, &message, detail); if (result) return result;
  SecCodeRef code = (SecCodeRef)oa_xpc_process_sealed_resource_code(message);
  if (code) CFRetain(code); oa_xpc_process_free(message);
  if (!code) { *detail = errSecInternalComponent; return OA_XPC_SYSTEM; }
  result = oa_started_process_check(p, detail);
  if (!result && !oa_xpc_request_active(request)) result = OA_XPC_CLOSED;
  if (result) { CFRelease(code); return result; } *out = code; return OA_XPC_OK;
}
