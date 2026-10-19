//go:build darwin && cgo

package identity

/*
#cgo LDFLAGS: -lbsm
#include <mach/mach.h>
#include <mach/task_info.h>
#include <bsm/libbsm.h>

static kern_return_t oa_self_audit_session(unsigned int *session) {
	audit_token_t token;
	mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
	kern_return_t result = task_info(mach_task_self(), TASK_AUDIT_TOKEN,
		(task_info_t)&token, &count);
	if (result == KERN_SUCCESS && count == TASK_AUDIT_TOKEN_COUNT) {
		*session = audit_token_to_asid(token);
		return KERN_SUCCESS;
	}
	return result == KERN_SUCCESS ? KERN_FAILURE : result;
}
*/
import "C"

import (
	"fmt"
	"os"
)

// Effective credentials retain their existing meaning. The audit session is
// read from this task's kernel token, independently of process group/session IDs.
func self() (User, error) {
	var session C.uint
	status := C.oa_self_audit_session(&session)
	if status != C.KERN_SUCCESS || session == 0 {
		return User{}, fmt.Errorf("%w: current task audit session status %d", ErrNotProven, int(status))
	}
	return User{Kind: "posix", UID: os.Geteuid(), GID: os.Getegid(), AuditSessionID: uint32(session)}, nil
}
