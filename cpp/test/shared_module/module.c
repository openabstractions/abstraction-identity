#include <abstraction/ipc/client.h>

/* Calls into the archive, so the linker must place its objects in this module. */
__attribute__((visibility("default"))) unsigned ipc_shared_module_version(void) {
    return oa_ipc_version();
}
