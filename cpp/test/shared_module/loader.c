#include <dlfcn.h>
#include <stdio.h>

int main(void) {
    void* module = dlopen(MODULE_PATH, RTLD_NOW | RTLD_LOCAL);
    if (!module) {
        fprintf(stderr, "dlopen %s: %s\n", MODULE_PATH, dlerror());
        return 1;
    }
    unsigned (*version)(void) = (unsigned (*)(void))dlsym(module, "ipc_shared_module_version");
    if (!version) {
        fprintf(stderr, "dlsym: %s\n", dlerror());
        return 1;
    }
    unsigned got = version();
    dlclose(module);
    if (got != 1) {
        fprintf(stderr, "module reports IPC version %u, want 1\n", got);
        return 1;
    }
    printf("shared module loaded the static IPC package, version %u\n", got);
    return 0;
}
