#include "inject.h"
#include "../../src/fileid_private.cpp"
#include <cstdio>

extern "C" int oa_probe_query(int, struct statfs*);
extern "C" void oa_probe_event(int);
extern "C" void oa_probe_startup();

namespace {
struct ModuleLifetime { ~ModuleLifetime() { oa_probe_event(1); } } module_lifetime;
}

extern "C" int oa_probe_fstatfs(int fd, struct statfs* result) {
    return oa_probe_query(fd, result);
}

extern "C" int oa_probe_volume(int fd, char* error, size_t size) {
    static const bool seam=[] {
        abstraction::fileid::testing::worker_starting=oa_probe_startup;
        return true;
    }();
    (void)seam;
    try {
        abstraction::fileid::volume_local(fd, "owned local probe");
        return 0;
    } catch (const std::exception& e) {
        std::snprintf(error, size, "%s", e.what());
        return 1;
    }
}
