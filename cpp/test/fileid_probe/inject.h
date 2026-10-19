#pragma once
#ifdef __APPLE__
#include <sys/mount.h>
#else
#include <sys/vfs.h>
#endif
extern "C" int oa_probe_fstatfs(int, struct statfs*);
// Function-like substitution leaves the system's statfs type untouched.
#define fstatfs(fd, result) oa_probe_fstatfs(fd, result)
