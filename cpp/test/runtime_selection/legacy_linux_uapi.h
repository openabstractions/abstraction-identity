#pragma once
// Reproduce the manylinux 2.28 declaration gaps while using the native kernel.
#define clone_args oa_test_later_clone_args
#include <linux/sched.h>
#undef clone_args
#undef CLONE_ARGS_SIZE_VER0
#undef CLONE_ARGS_SIZE_VER1
#undef CLONE_ARGS_SIZE_VER2
#include <sys/syscall.h>
#undef SYS_clone3
#undef __NR_clone3
#define P_PIDFD OA_TEST_LATER_PIDFD
#include <sys/wait.h>
#undef P_PIDFD
