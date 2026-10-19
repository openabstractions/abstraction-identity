#include "legacy_linux_uapi.h"
#include "../../src/runtime_selection_linux.h"
#include <cstdarg>
#include <dirent.h>
#include <iostream>
#include <stdexcept>

using namespace abstraction::ipc_internal;
static int refused_errno=ENOSYS,clone_calls=0;
static void require(bool condition,const char* message) {
    if(!condition)throw std::runtime_error(message);
}
extern "C" long __wrap_syscall(long number,...) noexcept {
    require(number==linux_selection::clone3_number,"unexpected syscall/fallback");
    va_list arguments;va_start(arguments,number);
    const auto* options=va_arg(arguments,const linux_selection::CloneArgsV0*);
    const auto size=va_arg(arguments,size_t);va_end(arguments);
    require(size==64 && options->flags==CLONE_PIDFD && options->pidfd &&
        options->exit_signal==SIGCHLD,"clone3 atomic pidfd arguments");
    require(!options->child_tid && !options->parent_tid && !options->stack &&
        !options->stack_size && !options->tls,"unused clone3 fields");
    ++clone_calls;errno=refused_errno;return -1;
}
static size_t descriptors() {
    DIR* directory=::opendir("/proc/self/fd");require(directory,"own descriptor listing");
    size_t count=0;while(::readdir(directory))++count;
    ::closedir(directory);return count;
}
int main() {
    for(int error:{ENOSYS,EPERM,EACCES,EINVAL}) {
        const auto before=descriptors();refused_errno=error;clone_calls=0;
        std::string output;int exit_code=-1;
        const auto status=linux_selection::run_owned(output,exit_code,
            abstraction::local_stream::Clock::now()+std::chrono::seconds(1),nullptr,"/not-executed",{});
        require(status==OA_IPC_PROOF_UNAVAILABLE,"clone3 refusal must fail closed");
        require(clone_calls==1 && descriptors()==before,"single clone3 attempt/descriptor cleanup");
        std::cout<<"clone3 errno "<<error<<": proof unavailable, no fallback, descriptors closed\n";
    }
}
