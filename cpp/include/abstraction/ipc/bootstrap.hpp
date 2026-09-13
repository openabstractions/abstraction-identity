#pragma once
#include <cstdlib>
#include <string>
#ifdef _WIN32
#include <abstraction/ipc/process.hpp>
#endif

namespace abstraction::ipc {
// Shared language bootstrap convention. Windows identity comes from the process
// token; the explicit endpoint override remains an operator choice.
inline std::string runtime_endpoint() {
    if (const char* value = std::getenv("ABSTRACTION_RUNTIME_ENDPOINT")) {
        if (*value) return value;
    }
#ifdef _WIN32
    return std::string(R"(\\.\pipe\openabstractions-user-)") + process_user_sid() + "-runtime-v1";
#else
    if (const char* value = std::getenv("XDG_RUNTIME_DIR")) {
        if (*value) return std::string(value) + "/openabstractions-runtime-v1.sock";
    }
    const char* temporary = std::getenv("TMPDIR");
    const char* user = std::getenv("USER");
    return std::string(temporary && *temporary ? temporary : "/tmp") +
        "/openabstractions-runtime-v1-" + (user ? user : "") + ".sock";
#endif
}
}
