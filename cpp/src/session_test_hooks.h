#pragma once

// Private transport seams present only in a local test build. They let the
// session test report a complete OS write together with an error, a result
// that cannot be induced reliably through a real local socket or pipe.
#ifdef ABSTRACTION_IPC_TEST_HOOKS
#include <abstraction/ipc/client.h>
#include <chrono>
#include <string>

namespace abstraction { namespace ipc_internal {
using SessionWriteHook = oa_ipc_status (*)(oa_ipc_connection*, const unsigned char*, size_t, size_t*);
using SessionOpenHook = oa_ipc_status (*)(const std::string&, std::chrono::steady_clock::time_point,
    oa_ipc_cancellation*, const oa_ipc_server_expectation*, oa_ipc_connection**);
extern OA_IPC_API SessionWriteHook session_test_write;
extern OA_IPC_API SessionOpenHook session_test_open;
}}
#endif
