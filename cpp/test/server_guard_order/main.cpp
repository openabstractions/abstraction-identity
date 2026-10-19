// PT-5a review: the Windows server guard checks the server's account before it
// opens any file the server names, and opens only local drive paths. The
// counter is the private test hook incremented by every identity open.
#include <abstraction/ipc/client.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#include "../../src/server_guard.h"

using abstraction::ipc_internal::ServerGuard;
using abstraction::ipc_internal::server_guard_test_opens;

#define CHECK(condition) do { if (!(condition)) { std::fprintf(stderr, "failed at line %d: %s\n", __LINE__, #condition); return 1; } } while (0)

int main() {
    char program[MAX_PATH * 4];
    const DWORD length = ::GetModuleFileNameA(nullptr, program, sizeof program);
    CHECK(length > 0 && length < sizeof program);

    const std::string path = "\\\\.\\pipe\\oa-server-guard-order-" + std::to_string(::GetCurrentProcessId());
    const std::wstring wide(path.begin(), path.end());
    HANDLE listener = ::CreateNamedPipeW(wide.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 1024, 1024, 0, nullptr);
    CHECK(listener != INVALID_HANDLE_VALUE);
    std::thread worker([listener] { ::ConnectNamedPipe(listener, nullptr); });

    oa_ipc_server_expectation wrong{};
    wrong.struct_size = sizeof wrong;
    wrong.version = 1;
    wrong.principal_kind = OA_IPC_PRINCIPAL_WINDOWS_SID;
    wrong.principal = "S-1-0-0";
    wrong.principal_length = std::strlen(wrong.principal);
    wrong.program = program;
    wrong.program_length = length;
    oa_ipc_connection* connection = nullptr;
    server_guard_test_opens = 0;
    const oa_ipc_status status = oa_ipc_open_verified(path.c_str(), path.size(), 1000, nullptr, &wrong, &connection);
    worker.join();
    ::DisconnectNamedPipe(listener);
    ::CloseHandle(listener);
    CHECK(status == OA_IPC_UNTRUSTED && connection == nullptr);
    CHECK(server_guard_test_opens == 0);

    CHECK(!ServerGuard::local_image(L"\\\\host\\share\\x.exe"));
    CHECK(!ServerGuard::local_image(L"\\\\?\\UNC\\host\\share\\x.exe"));
    CHECK(!ServerGuard::local_image(L"\\\\host@SSL\\DavWWWRoot\\x.exe"));
    CHECK(!ServerGuard::local_image(L"\\\\?\\C:\\x.exe"));
    CHECK(!ServerGuard::local_image(L"x.exe"));
    std::wstring self(program, program + length);
    CHECK(ServerGuard::local_image(self));
    CHECK(server_guard_test_opens == 0);
    std::puts("PASS: wrong principal refused before any image open; non-local image names refused without an open");
    return 0;
}
#else
int main() {
    std::puts("SKIP: Windows server guard ordering");
    return 0;
}
#endif
