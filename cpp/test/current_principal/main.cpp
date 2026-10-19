#include <abstraction/ipc/client.h>
#include <abstraction/ipc/process.hpp>
#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

static void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

int main() {
    uint32_t kind = 99;
    size_t required = 99;
    char byte = '!';
    require(oa_ipc_version() == 1, "ABI version unchanged");
    require(oa_ipc_current_principal(nullptr, nullptr, 0, &required) == OA_IPC_INVALID_ARGUMENT && required == 0,
            "kind required before query");
    require(oa_ipc_current_principal(&kind, nullptr, 0, nullptr) == OA_IPC_INVALID_ARGUMENT && kind == 0,
            "size required before query");
    require(oa_ipc_current_principal(&kind, nullptr, 1, &required) == OA_IPC_INVALID_ARGUMENT && kind == 0 && required == 0,
            "null buffer capacity");
    require(oa_ipc_current_principal(&kind, &byte, 0, &required) == OA_IPC_INVALID_ARGUMENT && byte == '!' && required == 0,
            "zero buffer capacity");
    require(oa_ipc_current_principal(&kind, nullptr, 0, &required) == OA_IPC_OK && required > 1,
            "size query");
#ifdef _WIN32
    const auto expected = abstraction::ipc::process_user_sid();
    const uint32_t expected_kind = OA_IPC_PRINCIPAL_WINDOWS_SID;
#else
    const auto expected = std::to_string(abstraction::ipc::process_effective_uid());
    const uint32_t expected_kind = OA_IPC_PRINCIPAL_POSIX_UID;
#endif
    require(kind == expected_kind && required == expected.size() + 1, "shared native process owner");
    const auto size = required;
    std::vector<char> output(size + 2, '!');
    require(oa_ipc_current_principal(&kind, output.data() + 1, size - 1, &required) == OA_IPC_INVALID_ARGUMENT
            && kind == 0 && required == size && std::all_of(output.begin(), output.end(), [](char c) { return c == '!'; }),
            "short buffer untouched");
    for (unsigned n = 0; n < 32; ++n) {
        require(oa_ipc_current_principal(&kind, output.data() + 1, size, &required) == OA_IPC_OK,
                "bounded principal copy");
        require(kind == expected_kind && required == size && output.front() == '!' && output.back() == '!'
                && output[size] == 0 && std::string(output.data() + 1) == expected, "principal bytes and guards");
    }
#ifdef _WIN32
    // The owner reads the primary token. Anonymous thread impersonation must
    // either retain that principal or refuse metadata access, never substitute
    // a thread identity. Revert this fixture's own thread before assertions.
    require(::ImpersonateAnonymousToken(::GetCurrentThread()) != 0, "own anonymous thread fixture");
    std::fill(output.begin(), output.end(), '!');
    const auto result = oa_ipc_current_principal(&kind, output.data() + 1, size, &required);
    const bool reverted = ::RevertToSelf() != 0;
    require(reverted, "revert own thread");
    require((result == OA_IPC_OK && kind == expected_kind && required == size
                && output[size] == 0 && std::string(output.data() + 1) == expected)
            || (result == OA_IPC_IO_ERROR && kind == 0 && required == 0
                && std::all_of(output.begin(), output.end(), [](char c) { return c == '!'; })),
            "primary process identity or explicit metadata refusal");
#endif
    std::cout << "PASS current process principal kind=" << expected_kind << " bytes=" << expected.size()
              << "; ABI-1, null/size/guard/current-owner controls\n";
}
