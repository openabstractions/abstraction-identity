#pragma once
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <sddl.h>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

namespace abstraction::ipc {
namespace process_detail {
struct close_token { void operator()(void* token) const noexcept { CloseHandle(token); } };
struct free_sid_text { void operator()(char* text) const noexcept { LocalFree(text); } };
}

// Local process identity for selecting its user namespace. OpenProcessToken
// binds this to the process even when the calling thread is impersonating.
inline std::string process_user_sid() {
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token))
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "OpenProcessToken");
    std::unique_ptr<void, process_detail::close_token> token(raw_token);
    DWORD size = 0;
    if (GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size))
        throw std::system_error(ERROR_INVALID_DATA, std::system_category(), "TokenUser size");
    const DWORD error = GetLastError();
    if (error != ERROR_INSUFFICIENT_BUFFER)
        throw std::system_error(static_cast<int>(error), std::system_category(), "TokenUser size");
    if (size < sizeof(TOKEN_USER))
        throw std::system_error(ERROR_INVALID_DATA, std::system_category(), "TokenUser size");
    std::vector<unsigned char> storage(size);
    if (!GetTokenInformation(token.get(), TokenUser, storage.data(), size, &size))
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "TokenUser");
    const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
    char* raw_text = nullptr;
    if (!ConvertSidToStringSidA(user->User.Sid, &raw_text))
        throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "ConvertSidToStringSid");
    std::unique_ptr<char, process_detail::free_sid_text> text(raw_text);
    return std::string(text.get());
}
}
#endif
