#pragma once

// Shared native verification for the C ABI. Capability/language clients supply
// independent expectations and consume the result; they do no platform lookup.
#include <abstraction/ipc/client.h>
#include "local_stream.h"
#include <limits>
#include <cstdint>
#include <vector>
#ifdef _WIN32
#include <sddl.h>
#elif defined(__linux__)
#include <poll.h>
#endif

namespace abstraction { namespace ipc_internal {

class ServerGuard {
public:
    explicit ServerGuard(const oa_ipc_server_expectation& expected)
        : principal_(expected.principal, expected.principal_length),
          program_(expected.program, expected.program_length) {}
    ServerGuard(const ServerGuard&) = delete;
    ServerGuard& operator=(const ServerGuard&) = delete;
    ~ServerGuard() {
#ifdef _WIN32
        if (process_) ::CloseHandle(process_);
#elif defined(__linux__)
        if (pidfd_ >= 0) ::close(pidfd_);
#endif
    }
    static bool valid_input(const oa_ipc_server_expectation* e) {
        if (!e || e->struct_size != sizeof(*e) || e->version != 1 || e->reserved != 0 ||
            !e->principal || !e->program || !e->principal_length || !e->program_length ||
            e->principal_length > 184 || e->program_length > 32768) return false;
        if (std::memchr(e->principal, 0, e->principal_length) || std::memchr(e->program, 0, e->program_length)) return false;
        if (e->principal_kind != OA_IPC_PRINCIPAL_WINDOWS_SID && e->principal_kind != OA_IPC_PRINCIPAL_POSIX_UID) return false;
#ifdef _WIN32
        if (e->principal_kind != OA_IPC_PRINCIPAL_WINDOWS_SID) return false;
        if (e->program_length < 3 || e->program[1] != ':' ||
            (e->program[2] != '\\' && e->program[2] != '/')) return false;
#else
        if (e->principal_kind != OA_IPC_PRINCIPAL_POSIX_UID || e->program[0] != '/') return false;
#endif
        return true;
    }

    oa_ipc_status capture(local_stream::Stream& stream) {
#ifdef _WIN32
        if (!wide(program_, image_) || !wide(principal_, sid_text_)) return OA_IPC_INVALID_ARGUMENT;
        std::replace(image_.begin(), image_.end(), L'/', L'\\');
        PSID sid = nullptr;
        if (!::ConvertStringSidToSidW(sid_text_.c_str(), &sid)) return OA_IPC_INVALID_ARGUMENT;
        struct SidOwner { PSID sid; ~SidOwner(){::LocalFree(sid);} } owned_sid{sid};
        const auto sid_length = ::GetLengthSid(sid);
        expected_sid_.assign(static_cast<unsigned char*>(sid), static_cast<unsigned char*>(sid) + sid_length);
        pipe_ = stream.native_handle();
        if (!::GetNamedPipeServerProcessId(pipe_, &pid_)) return OA_IPC_PROOF_UNAVAILABLE;
        process_ = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid_);
        if (!process_) return OA_IPC_UNTRUSTED;
        FILETIME exit{}, kernel{}, user{};
        if (!::GetProcessTimes(process_, &created_, &exit, &kernel, &user)) return OA_IPC_UNTRUSTED;
        const auto connected = stream.connected_at();
        if (::CompareFileTime(&created_, &connected) > 0) return OA_IPC_UNTRUSTED;
        std::vector<wchar_t> image(32768);
        DWORD size = static_cast<DWORD>(image.size());
        if (!::QueryFullProcessImageNameW(process_, 0, image.data(), &size)) return OA_IPC_UNTRUSTED;
        if (::CompareStringOrdinal(image.data(), static_cast<int>(size), image_.data(), static_cast<int>(image_.size()), TRUE) != CSTR_EQUAL)
            return OA_IPC_UNTRUSTED;
        return check() ? OA_IPC_OK : OA_IPC_UNTRUSTED;
#elif defined(__linux__)
        std::uint64_t uid = 0;
        for (unsigned char ch : principal_) {
            if (ch < '0' || ch > '9' || uid > (std::numeric_limits<uid_t>::max() - (ch - '0')) / 10) return OA_IPC_INVALID_ARGUMENT;
            uid = uid * 10 + (ch - '0');
        }
        // Linux UAPI SO_PEERPIDFD (since 6.5); no PID-only fallback.
#ifdef SO_PEERPIDFD
        constexpr int peer_pidfd = SO_PEERPIDFD;
#else
        constexpr int peer_pidfd = 77;
#endif
        socklen_t fd_size = sizeof(pidfd_);
        if (::getsockopt(stream.native_handle(), SOL_SOCKET, peer_pidfd, &pidfd_, &fd_size) != 0) return OA_IPC_PROOF_UNAVAILABLE;
        if (fd_size != sizeof(pidfd_) || pidfd_ < 0 || ::fcntl(pidfd_, F_SETFD, FD_CLOEXEC) < 0) return OA_IPC_UNTRUSTED;
        struct ucred credentials{};
        socklen_t size = sizeof(credentials);
        if (::getsockopt(stream.native_handle(), SOL_SOCKET, SO_PEERCRED, &credentials, &size) != 0 || size != sizeof(credentials) ||
            credentials.pid <= 0 || credentials.uid != uid) return OA_IPC_UNTRUSTED;
        pid_ = credentials.pid;
        return check() ? OA_IPC_OK : OA_IPC_UNTRUSTED;
#else
        (void)stream;
        return OA_IPC_PROOF_UNAVAILABLE;
#endif
    }

    bool check() const {
#ifdef _WIN32
        DWORD pid = 0;
        if (!::GetNamedPipeServerProcessId(pipe_, &pid) || pid != pid_) return false;
        HANDLE token = nullptr;
        if (!::OpenProcessToken(process_, TOKEN_QUERY, &token)) return false;
        struct TokenOwner { HANDLE h; ~TokenOwner(){::CloseHandle(h);} } owned{token};
        DWORD size = 0;
        ::GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0 || size > 4096) return false;
        std::vector<unsigned char> bytes(size);
        if (!::GetTokenInformation(token, TokenUser, bytes.data(), size, &size)) return false;
        return ::EqualSid(reinterpret_cast<const TOKEN_USER*>(bytes.data())->User.Sid,
                          const_cast<unsigned char*>(expected_sid_.data())) != FALSE;
#elif defined(__linux__)
        if (pidfd_ < 0 || pid_ <= 0) return false;
        pollfd poll{pidfd_, POLLIN, 0};
        if (::poll(&poll, 1, 0) != 0) return false;
        std::vector<char> image(32769);
        const auto path = "/proc/" + std::to_string(pid_) + "/exe";
        const auto size = ::readlink(path.c_str(), image.data(), image.size());
        if (size < 0 || static_cast<std::size_t>(size) >= image.size()) return false;
        std::string actual(image.data(), static_cast<std::size_t>(size));
        // Match the existing Go path vocabulary for a retained deleted image.
        constexpr std::string_view deleted = " (deleted)";
        if (actual.size() >= deleted.size() && actual.compare(actual.size()-deleted.size(), deleted.size(), deleted) == 0)
            actual.resize(actual.size()-deleted.size());
        return actual == program_;
#else
        return false;
#endif
    }
private:
    std::string principal_, program_;
#ifdef _WIN32
    static bool wide(const std::string& text, std::wstring& out) {
        const int size = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
        if (!size) return false;
        out.resize(size);
        return ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), out.data(), size) == size;
    }
    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    HANDLE process_ = nullptr;
    DWORD pid_ = 0;
    FILETIME created_{};
    std::wstring image_, sid_text_;
    std::vector<unsigned char> expected_sid_;
#elif defined(__linux__)
    int pidfd_ = -1;
    pid_t pid_ = 0;
#endif
};
}}
