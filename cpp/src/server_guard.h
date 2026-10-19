#pragma once

// Shared native verification for the C ABI. Capability/language clients supply
// independent expectations and consume the result; they do no platform lookup.
#include <abstraction/ipc/client.h>
#include "local_stream.h"
#include <limits>
#include <cstdint>
#include <vector>
#include "session_test_hooks.h"
#ifdef _WIN32
#include <sddl.h>
#elif defined(__linux__)
#include <poll.h>
#include <sys/stat.h>
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
        // The principal first: a server of another account is refused before
        // the client opens any file it names.
        if (!check()) return OA_IPC_UNTRUSTED;
        std::vector<wchar_t> image(32768);
        DWORD size = static_cast<DWORD>(image.size());
        if (!::QueryFullProcessImageNameW(process_, 0, image.data(), &size)) return OA_IPC_UNTRUSTED;
        // File identity, not the name: a renamed or differently spelled image
        // (hard link, 8.3 alias, junction) keeps the check; another file at
        // the expected name fails it. Only local drive paths are opened, so a
        // reported share or WebDAV name causes no remote open.
        const std::wstring reported(image.data(), size);
        FileIdentity running{}, installed{};
        if (!local_image(reported) || !local_image(image_) || !identity_of(reported, running) ||
            !identity_of(image_, installed) || !(running == installed)) return OA_IPC_UNTRUSTED;
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
        // stat on /proc/<pid>/exe follows the kernel's reference to the mapped
        // image file, so a rename keeps its identity and a replacement at the
        // installed name does not match it.
        const auto path = "/proc/" + std::to_string(pid_) + "/exe";
        struct stat running{}, installed{};
        if (::stat(path.c_str(), &running) != 0 || ::stat(program_.c_str(), &installed) != 0) return false;
        if (::poll(&poll, 1, 0) != 0) return false; // the pid still names the pidfd's process
        return running.st_dev == installed.st_dev && running.st_ino == installed.st_ino;
#else
        return false;
#endif
    }
#ifdef _WIN32
    // A drive-letter path on a drive that is not a network drive. UNC, device
    // and relative names are refused without opening them.
    static bool local_image(const std::wstring& name) {
        if (name.size() < 3 || name[1] != L':' || name[2] != L'\\') return false;
        const wchar_t drive = name[0];
        if (!((drive >= L'A' && drive <= L'Z') || (drive >= L'a' && drive <= L'z'))) return false;
        const wchar_t root[4] = {drive, L':', L'\\', 0};
        const UINT type = ::GetDriveTypeW(root);
        return type == DRIVE_FIXED || type == DRIVE_REMOVABLE || type == DRIVE_RAMDISK || type == DRIVE_CDROM;
    }
#endif
private:
    friend struct RuntimeActivationFile;
    std::string principal_, program_;
#ifdef _WIN32
    struct FileIdentity {
        ULONGLONG volume = 0;
        FILE_ID_128 id{};
        bool operator==(const FileIdentity& o) const {
            return volume == o.volume && std::memcmp(id.Identifier, o.id.Identifier, sizeof(id.Identifier)) == 0;
        }
    };
    // Volume serial and file ID read from a handle opened on the name.
    static bool identity_of(const std::wstring& name, FileIdentity& out) {
#ifdef ABSTRACTION_IPC_TEST_HOOKS
        ++server_guard_test_opens;
#endif
        HANDLE file = ::CreateFileW(name.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        FILE_ID_INFO info{};
        const BOOL read = ::GetFileInformationByHandleEx(file, FileIdInfo, &info, sizeof(info));
        ::CloseHandle(file);
        if (!read) return false;
        out.volume = info.VolumeSerialNumber;
        out.id = info.FileId;
        return true;
    }
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
