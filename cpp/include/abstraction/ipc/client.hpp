#pragma once
#include <abstraction/ipc/client.h>
// The original status codes, frame bounds and call budget of identity.thrift
// (abstraction-ipc CONTRACT.md IPC-E1, IPC-F1, IPC-D1), generated beside
// this package by scripts/generate.targets. OpenIoError is the opt-in native
// ABI-1 phase extension; it changes no generated protocol record.
#include <abstraction/ipc/constants/rec.h>
#include <algorithm>
#include <chrono>
#include <string>
#include <memory>
#include <optional>
#include <utility>
#include <stdexcept>
#include <string_view>
#include <functional>
#include <random>
#include <vector>
#ifdef _WIN32
#include <abstraction/ipc/process.hpp>
#include <shlobj.h>
#endif
namespace abstraction { namespace ipc {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
enum class Status { Ok = OA_IPC_OK, Timeout = OA_IPC_TIMEOUT,
    Disconnected = OA_IPC_DISCONNECTED, IoError = OA_IPC_IO_ERROR,
    InvalidArgument = OA_IPC_INVALID_ARGUMENT, NoMemory = OA_IPC_NO_MEMORY,
    InternalError = OA_IPC_INTERNAL_ERROR, Cancelled = OA_IPC_CANCELLED,
    Untrusted = OA_IPC_UNTRUSTED, ProofUnavailable = OA_IPC_PROOF_UNAVAILABLE,
    OpenIoError = OA_IPC_OPEN_IO_ERROR };
// client.h states the C ABI in C, which has no generated binding; every C++
// build holds it to the definition.
static_assert(OA_IPC_OK == constants::kIpcOk && OA_IPC_TIMEOUT == constants::kIpcTimeout &&
    OA_IPC_DISCONNECTED == constants::kIpcDisconnected && OA_IPC_IO_ERROR == constants::kIpcIoError &&
    OA_IPC_INVALID_ARGUMENT == constants::kIpcInvalidArgument && OA_IPC_NO_MEMORY == constants::kIpcNoMemory &&
    OA_IPC_INTERNAL_ERROR == constants::kIpcInternalError && OA_IPC_CANCELLED == constants::kIpcCancelled &&
    OA_IPC_UNTRUSTED == constants::kIpcUntrusted && OA_IPC_PROOF_UNAVAILABLE == constants::kIpcProofUnavailable,
    "abstraction/ipc/client.h disagrees with identity.thrift's ipc status codes");

// Independent installation/caller evidence. Values are owned by the copy.
struct ServerExpectation {
    std::uint32_t principal_kind;
    std::string principal, program;
};
namespace detail { struct RuntimeActivationAccess; }

#ifdef _WIN32
namespace detail {
struct RuntimeProfileView { bool virtualized=false;std::string family; };
struct ProfileHandle {
    HANDLE value=nullptr;
    explicit ProfileHandle(HANDLE h):value(h==INVALID_HANDLE_VALUE?nullptr:h){}
    ~ProfileHandle(){if(value)::CloseHandle(value);}
    ProfileHandle(const ProfileHandle&)=delete;
    ProfileHandle& operator=(const ProfileHandle&)=delete;
};
inline RuntimeProfileView probe_profile(const std::wstring& root, const std::function<bool(const std::wstring&)>& create) {
    std::random_device random;
    const std::wstring name = L".oa-profile-" + std::to_wstring(::GetCurrentProcessId()) + L"-" +
        std::to_wstring(random()) + std::to_wstring(random());
    const std::wstring probe = root + L"\\" + name;
    if (!create(probe)) throw std::runtime_error("profile view: the probe file could not be created");
    std::vector<std::wstring> copies;
    bool unknown=false;size_t inspected=0;
    WIN32_FIND_DATAW found{};
    const std::wstring packages = root + L"\\Packages\\";
    auto plain_directory=[](const std::wstring& path) {
        const auto attributes=::GetFileAttributesW(path.c_str());
        if(attributes==INVALID_FILE_ATTRIBUTES) {
            const auto error=::GetLastError();
            return error==ERROR_FILE_NOT_FOUND||error==ERROR_PATH_NOT_FOUND?0:-1;
        }
        return (attributes&FILE_ATTRIBUTE_DIRECTORY)&&!(attributes&FILE_ATTRIBUTE_REPARSE_POINT)?1:-1;
    };
    const auto package_state=plain_directory(root+L"\\Packages");
    unknown=package_state<0;
    HANDLE search = package_state==1?::FindFirstFileExW((packages + L"*").c_str(), FindExInfoBasic, &found, FindExSearchLimitToDirectories, nullptr, 0):INVALID_HANDLE_VALUE;
    if (search != INVALID_HANDLE_VALUE) {
        do {
            if(++inspected>4096){unknown=true;break;}
            const std::wstring family = found.cFileName;
            if (family == L"." || family == L"..") continue;
            if(found.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT){unknown=true;break;}
            if(!(found.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))continue;
            const auto cache=plain_directory(packages+family+L"\\LocalCache");
            if(cache<0){unknown=true;break;}if(cache==0)continue;
            const auto local=plain_directory(packages+family+L"\\LocalCache\\Local");
            if(local<0){unknown=true;break;}if(local==0)continue;
            const std::wstring copy = packages + family + L"\\LocalCache\\Local\\" + name;
            if (::GetFileAttributesW(copy.c_str()) != INVALID_FILE_ATTRIBUTES) copies.push_back(family);
            else if(::GetLastError()!=ERROR_FILE_NOT_FOUND&&::GetLastError()!=ERROR_PATH_NOT_FOUND){unknown=true;break;}
        } while (::FindNextFileW(search, &found));
        if(!unknown&&::GetLastError()!=ERROR_NO_MORE_FILES)unknown=true;
        ::FindClose(search);
    }else if(package_state==1&&::GetLastError()!=ERROR_FILE_NOT_FOUND&&::GetLastError()!=ERROR_PATH_NOT_FOUND)unknown=true;
    auto remove_probe=[&unknown](const std::wstring& path) {
        if(!::DeleteFileW(path.c_str())) {
            const auto error=::GetLastError();
            if(error!=ERROR_FILE_NOT_FOUND&&error!=ERROR_PATH_NOT_FOUND)unknown=true;
        }
    };
    remove_probe(probe);
    for (const auto& family : copies) remove_probe(packages + family + L"\\LocalCache\\Local\\" + name);
    if(unknown)throw std::runtime_error("profile view: package directory proof unavailable");
    if (copies.empty()) return {};
    if (copies.size() > 1) throw std::runtime_error("profile view: the probe appears in " + std::to_string(copies.size()) + " package copies");
    const std::wstring& family = copies.front();
    const int size = ::WideCharToMultiByte(CP_UTF8, 0, family.data(), static_cast<int>(family.size()), nullptr, 0, nullptr, nullptr);
    std::string narrow(static_cast<std::size_t>(size > 0 ? size : 0), '\0');
    if (size > 0) ::WideCharToMultiByte(CP_UTF8, 0, family.data(), static_cast<int>(family.size()), narrow.data(), size, nullptr, nullptr);
    return {true, narrow};
}


// The root comes from the native KnownFolder owner. Environment text never
// selects the directory in which this proof creates its uniquely named file.
inline RuntimeProfileView profile_view_with(const std::function<std::wstring()>& root_provider,
    const std::function<bool(const std::wstring&)>& create) {
    const auto root=root_provider();
    if(root.size()<3||root[1]!=L':'||root[2]!=L'\\')throw std::runtime_error("profile view: non-local known folder");
    const wchar_t drive[]={root[0],L':',L'\\',0};
    const auto type=::GetDriveTypeW(drive);
    if(type!=DRIVE_FIXED&&type!=DRIVE_REMOVABLE&&type!=DRIVE_RAMDISK)
        throw std::runtime_error("profile view: known folder is not on a local writable drive");
    const auto attributes=::GetFileAttributesW(root.c_str());
    if(attributes==INVALID_FILE_ATTRIBUTES||!(attributes&FILE_ATTRIBUTE_DIRECTORY)||(attributes&FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("profile view: known folder proof unavailable");
    return probe_profile(root,create);
}
inline RuntimeProfileView current_profile_view() {
    return profile_view_with([] {
        HANDLE raw=nullptr;
        if(!::OpenProcessToken(::GetCurrentProcess(),TOKEN_QUERY|TOKEN_IMPERSONATE,&raw))
            throw std::runtime_error("profile view: primary token unavailable");
        ProfileHandle token(raw);PWSTR path=nullptr;
        const auto status=::SHGetKnownFolderPath(FOLDERID_LocalAppData,KF_FLAG_NO_PACKAGE_REDIRECTION,token.value,&path);
        if(FAILED(status)||!path){if(path)::CoTaskMemFree(path);throw std::runtime_error("profile view: known folder unavailable");}
        const std::wstring result(path);::CoTaskMemFree(path);return result;
    },[](const std::wstring& path) {
        ProfileHandle file(::CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
        return file.value!=nullptr;
    });
}
}
#endif

// Copyable shared ownership keeps the native cancellation handle alive while
// a token is being used to open a connection. A default token is uncancelable.
class CancellationToken {
public:
    CancellationToken() = default;
private:
    explicit CancellationToken(std::shared_ptr<oa_ipc_cancellation> handle) : handle_(std::move(handle)) {}
    std::shared_ptr<oa_ipc_cancellation> handle_;
    friend class CancellationSource;
    friend class Stream;
    friend class FrameTransport;
    friend ServerExpectation select_runtime(Deadline, const CancellationToken&);
    friend struct detail::RuntimeActivationAccess;
};

namespace detail {
// Internal C++ bridge keeps cancellation ownership private. Facade owns the
// default-discovery decision; the native library owns all platform policy.
struct RuntimeActivationAccess {
    static oa_ipc_status call(const ServerExpectation& server, Deadline deadline,
                              const CancellationToken& token, int32_t& outcome) {
        auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now()).count();
        const auto ms=left<=0?0:static_cast<uint32_t>(std::min<decltype(left)>(left,UINT32_MAX));
        const oa_ipc_server_expectation expected{sizeof(oa_ipc_server_expectation),1,server.principal_kind,0,
            server.principal.data(),server.principal.size(),server.program.data(),server.program.size()};
        return oa_ipc_activate_runtime(&expected,ms,token.handle_.get(),&outcome);
    }
};
}

class CancellationSource {
public:
    CancellationSource() {
        oa_ipc_cancellation* handle = nullptr;
        const auto status = oa_ipc_cancellation_create(&handle);
        if (status == OA_IPC_NO_MEMORY) throw std::bad_alloc();
        if (status != OA_IPC_OK) throw std::runtime_error("IPC cancellation creation failed");
        handle_ = std::shared_ptr<oa_ipc_cancellation>(handle, oa_ipc_cancellation_release);
    }
    CancellationToken token() const { return CancellationToken(handle_); }
    void cancel() const { oa_ipc_cancellation_signal(handle_.get()); }
private:
    std::shared_ptr<oa_ipc_cancellation> handle_;
};
class Stream {
public:
    Stream(const std::string& path, Deadline deadline)
        : Stream(path, deadline, CancellationToken{}) {}
    Stream(const std::string& path, Deadline deadline, CancellationToken token,
           const std::optional<ServerExpectation>& server = std::nullopt) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        auto ms = left <= 0 ? 0 : static_cast<uint32_t>(std::min<decltype(left)>(left, UINT32_MAX));
        if (server) {
            const oa_ipc_server_expectation expected{sizeof(oa_ipc_server_expectation),1,
                server->principal_kind,0,server->principal.data(),server->principal.size(),
                server->program.data(),server->program.size()};
            status_ = oa_ipc_open_verified(path.data(),path.size(),ms,token.handle_.get(),&expected,&connection_);
            return;
        }
        status_ = token.handle_
            ? oa_ipc_open_cancelable(path.data(), path.size(), ms, token.handle_.get(), &connection_)
            : oa_ipc_open(path.data(), path.size(), ms, &connection_);
    }
    ~Stream() { oa_ipc_close(connection_); }
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    bool valid() const { return status_ == OA_IPC_OK; }
    Status status() const { return static_cast<Status>(status_); }
    bool write_all(std::string_view bytes) {
        if (!valid()) return false;
        size_t moved;
        status_ = oa_ipc_write(connection_, bytes.data(), bytes.size(), &moved);
        return valid();
    }
    bool read_some(void* buffer, size_t capacity, size_t& moved) {
        moved = 0;
        if (!valid()) return false;
        status_ = oa_ipc_read(connection_, buffer, capacity, &moved);
        return valid();
    }
private:
    oa_ipc_connection* connection_ = nullptr;
    oa_ipc_status status_ = OA_IPC_IO_ERROR;
};
}}
