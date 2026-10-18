#pragma once

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwchar>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace oa_identity_path {

enum class FailureKind { invalid_argument, not_local, system };

struct Failure {
    FailureKind kind;
    DWORD code = ERROR_SUCCESS;
    std::wstring operation;
    std::wstring path;
    std::wstring reason;
};

#ifdef OA_IDENTITY_PATH_TESTING
using DriveTypeProbe = UINT (*)(const std::wstring& root);
inline DriveTypeProbe drive_type_probe = nullptr;
inline size_t open_count = 0;
#endif

[[noreturn]] inline void invalid_argument(const std::wstring& path, const wchar_t* reason) {
    throw Failure{FailureKind::invalid_argument, ERROR_INVALID_NAME, L"validate", path, reason};
}

[[noreturn]] inline void not_local(const std::wstring& path, const wchar_t* reason) {
    throw Failure{FailureKind::not_local, ERROR_INVALID_NAME, L"validate", path, reason};
}

[[noreturn]] inline void system_failure(const wchar_t* operation, const std::wstring& path, DWORD code) {
    throw Failure{FailureKind::system, code, operation, path, L""};
}

inline bool begins_with(const std::wstring& value, const wchar_t* prefix) {
    const std::wstring start(prefix);
    return value.size() >= start.size() && value.compare(0, start.size(), start) == 0;
}

inline bool drive_absolute(const std::wstring& path) {
    return path.size() >= 3 && ((path[0] | 0x20) >= L'a' && (path[0] | 0x20) <= L'z') &&
        path[1] == L':' && path[2] == L'\\';
}

inline bool extended_drive_path(const std::wstring& path) {
    return begins_with(path, L"\\\\?\\") && drive_absolute(path.substr(4));
}

inline size_t drive_root_length(const std::wstring& path) {
    return extended_drive_path(path) ? 7 : 3;
}

inline std::wstring full_path(const std::wstring& path) {
    DWORD needed = ::GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (needed == 0) system_failure(L"resolve", path, ::GetLastError());
    if (needed > 32768) system_failure(L"resolve", path, ERROR_FILENAME_EXCED_RANGE);
    std::vector<wchar_t> buffer(static_cast<size_t>(needed) + 1);
    DWORD written = ::GetFullPathNameW(path.c_str(), static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
    if (written == 0) system_failure(L"resolve", path, ::GetLastError());
    if (written >= static_cast<DWORD>(buffer.size())) system_failure(L"resolve", path, ERROR_FILENAME_EXCED_RANGE);
    return std::wstring(buffer.data(), written);
}

inline bool ordinal_equal_ignoring_case(const std::wstring& left, const wchar_t* right) {
    const int right_length = static_cast<int>(wcslen(right));
    return ::CompareStringOrdinal(left.data(), static_cast<int>(left.size()), right, right_length, TRUE) == CSTR_EQUAL;
}

inline bool reserved_device_name(std::wstring component) {
    const auto end = component.find_first_of(L".:");
    if (end != std::wstring::npos) component.resize(end);
    while (!component.empty() && component.back() == L' ') component.pop_back();
    if (component.size() < 3 || component.size() > 7) return false;
    if (std::wstring(L"CcPpAaNnLl").find(component.front()) == std::wstring::npos) return false;
    static constexpr const wchar_t* devices[] = {
        L"CON", L"PRN", L"AUX", L"NUL", L"CONIN$", L"CONOUT$",
        L"COM0", L"COM1", L"COM2", L"COM3", L"COM4", L"COM5", L"COM6", L"COM7", L"COM8", L"COM9",
        L"LPT0", L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5", L"LPT6", L"LPT7", L"LPT8", L"LPT9",
        L"COM\u00b9", L"COM\u00b2", L"COM\u00b3", L"LPT\u00b9", L"LPT\u00b2", L"LPT\u00b3"
    };
    for (const auto* device : devices) {
        if (ordinal_equal_ignoring_case(component, device)) return true;
    }
    return false;
}

inline void reject_reserved_components(const std::wstring& path) {
    size_t start = drive_root_length(path);
    while (start <= path.size()) {
        const auto end = path.find(L'\\', start);
        const auto count = (end == std::wstring::npos ? path.size() : end) - start;
        if (reserved_device_name(path.substr(start, count)))
            not_local(path, L"a reserved device name is a path component");
        if (end == std::wstring::npos) break;
        start = end + 1;
    }
}

// This check reads only the spelling, Win32's non-opening full-path result,
// and the drive type. It performs no file open.
inline std::wstring local_path(const std::wstring& input) {
    if (input.empty()) invalid_argument(input, L"the path is empty");
    if (input.find(L'\0') != std::wstring::npos) not_local(input, L"the path contains NUL");

    std::wstring path = input;
    if (begins_with(path, L"\\??\\")) not_local(input, L"an NT object path");
    if (begins_with(path, L"\\\\?\\")) {
        // Extended drive paths bypass Win32 path normalization. Keep the
        // caller's spelling for CreateFileW, especially literal trailing
        // dots and spaces in components; only inspect its drive and names.
        if (!drive_absolute(path.substr(4))) not_local(input, L"a device or non-drive extended path");
        reject_reserved_components(path);
    } else {
        std::replace(path.begin(), path.end(), L'/', L'\\');
        if (begins_with(path, L"\\??\\")) not_local(input, L"an NT object path");
        if (begins_with(path, L"\\\\?\\")) {
            path.erase(0, 4);
            if (!drive_absolute(path)) not_local(input, L"a device or non-drive extended path");
        } else if (begins_with(path, L"\\\\")) {
            not_local(input, L"a UNC or device path");
        }

        if (drive_absolute(path)) reject_reserved_components(path);
        path = full_path(path);
        if (begins_with(path, L"\\\\")) not_local(input, L"its full path is a UNC or device path");
        if (!drive_absolute(path)) not_local(input, L"it names no absolute drive letter");
        reject_reserved_components(path);
    }

    const std::wstring root = extended_drive_path(path) ? path.substr(4, 3) : path.substr(0, 3);
#ifdef OA_IDENTITY_PATH_TESTING
    const UINT type = drive_type_probe ? drive_type_probe(root) : ::GetDriveTypeW(root.c_str());
#else
    const UINT type = ::GetDriveTypeW(root.c_str());
#endif
    if (type == DRIVE_REMOTE) not_local(input, L"a network drive");
    return path;
}

class Handle {
public:
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value_(other.value_) { other.value_ = INVALID_HANDLE_VALUE; }
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            close();
            value_ = other.value_;
            other.value_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    ~Handle() { close(); }
    HANDLE get() const { return value_; }
private:
    void close() {
        if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr) ::CloseHandle(value_);
        value_ = INVALID_HANDLE_VALUE;
    }
    HANDLE value_;
};

inline std::wstring final_path(HANDLE handle, const std::wstring& path) {
    std::vector<wchar_t> buffer(32768);
    DWORD size = ::GetFinalPathNameByHandleW(handle, buffer.data(), static_cast<DWORD>(buffer.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (size == 0) system_failure(L"resolve final path for", path, ::GetLastError());
    if (size >= static_cast<DWORD>(buffer.size())) system_failure(L"resolve final path for", path, ERROR_FILENAME_EXCED_RANGE);
    return std::wstring(buffer.data(), size);
}

struct OpenedHandle {
    Handle handle;
    std::wstring final;
};

inline OpenedHandle open_handle(const std::wstring& input, DWORD extra_flags = 0) {
    const auto path = local_path(input);
#ifdef OA_IDENTITY_PATH_TESTING
    ++open_count;
#endif
    HANDLE raw = ::CreateFileW(path.c_str(), 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | extra_flags, nullptr);
    if (raw == INVALID_HANDLE_VALUE) system_failure(L"open", path, ::GetLastError());
    Handle handle(raw);

    // A local reparse point may lead off-local. Its first identity-only open
    // follows the link; refuse the resolved location before any later open.
    const auto final = final_path(handle.get(), path);
    local_path(final);
    return OpenedHandle{std::move(handle), final};
}

struct FileKey {
    uint64_t volume = 0;
    std::array<unsigned char, 16> id{};
    size_t length = 0;

    bool operator==(const FileKey& other) const {
        return volume == other.volume && length == other.length && id == other.id;
    }
};

struct FileInfo {
    FileKey key;
    bool directory = false;
};

struct PathIdentity {
    FileKey key;
    bool directory = false;
    std::wstring final;
};

inline FileInfo file_info(HANDLE handle, const std::wstring& path) {
    // FileIdInfo is value 18 in FILE_INFO_BY_HANDLE_CLASS. Keeping the layout
    // local avoids requiring a newer Windows SDK typedef in the public build.
    struct IdInfo { ULONGLONG volume; BYTE id[16]; } wide{};
    constexpr auto file_id_info = static_cast<FILE_INFO_BY_HANDLE_CLASS>(18);
    FileKey key;
    if (::GetFileInformationByHandleEx(handle, file_id_info, &wide, sizeof(wide))) {
        key.volume = wide.volume;
        std::copy(std::begin(wide.id), std::end(wide.id), key.id.begin());
        key.length = sizeof(wide.id);
    } else {
        BY_HANDLE_FILE_INFORMATION legacy{};
        if (!::GetFileInformationByHandle(handle, &legacy))
            system_failure(L"identify", path, ::GetLastError());
        key.volume = legacy.dwVolumeSerialNumber;
        const uint64_t index = (uint64_t(legacy.nFileIndexHigh) << 32) | legacy.nFileIndexLow;
        for (size_t i = 0; i < sizeof(index); ++i) key.id[i] = static_cast<unsigned char>(index >> (i * 8));
        key.length = sizeof(index);
        return FileInfo{key, (legacy.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0};
    }

    BY_HANDLE_FILE_INFORMATION legacy{};
    if (!::GetFileInformationByHandle(handle, &legacy))
        system_failure(L"read attributes for", path, ::GetLastError());
    return FileInfo{key, (legacy.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0};
}

inline PathIdentity identity_of(const std::wstring& input) {
    auto opened = open_handle(input);
    const auto path = local_path(input);
    const auto info = file_info(opened.handle.get(), path);
    return PathIdentity{info.key, info.directory, std::move(opened.final)};
}

inline bool missing_error(DWORD code) {
    return code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND;
}

inline bool path_exists(const std::wstring& path) {
    try {
        auto opened = open_handle(path, FILE_FLAG_OPEN_REPARSE_POINT);
        (void)opened;
        return true;
    } catch (const Failure& error) {
        if (error.kind == FailureKind::system && missing_error(error.code)) return false;
        throw;
    }
}

inline std::wstring parent_path(const std::wstring& path) {
    const auto slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos) return path;
    const size_t root_length = begins_with(path, L"\\\\?\\") ? 7 : 3;
    if (slash == root_length - 1 && path.size() >= root_length) return path.substr(0, root_length);
    if (slash == 0) return L"\\";
    return path.substr(0, slash);
}

inline std::wstring base_name(const std::wstring& path) {
    const auto slash = path.find_last_of(L'\\');
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

inline std::wstring join_path(const std::wstring& parent, const std::wstring& rest) {
    if (rest.empty()) return parent;
    if (parent.empty() || parent.back() == L'\\') return parent + rest;
    return parent + L"\\" + rest;
}

struct Resolved {
    std::wstring path;
    bool parent_is_directory = false;
};

inline Resolved resolve_existing(const std::wstring& input) {
    const auto path = local_path(input);
    auto existing = parent_path(path);
    auto rest = base_name(path);
    while (!path_exists(existing)) {
        const auto up = parent_path(existing);
        if (up == existing) system_failure(L"find an existing parent for", path, ERROR_PATH_NOT_FOUND);
        rest = join_path(base_name(existing), rest);
        existing = up;
    }

    const auto info = identity_of(existing);
    return Resolved{join_path(info.final, rest), info.directory};
}

inline bool within(const std::wstring& path_input, const std::wstring& folder_input) {
    // Both caller spellings are refused before either can cause an open.
    const auto folder = local_path(folder_input);
    const auto path = local_path(path_input);
    const auto target = identity_of(folder);
    if (!target.directory) return false;

    const auto resolved = resolve_existing(path);
    if (!resolved.parent_is_directory) return false;
    for (auto parent = parent_path(resolved.path);; parent = parent_path(parent)) {
        try {
            const auto info = identity_of(parent);
            if (info.directory && info.key == target.key) {
                auto remainder = resolved.path.substr(parent.size());
                while (!remainder.empty() && remainder.front() == L'\\') remainder.erase(remainder.begin());
                return !remainder.empty();
            }
        } catch (const Failure& error) {
            if (error.kind != FailureKind::system || !missing_error(error.code)) throw;
        }
        const auto up = parent_path(parent);
        if (up == parent) return false;
    }
}

} // namespace oa_identity_path

#endif // _WIN32
