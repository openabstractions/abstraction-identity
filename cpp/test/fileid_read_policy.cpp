#ifdef NDEBUG
#undef NDEBUG
#endif
#include <abstraction/fileid.h>
#include <cassert>
#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <unistd.h>
#endif
namespace fs = std::filesystem;
namespace fileid = abstraction::fileid;
static void put(const fs::path& path, const char* value) {
    std::ofstream stream(path); stream << value; assert(stream.good());
}
static std::string read(const fs::path& path, bool confined = false) {
    auto file = fileid::open_read(path, confined);
    char buffer[64];
#ifdef _WIN32
    DWORD size = 0;
    assert(ReadFile(reinterpret_cast<HANDLE>(file.native_handle()), buffer, sizeof buffer, &size, nullptr));
#else
    auto size = ::read(int(file.native_handle()), buffer, sizeof buffer);
    assert(size >= 0);
#endif
    return {buffer, size_t(size)};
}
static bool link(const fs::path& name, const fs::path& target) {
#ifdef _WIN32
    if (!CreateSymbolicLinkW(name.c_str(), target.c_str(), 2)) {
        if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD) return false;
        throw std::system_error(int(GetLastError()), std::system_category(), "create read-policy fixture link");
    }
#else
    fs::create_symlink(target, name);
#endif
    return true;
}
int main() {
    auto root = fs::temp_directory_path() / fs::path("fileid-read-policy-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directory(root);
    struct Cleanup { fs::path path; ~Cleanup() { fs::remove_all(path); } } cleanup{root};
    auto folder = root / "read-root"; fs::create_directory(folder);
    put(folder / "inside", "inside"); put(root / "outside", "outside");
    auto held = fileid::open_folder(folder);
    auto identity = fileid::identity(held.native_handle());
    fs::rename(folder, root / "moved"); fs::create_directory(folder);
    assert(fileid::identity(held.native_handle()) == identity);
    assert(fileid::identity(fileid::open_folder(folder).native_handle()) != identity);
    fs::remove(folder); fs::rename(root / "moved", folder);
    assert(fileid::entry_id(folder / "inside") == fileid::entry_id(folder / "." / "inside"));
#ifdef _WIN32
    struct CaseSensitive { ULONG flags; } info{};
    bool sensitive = GetFileInformationByHandleEx(reinterpret_cast<HANDLE>(held.native_handle()),
        static_cast<FILE_INFO_BY_HANDLE_CLASS>(23), &info, sizeof info) && (info.flags & 1);
    assert((fileid::entry_id(folder / "inside") == fileid::entry_id(folder / "INSIDE")) == !sensitive);
#endif
    if (!link(folder / "escape", fs::path("..") / "outside")) {
        std::cout << "UNPROVEN symlink read policy: host privilege unavailable\n"; return 77;
    }
    assert(read(folder / "escape") == "outside");
    try { read(folder / "escape", true); assert(false); } catch (const fileid::ReadEscape&) {}
    assert(link(folder / "relative", "inside"));
    assert(read(folder / "relative", true) == "inside");
    assert(link(folder / "absolute", folder / "inside"));
    assert(read(folder / "absolute") == "inside");
    try { read(folder / "absolute", true); assert(false); } catch (const fileid::ReadEscape&) {}
}
