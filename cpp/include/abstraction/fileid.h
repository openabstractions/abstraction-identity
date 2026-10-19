#pragma once
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <array>
#include <cstdint>
#include <memory>

// Current-process local path identity. These functions supply physical names,
// not caller authority, content verification or a retained file capability.
namespace abstraction::fileid {
namespace fs = std::filesystem;
struct NotLocal : std::runtime_error { using std::runtime_error::runtime_error; };
struct ReadEscape : std::runtime_error { using std::runtime_error::runtime_error; };
struct Leaf {
    fs::path folder, name;
    fs::path path() const { return folder / name; }
};
// Refuses unsafe/nonlocal spelling or volume. A missing path is checked through
// its deepest existing folder. Queries that cannot establish locality refuse.
void local(const fs::path&);
// Resolves links physically. With create=false, safe missing remainder names are
// returned beneath the deepest existing folder; create=true creates folders.
fs::path folder(const fs::path&, bool create = false);
// Resolves the parent and the directory entry name, leaving the leaf's symbolic
// or hard-link target untouched. An existing Windows 8.3 leaf uses its long name.
Leaf leaf(const fs::path&, bool create_folders = false);
// Physical folder ancestry, proven by native identity. Returns the relative
// spelling, including "." for the same folder, or no value for an outside path.
std::optional<fs::path> within(const fs::path&, const fs::path&);

// Borrowed native handles remain valid while this owning value is alive. The
// caller never closes native_handle(). Releasing a value has no thread affinity.
class Opened {
public:
    std::intptr_t native_handle() const { return native_; }
private:
    std::intptr_t native_;
    std::shared_ptr<void> owner_;
    Opened(std::intptr_t native, std::shared_ptr<void> owner)
        : native_(native), owner_(std::move(owner)) {}
    friend Opened open_folder(const fs::path&);
    friend Opened open_read(const fs::path&, bool, bool);
};
struct ObjectID {
    // 1: Windows FILE_ID_INFO; 2: legacy BY_HANDLE_FILE_INFORMATION;
    // 3: POSIX device/inode. The format participates in equality.
    std::uint32_t format = 0;
    std::uint64_t volume = 0;
    std::array<std::uint8_t,16> file{};
    bool operator==(const ObjectID& other) const { return format==other.format && volume==other.volume && file==other.file; }
    bool operator!=(const ObjectID& other) const { return !(*this==other); }
};
// Identity of an already-open handle. No path lookup or authority change.
ObjectID identity(std::intptr_t native_handle);
struct EntryID {
    ObjectID parent;
    fs::path::string_type name;
    bool operator==(const EntryID& other) const {return parent==other.parent && name==other.name;}
};
// A rename-stable entry key: native parent identity plus the leaf under that
// directory's case rule. This never keys on the replaceable file's own identity.
EntryID entry_id(const fs::path&);
// Local physical folder admission through the same walker as folder()/leaf().
Opened open_folder(const fs::path&);
// Read admission does not require locality. parent_confined permits relative
// links beneath the held parent and refuses absolute links and root escapes.
// nonblocking opens a POSIX FIFO without waiting, so bounded callers can inspect
// the handle type before reading. All resolution uses this owner's walker.
Opened open_read(const fs::path&, bool parent_confined = false, bool nonblocking = false);
}
