#pragma once
#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <CoreFoundation/CFXMLParser.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <fcntl.h>
#include <memory>
#include <pwd.h>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace abstraction::ipc_internal::darwin_selection {
constexpr std::size_t kMaxPlistBytes = 64 * 1024;

struct FD {
    int value = -1;
    FD() = default;
    explicit FD(int fd) : value(fd) {}
    FD(const FD&) = delete;
    FD& operator=(const FD&) = delete;
    FD(FD&& other) noexcept : value(other.value) { other.value = -1; }
    FD& operator=(FD&& other) noexcept {
        if (this != &other) { if (value >= 0) ::close(value); value = other.value; other.value = -1; }
        return *this;
    }
    ~FD() { if (value >= 0) ::close(value); }
};

inline bool safe_metadata(const struct stat& value, uid_t uid, mode_t kind) {
    return value.st_uid == uid && (value.st_mode & S_IFMT) == kind &&
        (value.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

inline bool inspect(int fd, uid_t uid, mode_t kind, bool executable = false) {
    struct stat value{};
    return ::fstat(fd, &value) == 0 && safe_metadata(value, uid, kind) &&
        (!executable || (value.st_mode & S_IXUSR) != 0);
}

inline FD open_component(int parent, const char* name, uid_t uid, mode_t kind, bool executable = false) {
    int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
    if (kind == S_IFDIR) flags |= O_DIRECTORY;
    FD result(::openat(parent, name, flags));
    if (result.value < 0 || !inspect(result.value, uid, kind, executable)) return {};
    return result;
}

inline bool cf_string(CFTypeRef value, const std::string& expected) {
    if (!value || CFGetTypeID(value) != CFStringGetTypeID()) return false;
    CFStringRef text = CFStringCreateWithBytes(kCFAllocatorDefault,
        reinterpret_cast<const UInt8*>(expected.data()), static_cast<CFIndex>(expected.size()),
        kCFStringEncodingUTF8, false);
    if (!text) return false;
    const bool equal = CFStringCompare(static_cast<CFStringRef>(value), text, 0) == kCFCompareEqualTo;
    CFRelease(text);
    return equal;
}

struct XMLNode {
    CFXMLNodeTypeCode type = kCFXMLNodeTypeDocument;
    std::string text;
    std::size_t depth = 0;
    std::vector<XMLNode*> children;
};
struct XMLState {
    bool valid = true;
    std::vector<std::unique_ptr<XMLNode>> nodes;
};
constexpr std::size_t kMaxXMLDepth = 64;

inline std::string xml_text(CFStringRef value) {
    if (!value) return {};
    const CFIndex n = CFStringGetMaximumSizeForEncoding(CFStringGetLength(value), kCFStringEncodingUTF8);
    if (n < 0 || n > static_cast<CFIndex>(kMaxPlistBytes)) throw std::bad_alloc();
    std::vector<char> bytes(static_cast<std::size_t>(n) + 1);
    if (!CFStringGetCString(value, bytes.data(), bytes.size(), kCFStringEncodingUTF8)) throw std::bad_alloc();
    return bytes.data();
}
inline void* xml_create(CFXMLParserRef, CFXMLNodeRef description, void* info) {
    auto* state = static_cast<XMLState*>(info);
    try {
        std::unique_ptr<XMLNode> node(new XMLNode);
        node->type = CFXMLNodeGetTypeCode(description);
        node->text = xml_text(CFXMLNodeGetString(description));
        XMLNode* result = node.get();
        state->nodes.push_back(std::move(node));
        return result;
    } catch (...) {
        state->valid = false;
        return nullptr;
    }
}
inline void xml_add(CFXMLParserRef, void* parent_value, void* child_value, void* info) {
    auto* state = static_cast<XMLState*>(info);
    auto* parent = static_cast<XMLNode*>(parent_value);
    auto* child = static_cast<XMLNode*>(child_value);
    if (!parent || !child) { state->valid = false; return; }
    try {
        child->depth = parent->depth + 1;
        if (child->depth > kMaxXMLDepth) state->valid = false;
        parent->children.push_back(child);
    } catch (...) {
        state->valid = false;
    }
}
inline void xml_end(CFXMLParserRef, void* value, void* info) {
    auto* state = static_cast<XMLState*>(info);
    auto* node = static_cast<XMLNode*>(value);
    if (!node) { state->valid = false; return; }
    if (node->type == kCFXMLNodeTypeElement && node->text == "dict") {
        std::set<std::string> keys;
        try {
            for (const auto* child : node->children) {
                if (child->type != kCFXMLNodeTypeElement || child->text != "key") continue;
                std::string key;
                for (const auto* part : child->children)
                    if (part->type == kCFXMLNodeTypeText || part->type == kCFXMLNodeTypeCDATASection)
                        key += part->text;
                if (!keys.insert(std::move(key)).second) state->valid = false;
            }
        } catch (...) { state->valid = false; }
    }
}
inline CFDataRef xml_external(CFXMLParserRef, CFXMLExternalID*, void*) { return nullptr; }
inline Boolean xml_error(CFXMLParserRef, CFXMLParserStatusCode, void* info) {
    static_cast<XMLState*>(info)->valid = false;
    return false;
}
inline bool strict_xml(CFDataRef data) {
    XMLState state;
    CFXMLParserCallBacks callbacks{0, xml_create, xml_add, xml_end, xml_external, xml_error};
    CFXMLParserContext context{0, &state, nullptr, nullptr, nullptr};
    CFXMLParserRef parser = CFXMLParserCreate(kCFAllocatorDefault, data, nullptr,
        kCFXMLParserSkipMetaData | kCFXMLParserSkipWhitespace, kCFXMLNodeCurrentVersion,
        &callbacks, &context);
    if (!parser) return false;
    const bool parsed = CFXMLParserParse(parser);
    CFRelease(parser);
    return parsed && state.valid;
}

inline bool valid_services(CFTypeRef value) {
    static const char* const names[] = {
        "com.openabstractions.runtime-v1", "com.openabstractions.logging-v1",
        "com.openabstractions.config-v1", "com.openabstractions.job-acceptance-v1",
        "com.openabstractions.router-v1", "com.openabstractions.model-v1",
        "com.openabstractions.storage-content-v1", "com.openabstractions.asks-application-v1",
        "com.openabstractions.rights-authorization-v1", "com.openabstractions.credentials-v1",
        "com.openabstractions.inference-v1", "com.openabstractions.inference-remote-v1",
        "com.openabstractions.registry-v1", "com.openabstractions.applications-v1",
        "com.openabstractions.resource-table-v1", "com.openabstractions.lend-v1"
    };
    if (!value || CFGetTypeID(value) != CFDictionaryGetTypeID()) return false;
    const auto dictionary = static_cast<CFDictionaryRef>(value);
    if (CFDictionaryGetCount(dictionary) != static_cast<CFIndex>(sizeof(names) / sizeof(names[0]))) return false;
    for (const char* name : names) {
        CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, name, kCFStringEncodingASCII);
        if (!key) return false;
        const auto found = CFDictionaryGetValue(dictionary, key);
        CFRelease(key);
        if (found != kCFBooleanTrue) return false;
    }
    return true;
}

inline bool valid_plist(const std::vector<UInt8>& bytes, const std::string& executable) {
    if (bytes.empty() || bytes.size() > kMaxPlistBytes) return false;
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, bytes.data(), static_cast<CFIndex>(bytes.size()));
    if (!data) return false;
    if (!strict_xml(data)) { CFRelease(data); return false; }
    CFErrorRef error = nullptr;
    CFPropertyListRef root = CFPropertyListCreateWithData(kCFAllocatorDefault, data,
        kCFPropertyListImmutable, nullptr, &error);
    CFRelease(data);
    if (error) CFRelease(error);
    if (!root) return false;
    bool valid = false;
    if (CFGetTypeID(root) == CFDictionaryGetTypeID()) {
        const auto dictionary = static_cast<CFDictionaryRef>(root);
        const auto label = CFDictionaryGetValue(dictionary, CFSTR("Label"));
        const auto program = CFDictionaryGetValue(dictionary, CFSTR("Program"));
        const auto arguments = CFDictionaryGetValue(dictionary, CFSTR("ProgramArguments"));
        const auto services = CFDictionaryGetValue(dictionary, CFSTR("MachServices"));
        valid = cf_string(label, "com.openabstractions.runtime") &&
            (!program || cf_string(program, executable)) && valid_services(services) &&
            arguments && CFGetTypeID(arguments) == CFArrayGetTypeID() &&
            CFArrayGetCount(static_cast<CFArrayRef>(arguments)) == 4;
        if (valid) {
            const auto array = static_cast<CFArrayRef>(arguments);
            const std::string expected[] = {executable, "serve", "runtime", "--xpc"};
            for (CFIndex i = 0; i < 4 && valid; ++i)
                valid = cf_string(CFArrayGetValueAtIndex(array, i), expected[i]);
        }
    }
    CFRelease(root);
    return valid;
}

inline oa_ipc_status read_plist(std::vector<UInt8>& out, int fd, local_stream::Deadline deadline,
    local_stream::Cancellation* cancellation) {
    struct stat value{};
    if (::fstat(fd, &value) != 0 || value.st_size <= 0 ||
        static_cast<uint64_t>(value.st_size) > kMaxPlistBytes) return OA_IPC_UNTRUSTED;
    out.resize(static_cast<std::size_t>(value.st_size));
    std::size_t offset = 0;
    while (offset < out.size()) {
        auto budget = selection_budget(deadline, cancellation); if (budget != OA_IPC_OK) return budget;
        const auto read = ::pread(fd, out.data() + offset, out.size() - offset, static_cast<off_t>(offset));
        if (read < 0 && errno == EINTR) continue;
        if (read <= 0) return OA_IPC_UNTRUSTED;
        offset += static_cast<std::size_t>(read);
    }
    return selection_budget(deadline, cancellation);
}

inline oa_ipc_status select(RuntimeIdentity& out, local_stream::Deadline deadline,
    local_stream::Cancellation* cancellation, uid_t uid, const std::string& supplied_home) {
    auto budget = selection_budget(deadline, cancellation); if (budget != OA_IPC_OK) return budget;
    if (supplied_home.empty() || supplied_home[0] != '/' || supplied_home.size() >= PATH_MAX ||
        supplied_home.find('\0') != std::string::npos) return OA_IPC_UNTRUSTED;
    char canonical_buffer[PATH_MAX];
    if (!::realpath(supplied_home.c_str(), canonical_buffer)) return OA_IPC_UNTRUSTED;
    const std::string home(canonical_buffer);
    if (home != supplied_home || home == "/") return OA_IPC_UNTRUSTED;
    budget = selection_budget(deadline, cancellation); if (budget != OA_IPC_OK) return budget;

    FD home_fd(::open(home.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY));
    if (home_fd.value < 0 || !inspect(home_fd.value, uid, S_IFDIR)) return OA_IPC_UNTRUSTED;
    auto local = open_component(home_fd.value, ".local", uid, S_IFDIR);
    auto library = open_component(home_fd.value, "Library", uid, S_IFDIR);
    if (local.value < 0 || library.value < 0) return OA_IPC_UNTRUSTED;
    auto bin = open_component(local.value, "bin", uid, S_IFDIR);
    auto agents = open_component(library.value, "LaunchAgents", uid, S_IFDIR);
    if (bin.value < 0 || agents.value < 0) return OA_IPC_UNTRUSTED;
    auto executable = open_component(bin.value, "openabstractions", uid, S_IFREG, true);
    auto plist = open_component(agents.value, "com.openabstractions.runtime.plist", uid, S_IFREG);
    if (executable.value < 0 || plist.value < 0) return OA_IPC_UNTRUSTED;
    budget = selection_budget(deadline, cancellation); if (budget != OA_IPC_OK) return budget;

    const std::string program = home + "/.local/bin/openabstractions";
    std::vector<UInt8> bytes;
    auto status = read_plist(bytes, plist.value, deadline, cancellation);
    if (status != OA_IPC_OK) return status;
    if (!valid_plist(bytes, program)) return OA_IPC_UNTRUSTED;
    status = selection_budget(deadline, cancellation); if (status != OA_IPC_OK) return status;
    out.kind = OA_IPC_PRINCIPAL_POSIX_UID;
    out.principal = std::to_string(uid);
    out.program = program;
    return OA_IPC_OK;
}
}
#endif
