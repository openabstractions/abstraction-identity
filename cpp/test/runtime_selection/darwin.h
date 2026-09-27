#ifdef __APPLE__
#include <filesystem>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

namespace darwin_test {
namespace fs = std::filesystem;

struct Fixture {
    fs::path home;
    Fixture() {
        char pattern[] = "/private/tmp/oa-runtime-selection-XXXXXX";
        const char* made = ::mkdtemp(pattern);
        if (!made) throw std::runtime_error("temporary home");
        home = made;
        fs::create_directories(home / ".local/bin");
        fs::create_directories(home / "Library/LaunchAgents");
        for (const auto& path : {home, home / ".local", home / ".local/bin",
                home / "Library", home / "Library/LaunchAgents"})
            ::chmod(path.c_str(), 0700);
        std::ofstream executable(home / ".local/bin/openabstractions");
        executable << "fixture";
        executable.close();
        ::chmod((home / ".local/bin/openabstractions").c_str(), 0700);
    }
    ~Fixture() {
        if (home.filename().string().rfind("oa-runtime-selection-", 0) == 0)
            fs::remove_all(home);
    }
    fs::path program() const { return home / ".local/bin/openabstractions"; }
    fs::path plist() const { return home / "Library/LaunchAgents/com.openabstractions.runtime.plist"; }
    void write(const std::string& label = "com.openabstractions.runtime", bool extra = false,
        const std::string* program_value = nullptr, bool duplicate_label = false, unsigned nesting = 0) {
        static const char* const services[] = {
            "runtime-v1", "logging-v1", "config-v1", "job-acceptance-v1", "router-v1", "model-v1",
            "storage-content-v1", "asks-application-v1", "rights-authorization-v1", "credentials-v1",
            "inference-v1", "inference-remote-v1", "registry-v1", "applications-v1",
            "resource-table-v1", "lend-v1"
        };
        std::ofstream out(plist(), std::ios::binary | std::ios::trunc);
        out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
               "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
               "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
               "<plist version=\"1.0\"><dict><key>Label</key><string>" << label << "</string>"
               << (duplicate_label ? "<key>Label</key><string>com.openabstractions.runtime</string>" : "");
        if (program_value) out << "<key>Program</key><string>" << *program_value << "</string>";
        out <<
               "<key>ProgramArguments</key><array><string>" << (home / ".local/bin/openabstractions").string() <<
               "</string><string>serve</string><string>runtime</string><string>--xpc</string></array>";
        if (nesting) {
            out << "<key>IgnoredDeepValue</key>";
            for (unsigned i = 0; i < nesting; ++i) out << "<array>";
            out << "<string>value</string>";
            for (unsigned i = 0; i < nesting; ++i) out << "</array>";
        }
        out << "<key>MachServices</key><dict>";
        for (const char* service : services)
            out << "<key>com.openabstractions." << service << "</key><true/>";
        if (extra) out << "<key>com.openabstractions.unexpected</key><true/>";
        out << "</dict></dict></plist>";
        out.close();
        ::chmod(plist().c_str(), 0600);
    }
};
}

inline void darwin_tests() {
    using namespace abstraction;
    using namespace ipc_internal;
    auto deadline = local_stream::Clock::now() + std::chrono::seconds(2);
    darwin_test::Fixture fixture;
    fixture.write();
    RuntimeIdentity identity;
    require(darwin_selection::select(identity, deadline, nullptr, ::geteuid(), fixture.home.string()) == OA_IPC_OK,
        "registered LaunchAgent selection");
    require(identity.kind == OA_IPC_PRINCIPAL_POSIX_UID && identity.principal == std::to_string(::geteuid()) &&
        identity.program == (fixture.home / ".local/bin/openabstractions").string(), "selected Darwin snapshot");

    const auto expected_program = fixture.program().string();
    fixture.write("com.openabstractions.runtime", false, &expected_program);
    require(darwin_selection::select(identity, deadline, nullptr, ::geteuid(), fixture.home.string()) == OA_IPC_OK,
        "matching optional Program");
    const std::string wrong_program = "/tmp/not-openabstractions";
    fixture.write("com.openabstractions.runtime", false, &wrong_program);
    require(darwin_selection::select(identity, deadline, nullptr, ::geteuid(), fixture.home.string()) == OA_IPC_UNTRUSTED,
        "mismatched optional Program");
    fixture.write("com.openabstractions.runtime", false, nullptr, true);
    require(darwin_selection::select(identity, deadline, nullptr, ::geteuid(), fixture.home.string()) == OA_IPC_UNTRUSTED,
        "duplicate plist key");

    const std::string truncated = "<?xml version=\"1.0\"?><plist><dict><key>Label</key><string>broken";
    const std::vector<UInt8> truncated_bytes(truncated.begin(), truncated.end());
    for (unsigned i = 0; i < 1000; ++i)
        require(!darwin_selection::valid_plist(truncated_bytes, expected_program), "truncated plist");
    deadline = local_stream::Clock::now() + std::chrono::seconds(2);
    fixture.write("com.openabstractions.runtime", false, nullptr, false, 80);
    require(darwin_selection::select(identity, deadline, nullptr, ::geteuid(), fixture.home.string()) == OA_IPC_UNTRUSTED,
        "excessive plist nesting");

    fixture.write("wrong.label");
    require(darwin_selection::select(identity, deadline, nullptr, ::geteuid(), fixture.home.string()) == OA_IPC_UNTRUSTED,
        "wrong LaunchAgent label");
    fixture.write("com.openabstractions.runtime", true);
    require(darwin_selection::select(identity, deadline, nullptr, ::geteuid(), fixture.home.string()) == OA_IPC_UNTRUSTED,
        "unexpected Mach service");

    fixture.write();
    {
        std::ofstream oversized(fixture.plist(), std::ios::binary | std::ios::app);
        oversized << std::string(64 * 1024, ' ');
    }
    require(darwin_selection::select(identity, deadline, nullptr, ::geteuid(), fixture.home.string()) == OA_IPC_UNTRUSTED,
        "oversized plist");

    fixture.write();
    darwin_test::fs::remove(fixture.plist());
    require(::mkfifo(fixture.plist().c_str(), 0600) == 0, "plist FIFO fixture");
    require(darwin_selection::select(identity, deadline, nullptr, ::geteuid(), fixture.home.string()) == OA_IPC_UNTRUSTED,
        "plist FIFO");
    darwin_test::fs::remove(fixture.plist());
    fixture.write();
    darwin_test::fs::path moved = fixture.home / ".local/bin/openabstractions.real";
    darwin_test::fs::rename(fixture.program(), moved);
    require(::mkfifo(fixture.program().c_str(), 0700) == 0, "executable FIFO fixture");
    require(darwin_selection::select(identity, deadline, nullptr, ::geteuid(), fixture.home.string()) == OA_IPC_UNTRUSTED,
        "executable FIFO");
    darwin_test::fs::remove(fixture.program());
    darwin_test::fs::create_symlink(moved, fixture.program());
    require(darwin_selection::select(identity, deadline, nullptr, ::geteuid(), fixture.home.string()) == OA_IPC_UNTRUSTED,
        "symlink executable");
}
#endif
