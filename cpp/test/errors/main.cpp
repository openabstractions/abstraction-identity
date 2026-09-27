// An absent runtime and a failed installed-runtime selection name what was
// attempted and the next step, and keep their typed status.
#include <abstraction/ipc/frame.hpp>
#include <iostream>
#include <stdexcept>
#include <string>
using namespace abstraction::ipc;

static void require(bool value, const std::string& message) { if (!value) throw std::runtime_error(message); }
static bool contains(const std::string& text, const std::string& part) { return text.find(part) != std::string::npos; }

int main() {
    try {
        const std::string xpc = "xpc:org.openabstractions.test.absent";
        oa_ipc_connection* raw = nullptr;
        require(oa_ipc_open(xpc.data(), xpc.size(), 100, &raw) == OA_IPC_INVALID_ARGUMENT && !raw,
                "message endpoint accepted by raw stream API");
        for (int exchange = 0; exchange < 2; ++exchange) {
            FrameTransport transport(xpc, 1000);
            try {
                if (exchange) transport.exchange_frame("private"); else transport.write_frame("private");
                require(false, "XPC frame accepted without runtime trust");
            } catch (const FrameError& error) {
                const auto expected = (oa_ipc_features() & OA_IPC_FEATURE_XPC)
                    ? Status::Untrusted : Status::ProofUnavailable;
                require(error.status == expected, "XPC lost transport support/trust refusal");
            }
        }
        const auto suffix = std::to_string(Clock::now().time_since_epoch().count());
#ifdef _WIN32
        const std::string absent = "\\\\.\\pipe\\oa-absent-" + suffix;
#else
        const std::string absent = "/tmp/oa-absent-" + suffix + ".sock";
#endif
        for (int exchange = 0; exchange < 2; ++exchange) {
            FrameTransport transport(absent, 1000);
            try {
                if (exchange) transport.exchange_frame("x"); else transport.write_frame("x");
                require(false, "absent endpoint accepted a frame");
            } catch (const FrameError& error) {
                const std::string what = error.what();
                require(contains(what, "connect " + absent + ": no runtime accepted the connection"), "absent endpoint not named: " + what);
                require(contains(what, "Start the runtime") && contains(what, "--isolated"), "absent endpoint next step missing: " + what);
                require(!contains(what, "frame write failed"), "absent endpoint reported as a write failure: " + what);
                require(error.status == Status::IoError || error.status == Status::Disconnected, "absent endpoint status changed: " + what);
            }
        }
        try {
            select_runtime(Clock::now() - std::chrono::seconds(1));
            require(false, "expired selection succeeded");
        } catch (const FrameError& error) {
            const std::string what = error.what();
            require(error.status == Status::Timeout, "selection status: " + what);
            require(contains(what, "select installed runtime: timed out (timeout); looked for "), "selection wording: " + what);
#ifdef __APPLE__
            require(contains(what, "explicit endpoint and server expectation"), "selection next step missing: " + what);
#else
            require(contains(what, "ABSTRACTION_RUNTIME_ENDPOINT"), "selection next step missing: " + what);
#endif
        }
        const auto untrusted = runtime_selection_failure(Status::Untrusted);
        require(contains(untrusted, "no trusted runtime installation (untrusted)"), "untrusted wording: " + untrusted);
#ifdef _WIN32
        require(contains(untrusted, "MSI registered for the current account"), "Windows selection target: " + untrusted);
#elif defined(__linux__)
        require(contains(untrusted, "abstraction-runtime.service"), "Linux selection target: " + untrusted);
#elif defined(__APPLE__)
        require(contains(untrusted, "LaunchAgent com.openabstractions.runtime"), "macOS selection target: " + untrusted);
#endif
        require(contains(connect_failure("ep", Status::Untrusted), "not the expected runtime (untrusted)"), "untrusted connect wording");
        std::cout << "PASS frame error wording\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
