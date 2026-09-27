// Run against an isolated Go XPC echo listener: SERVICE PROGRAM UID.
#include <abstraction/ipc/frame.hpp>
#include <iostream>
#include <stdexcept>

using namespace abstraction::ipc;

static void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: ipc_xpc_client SERVICE PROGRAM UID\n";
        return 2;
    }
    try {
        const std::string endpoint = std::string("xpc:") + argv[1];
        const ServerExpectation server{OA_IPC_PRINCIPAL_POSIX_UID, argv[3], argv[2]};
        auto transport = FrameTransport(endpoint, 5000).with_server_expectation(server);
        for (const auto& request : {std::string(), std::string("native-xpc-echo"), std::string(128 * 1024, 'x')}) {
            require(transport.exchange_frame(request) == request, "XPC echo payload mismatch");
        }
        transport.write_frame("one-way");
        CancellationSource cancelled;
        cancelled.cancel();
        try {
            transport.with_cancellation(cancelled.token()).exchange_frame("must-not-dispatch");
            throw std::runtime_error("cancelled request sent");
        } catch (const FrameError& error) {
            require(error.status == Status::Cancelled, "cancelled request lost typed error");
        }
        auto small = FrameTransport(endpoint, 5000, 8).with_server_expectation(server);
        try {
            small.exchange_frame(std::string(9, 'x'));
            throw std::runtime_error("oversized outgoing frame accepted");
        } catch (const FrameError& error) {
            require(error.status == Status::InvalidArgument, "oversized frame lost typed error");
        }
        auto expired = FrameTransport(endpoint, Clock::now()).with_server_expectation(server);
        try {
            expired.exchange_frame("private");
            throw std::runtime_error("expired request sent");
        } catch (const FrameError& error) {
            require(error.status == Status::Timeout, "expired request lost timeout");
        }
        const ServerExpectation wrong{OA_IPC_PRINCIPAL_POSIX_UID, argv[3], "/usr/bin/true"};
        try {
            FrameTransport(endpoint, 5000).with_server_expectation(wrong).exchange_frame("must-not-dispatch");
            throw std::runtime_error("wrong runtime accepted");
        } catch (const FrameError& error) {
            require(error.status == Status::Untrusted || error.status == Status::Disconnected,
                    "wrong runtime did not report trust/connection refusal");
        }
        std::cout << "PASS C++ XPC Go echo, one-way, cancellation, bounds, deadline and server refusal\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
