// A local byte-stream fixture for the public C session call. Two exchanges
// must use one physical connection and retain their individual frame bounds.
#include <abstraction/ipc/client.h>
#include <abstraction/ipc/frame.hpp>
#include "../../src/session_test_hooks.h"
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace {
constexpr unsigned char session_flag = 0x80;
constexpr unsigned char proof_refusal[6] = {0xff, 0xff, 0xff, 0xfe, 1, 8};
enum class TestCase { ordinary, write_error, pooled_refusal, pooled_one_way_refusal, fresh_refusal,
    single_refusal, single_one_way_refusal, direct_refusal, direct_one_way_refusal,
    direct_malformed, direct_truncated, direct_old_eof, direct_oversize };
bool direct_case(TestCase scenario) {
    return scenario == TestCase::direct_refusal || scenario == TestCase::direct_one_way_refusal ||
        scenario == TestCase::direct_malformed || scenario == TestCase::direct_truncated ||
        scenario == TestCase::direct_old_eof || scenario == TestCase::direct_oversize;
}
std::atomic<int>* received_requests = nullptr;
std::atomic<bool>* release_second = nullptr;
std::atomic<int> injected_writes{0};
std::atomic<int> retry_opens{0};

oa_ipc_status full_write_then_error(oa_ipc_connection* c, const unsigned char* bytes, size_t length, size_t* moved) {
    const auto result = oa_ipc_write(c, bytes, length, moved);
    if (result != OA_IPC_OK || length != 7 || *moved != length) return result;
    ++injected_writes;
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(1);
    while (received_requests->load() < 2 && std::chrono::steady_clock::now() < until)
        std::this_thread::yield();
    release_second->store(true);
    return OA_IPC_IO_ERROR;
}

oa_ipc_status refuse_retry_open(const std::string&, std::chrono::steady_clock::time_point,
    oa_ipc_cancellation*, const oa_ipc_server_expectation*, oa_ipc_connection**) {
    ++retry_opens;
    return OA_IPC_IO_ERROR;
}

bool read_all(
#ifdef _WIN32
    HANDLE
#else
    int
#endif
    peer, unsigned char* bytes, size_t length) {
    for (size_t used = 0; used < length;) {
#ifdef _WIN32
        DWORD n = 0;
        if (!ReadFile(peer, bytes + used, static_cast<DWORD>(length - used), &n, nullptr) || !n) return false;
#else
        const auto n = recv(peer, bytes + used, length - used, 0);
        if (n <= 0) return false;
#endif
        used += static_cast<size_t>(n);
    }
    return true;
}

bool write_all(
#ifdef _WIN32
    HANDLE
#else
    int
#endif
    peer, const unsigned char* bytes, size_t length) {
    for (size_t used = 0; used < length;) {
#ifdef _WIN32
        DWORD n = 0;
        if (!WriteFile(peer, bytes + used, static_cast<DWORD>(length - used), &n, nullptr) || !n) return false;
#else
        const auto n = send(peer, bytes + used, length - used,
#ifdef MSG_NOSIGNAL
            MSG_NOSIGNAL
#else
            0
#endif
        );
        if (n <= 0) return false;
#endif
        used += static_cast<size_t>(n);
    }
    return true;
}

bool serve_two(
#ifdef _WIN32
    HANDLE
#else
    int
#endif
    peer, std::atomic<int>& received, std::atomic<bool>& release, TestCase scenario) {
    for (int i = 0; i < 2; ++i) {
        unsigned char header[4];
        const bool direct = direct_case(scenario);
        const bool one_way = (i == 1 && scenario == TestCase::pooled_one_way_refusal) ||
            (i == 0 && scenario == TestCase::single_one_way_refusal);
        if (!read_all(peer, header, sizeof header) || header[0] != (direct ? 0 : one_way ? 0xc0 : session_flag) ||
            header[1] != 0 || header[2] != 0 || header[3] != 3) return false;
        if (i == 0) {
            if (direct) {
                unsigned char body[3];
                if (!read_all(peer, body, sizeof body)) return false;
                ++received;
                if (scenario == TestCase::direct_old_eof) return true;
                if (scenario == TestCase::direct_oversize) {
                    const unsigned char oversized[4] = {0x40, 0, 0, 0};
                    if (!write_all(peer, oversized, sizeof oversized)) return false;
                } else if (scenario == TestCase::direct_truncated) {
                    if (!write_all(peer, proof_refusal, 5)) return false;
                    return true;
                } else if (scenario == TestCase::direct_malformed) {
                    const unsigned char malformed[6] = {0xff, 0xff, 0xff, 0xfe, 6, 8};
                    if (!write_all(peer, malformed, sizeof malformed)) return false;
                } else if (!write_all(peer, proof_refusal, sizeof proof_refusal)) return false;
                unsigned char byte;
                read_all(peer, &byte, 1);
                return true;
            }
            if (scenario == TestCase::fresh_refusal) {
                if (!write_all(peer, proof_refusal, sizeof proof_refusal)) return false;
                unsigned char byte;
                read_all(peer, &byte, 1);
                return true;
            }
            if (scenario == TestCase::single_refusal || scenario == TestCase::single_one_way_refusal) {
                const unsigned char unsupported[4] = {0x40, 0, 0, 0};
                if (!write_all(peer, unsupported, sizeof unsupported)) return false;
                unsigned char body[3];
                if (!read_all(peer, body, sizeof body)) return false;
                ++received;
                if (!write_all(peer, proof_refusal, sizeof proof_refusal)) return false;
                unsigned char byte;
                read_all(peer, &byte, 1);
                return true;
            }
            const unsigned char accept[4] = {session_flag, 0, 0, 0};
            if (!write_all(peer, accept, sizeof accept)) return false;
        }
        unsigned char body[3];
        if (!read_all(peer, body, sizeof body)) return false;
        ++received;
        if (i == 1 && scenario == TestCase::write_error) {
            const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(1);
            while (!release.load() && std::chrono::steady_clock::now() < until)
                std::this_thread::yield();
            return true;
        }
        if (i == 1 && (scenario == TestCase::pooled_refusal || scenario == TestCase::pooled_one_way_refusal)) {
            if (!write_all(peer, proof_refusal, sizeof proof_refusal)) return false;
            unsigned char byte;
            read_all(peer, &byte, 1);
            return true;
        }
        const unsigned char response[4] = {static_cast<unsigned char>(i == 0 ? session_flag : 0), 0, 0, 3};
        if (!write_all(peer, response, sizeof response) || !write_all(peer, body, sizeof body)) return false;
        if (i == 1) {
            // Keep the Windows pipe alive until the client drains and closes.
            unsigned char byte;
            read_all(peer, &byte, 1);
        }
    }
    return true;
}
bool run_case(TestCase scenario) {
    const bool inject_error = scenario == TestCase::write_error;
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
        "-" + std::to_string(static_cast<int>(scenario));
#ifdef _WIN32
    const std::string endpoint = "\\\\.\\pipe\\oa-ipc-session-" + suffix;
    const std::wstring wide(endpoint.begin(), endpoint.end());
    auto listener = CreateNamedPipeW(wide.c_str(), PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr);
    if (listener == INVALID_HANDLE_VALUE) return 1;
#else
    const std::string endpoint = "/tmp/oa-ipc-session-" + suffix;
    const auto listener = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (listener < 0 || endpoint.size() >= sizeof addr.sun_path) return 1;
    std::memcpy(addr.sun_path, endpoint.c_str(), endpoint.size());
    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof addr) || listen(listener, 1)) return 1;
#endif
    std::atomic<bool> served{false};
    std::atomic<int> received{0};
    std::atomic<bool> release{false};
    std::thread server([&] {
#ifdef _WIN32
        if (ConnectNamedPipe(listener, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED)
            served = serve_two(listener, received, release, scenario);
        DisconnectNamedPipe(listener);
#else
        const auto peer = accept(listener, nullptr, nullptr);
        if (peer >= 0) {
            served = serve_two(peer, received, release, scenario);
            close(peer);
        }
#endif
    });
    bool calls_ok = true;
    injected_writes = 0;
    retry_opens = 0;
    received_requests = &received;
    release_second = &release;
    if (direct_case(scenario)) {
        try {
            abstraction::ipc::FrameTransport transport(endpoint, 2000, 3);
            if (scenario == TestCase::direct_one_way_refusal) transport.write_frame("one");
            else transport.exchange_frame("one");
            calls_ok = false;
        } catch (const abstraction::ipc::FrameError& error) {
            if (scenario == TestCase::direct_refusal || scenario == TestCase::direct_one_way_refusal)
                calls_ok = error.status == abstraction::ipc::Status::ProofUnavailable &&
                    std::string(error.what()).find("user requires signed") != std::string::npos;
            else if (scenario == TestCase::direct_oversize)
                calls_ok = error.status == abstraction::ipc::Status::InvalidArgument;
            else
                calls_ok = error.status != abstraction::ipc::Status::ProofUnavailable;
        }
    } else for (const char* request : {"one", "two"}) {
        if ((scenario == TestCase::fresh_refusal || scenario == TestCase::single_refusal ||
             scenario == TestCase::single_one_way_refusal) && std::strcmp(request, "two") == 0) break;
        if (inject_error && std::strcmp(request, "two") == 0) {
            abstraction::ipc_internal::session_test_write = full_write_then_error;
            abstraction::ipc_internal::session_test_open = refuse_retry_open;
        }
        oa_ipc_reply* reply = nullptr;
        size_t sent = 0;
        const auto status = oa_ipc_session_call(endpoint.c_str(), endpoint.size(), 2000,
            nullptr, nullptr, request, 3, 3,
            (scenario == TestCase::pooled_one_way_refusal && std::strcmp(request, "two") == 0) ||
                scenario == TestCase::single_one_way_refusal ? OA_IPC_CALL_ONE_WAY : 0,
            &reply, &sent);
        size_t length = 0;
        const auto* bytes = oa_ipc_reply_data(reply, &length);
        const bool expected_error = inject_error && std::strcmp(request, "two") == 0;
        const bool expected_refusal = scenario == TestCase::fresh_refusal ||
            scenario == TestCase::single_refusal || scenario == TestCase::single_one_way_refusal ||
            ((scenario == TestCase::pooled_refusal || scenario == TestCase::pooled_one_way_refusal) &&
             std::strcmp(request, "two") == 0);
        if ((expected_error && (status != OA_IPC_IO_ERROR || sent != 3 || reply != nullptr)) ||
            (expected_refusal && (status != OA_IPC_PROOF_UNAVAILABLE ||
                sent != (scenario == TestCase::fresh_refusal ? 0u : 3u) || reply != nullptr)) ||
            (!expected_error && !expected_refusal && (status != OA_IPC_OK || sent != 3 || length != 3 ||
            !bytes || std::memcmp(bytes, request, 3)))) {
            std::fprintf(stderr, "session call %s: status %d, sent %zu, reply %zu\n",
                request, static_cast<int>(status), sent, length);
            calls_ok = false;
        }
        oa_ipc_reply_release(reply);
        if (!calls_ok) break;
    }
    abstraction::ipc_internal::session_test_write = nullptr;
    abstraction::ipc_internal::session_test_open = nullptr;
    server.join();
#ifdef _WIN32
    CloseHandle(listener);
#else
    close(listener);
    unlink(endpoint.c_str());
#endif
    if (inject_error && (injected_writes != 1 || retry_opens != 0)) {
        std::fprintf(stderr, "complete write error: %d writes, %d retry opens\n",
            injected_writes.load(), retry_opens.load());
        calls_ok = false;
    }
    const int want_received = scenario == TestCase::fresh_refusal ? 0 :
        (scenario == TestCase::single_refusal || scenario == TestCase::single_one_way_refusal ||
         direct_case(scenario) ? 1 : 2);
    return calls_ok && served && received == want_received;
}

enum class EarlyControl { valid, partial, malformed, other, eof, cancelled };
enum class EarlyStage { body, header, header_direct, header_declined, header_unsupported,
                        declined_body, unsupported_body };
std::atomic<bool>* early_ready = nullptr;
bool early_pooled = false;
bool early_cancelled = false;
EarlyStage early_stage = EarlyStage::body;
std::atomic<int> early_writes{0};
oa_ipc_status fail_after_early_control(oa_ipc_connection* c, const unsigned char* bytes, size_t length, size_t* moved) {
    const bool header_write = early_stage == EarlyStage::header || early_stage == EarlyStage::header_direct ||
        early_stage == EarlyStage::header_declined || early_stage == EarlyStage::header_unsupported;
    const size_t intercepted = header_write ? 4 : early_pooled ? 7 : 3;
    if (length != intercepted)
        return oa_ipc_write(c, bytes, length, moved);
    ++early_writes;
    *moved = 0;
    if (early_pooled || header_write) {
        const auto status = oa_ipc_write(c, bytes, 4, moved);
        if (status != OA_IPC_OK) return status;
    }
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!early_ready->load() && std::chrono::steady_clock::now() < until)
        std::this_thread::yield();
    return early_cancelled ? OA_IPC_CANCELLED : OA_IPC_IO_ERROR;
}
bool run_early_case(bool pooled, bool one_way, EarlyControl kind, EarlyStage stage = EarlyStage::body) {
    const auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
        "-early-" + std::to_string(static_cast<int>(kind));
#ifdef _WIN32
    const std::string endpoint = "\\\\.\\pipe\\oa-ipc-session-" + suffix;
    const std::wstring wide(endpoint.begin(), endpoint.end());
    auto listener = CreateNamedPipeW(wide.c_str(), PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr);
    if (listener == INVALID_HANDLE_VALUE) return false;
#else
    const std::string endpoint = "/tmp/oa-ipc-session-" + suffix;
    const auto listener = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (listener < 0 || endpoint.size() >= sizeof addr.sun_path) return false;
    std::memcpy(addr.sun_path, endpoint.c_str(), endpoint.size());
    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof addr) || listen(listener, 1)) return false;
#endif
    std::atomic<bool> ready{false};
    std::atomic<bool> served{false};
    std::thread server([&] {
#ifdef _WIN32
        const auto peer = listener;
        if (!(ConnectNamedPipe(listener, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED)) return;
#else
        const auto peer = accept(listener, nullptr, nullptr);
        if (peer < 0) return;
#endif
        bool ok = true;
        if (pooled) {
            unsigned char first[4];
            unsigned char body[3];
            const unsigned char accept[4] = {session_flag, 0, 0, 0};
            const unsigned char answer[7] = {session_flag, 0, 0, 3, 'o', 'n', 'e'};
            ok = read_all(peer, first, sizeof first) && write_all(peer, accept, sizeof accept) &&
                read_all(peer, body, sizeof body) && write_all(peer, answer, sizeof answer);
        }
        unsigned char header[4];
        ok = ok && read_all(peer, header, sizeof header) && header[0] == (one_way ? 0xC0 : session_flag) &&
            header[1] == 0 && header[2] == 0 && header[3] == 3;
        if (ok && !pooled && stage != EarlyStage::header_direct) {
            const unsigned char answer[4] = {
                static_cast<unsigned char>(stage == EarlyStage::declined_body ||
                    stage == EarlyStage::header_declined ? 0 :
                    stage == EarlyStage::unsupported_body || stage == EarlyStage::header_unsupported ?
                    0x40 : session_flag), 0, 0, 0};
            ok = write_all(peer, answer, sizeof answer);
        }
        if (ok && kind != EarlyControl::eof) {
            unsigned char control[6];
            std::memcpy(control, proof_refusal, sizeof control);
            if (kind == EarlyControl::malformed) control[4] = 6;
            if (kind == EarlyControl::other) control[0] = 0x80;
            ok = write_all(peer, control, kind == EarlyControl::partial ? 5 : sizeof control);
        }
        served = ok;
        ready = true;
        if (kind != EarlyControl::eof && kind != EarlyControl::partial) {
            unsigned char byte;
            read_all(peer, &byte, 1); // retain queued control until the client closes
        }
#ifdef _WIN32
        DisconnectNamedPipe(peer);
#else
        close(peer);
#endif
    });
    early_ready = &ready;
    early_pooled = pooled;
    early_cancelled = kind == EarlyControl::cancelled;
    early_stage = stage;
    early_writes = 0;
    retry_opens = 0;
    bool calls_ok = true;
    if (pooled) {
        oa_ipc_reply* first = nullptr;
        size_t sent = 0;
        const auto status = oa_ipc_session_call(endpoint.data(), endpoint.size(), 2000,
            nullptr, nullptr, "one", 3, 3, 0, &first, &sent);
        size_t size = 0;
        const auto* bytes = oa_ipc_reply_data(first, &size);
        calls_ok = status == OA_IPC_OK && sent == 3 && size == 3 && bytes && !std::memcmp(bytes, "one", 3);
        oa_ipc_reply_release(first);
    }
    abstraction::ipc_internal::session_test_write = fail_after_early_control;
    oa_ipc_reply* reply = nullptr;
    size_t sent = 0;
    const auto status = oa_ipc_session_call(endpoint.data(), endpoint.size(), 250,
        nullptr, nullptr, "two", 3, 3, one_way ? OA_IPC_CALL_ONE_WAY : 0, &reply, &sent);
    abstraction::ipc_internal::session_test_write = nullptr;
    const auto expected = kind == EarlyControl::valid ? OA_IPC_PROOF_UNAVAILABLE :
        kind == EarlyControl::cancelled ? OA_IPC_CANCELLED : OA_IPC_IO_ERROR;
    calls_ok = calls_ok && status == expected && reply == nullptr && sent == 0 && early_writes == 1;
    oa_ipc_reply_release(reply);
    server.join();
#ifdef _WIN32
    CloseHandle(listener);
#else
    close(listener);
    unlink(endpoint.c_str());
#endif
    if (!calls_ok || !served) std::fprintf(stderr, "early refusal: pooled %d one-way %d kind %d stage %d status %d sent %zu writes %d served %d\n",
        pooled, one_way, static_cast<int>(kind), static_cast<int>(stage), static_cast<int>(status), sent, early_writes.load(), served.load());
    return calls_ok && served;
}
#ifndef _WIN32
std::atomic<bool>* real_close_ready = nullptr;
std::atomic<int> real_write_status{OA_IPC_OK};
bool real_pooled = false;
oa_ipc_status write_after_real_close(oa_ipc_connection* c, const unsigned char* bytes, size_t length, size_t* moved) {
    const size_t body_length = 2 * 1024 * 1024;
    if (length != body_length + (real_pooled ? 4 : 0)) return oa_ipc_write(c, bytes, length, moved);
    if (real_pooled) {
        const auto status = oa_ipc_write(c, bytes, 4, moved);
        if (status != OA_IPC_OK) return status;
    }
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!real_close_ready->load() && std::chrono::steady_clock::now() < until)
        std::this_thread::yield();
    size_t body_moved = 0;
    const auto status = oa_ipc_write(c, bytes + (real_pooled ? 4 : 0), body_length, &body_moved);
    *moved = body_moved + (real_pooled ? 4 : 0);
    real_write_status = status;
    return status;
}
bool run_real_early_linux(bool pooled, bool one_way) {
    const std::string endpoint = "/tmp/oa-ipc-real-early-" + std::to_string(getpid()) +
        (pooled ? "-pooled" : "-fresh") + (one_way ? "-one" : "-exchange");
    const auto listener = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (listener < 0 || endpoint.size() >= sizeof addr.sun_path) return false;
    std::memcpy(addr.sun_path, endpoint.c_str(), endpoint.size());
    if (bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof addr) || listen(listener, 1)) return false;
    std::atomic<bool> ready{false};
    std::atomic<bool> served{false};
    std::thread server([&] {
        const auto peer = accept(listener, nullptr, nullptr);
        if (peer < 0) return;
        bool first_ok = true;
        if (pooled) {
            unsigned char first[4], body[3];
            const unsigned char accept_word[4] = {session_flag, 0, 0, 0};
            const unsigned char answer[7] = {session_flag, 0, 0, 3, 'o', 'n', 'e'};
            first_ok = read_all(peer, first, sizeof first) &&
                write_all(peer, accept_word, sizeof accept_word) &&
                read_all(peer, body, sizeof body) && write_all(peer, answer, sizeof answer);
        }
        unsigned char header[4];
        const unsigned char accept_word[4] = {session_flag, 0, 0, 0};
        served = first_ok && read_all(peer, header, sizeof header) &&
            header[0] == (one_way ? 0xC0 : session_flag) &&
            (pooled || write_all(peer, accept_word, sizeof accept_word)) &&
            write_all(peer, proof_refusal, sizeof proof_refusal);
        close(peer);
        ready = true;
    });
    real_close_ready = &ready;
    real_write_status = OA_IPC_OK;
    real_pooled = pooled;
    bool first_ok = true;
    if (pooled) {
        oa_ipc_reply* first = nullptr;
        size_t first_sent = 0;
        const auto first_status = oa_ipc_session_call(endpoint.data(), endpoint.size(), 2000,
            nullptr, nullptr, "one", 3, 3, 0, &first, &first_sent);
        size_t first_size = 0;
        const auto* bytes = oa_ipc_reply_data(first, &first_size);
        first_ok = first_status == OA_IPC_OK && first_sent == 3 && first_size == 3 &&
            bytes && !std::memcmp(bytes, "one", 3);
        oa_ipc_reply_release(first);
    }
    abstraction::ipc_internal::session_test_write = write_after_real_close;
    std::string body(2 * 1024 * 1024, 'x');
    oa_ipc_reply* reply = nullptr;
    size_t sent = 0;
    const auto status = oa_ipc_session_call(endpoint.data(), endpoint.size(), 2000,
        nullptr, nullptr, body.data(), body.size(), 1, one_way ? OA_IPC_CALL_ONE_WAY : 0,
        &reply, &sent);
    abstraction::ipc_internal::session_test_write = nullptr;
    oa_ipc_reply_release(reply);
    server.join();
    close(listener);
    unlink(endpoint.c_str());
    const bool ok = first_ok && served && real_write_status != OA_IPC_OK &&
        status == OA_IPC_PROOF_UNAVAILABLE && !reply;
    if (!ok) std::fprintf(stderr, "real early Linux: pooled %d one-way %d write %d result %d sent %zu served %d\n",
        pooled, one_way, real_write_status.load(), static_cast<int>(status), sent, served.load());
    return ok;
}
#endif
} // namespace

int main() {
    oa_ipc_reply* oversized_reply = nullptr;
    size_t oversized_sent = 0;
    const char byte = 'x';
    if (oa_ipc_session_call("x", 1, 100, nullptr, nullptr, &byte, size_t(0x40000000u), 1,
            0, &oversized_reply, &oversized_sent) != OA_IPC_INVALID_ARGUMENT || oversized_reply || oversized_sent)
        return 1;
    return run_case(TestCase::ordinary) && run_case(TestCase::write_error) &&
        run_case(TestCase::fresh_refusal) && run_case(TestCase::pooled_refusal) &&
        run_case(TestCase::pooled_one_way_refusal) && run_case(TestCase::single_refusal) &&
        run_case(TestCase::single_one_way_refusal) && run_case(TestCase::direct_refusal) &&
        run_case(TestCase::direct_one_way_refusal) && run_case(TestCase::direct_malformed) &&
        run_case(TestCase::direct_truncated) && run_case(TestCase::direct_old_eof) &&
        run_case(TestCase::direct_oversize) &&
        run_early_case(false, false, EarlyControl::valid) &&
        run_early_case(false, true, EarlyControl::valid) &&
        run_early_case(false, false, EarlyControl::valid, EarlyStage::header) &&
        run_early_case(false, true, EarlyControl::valid, EarlyStage::header) &&
        run_early_case(false, false, EarlyControl::valid, EarlyStage::header_direct) &&
        run_early_case(false, false, EarlyControl::valid, EarlyStage::header_declined) &&
        run_early_case(false, true, EarlyControl::valid, EarlyStage::header_unsupported) &&
        run_early_case(false, false, EarlyControl::partial, EarlyStage::header) &&
        run_early_case(false, false, EarlyControl::valid, EarlyStage::declined_body) &&
        run_early_case(false, true, EarlyControl::valid, EarlyStage::declined_body) &&
        run_early_case(false, false, EarlyControl::malformed, EarlyStage::declined_body) &&
        run_early_case(false, false, EarlyControl::valid, EarlyStage::unsupported_body) &&
        run_early_case(false, true, EarlyControl::valid, EarlyStage::unsupported_body) &&
        run_early_case(true, false, EarlyControl::valid) &&
        run_early_case(true, true, EarlyControl::valid) &&
        run_early_case(true, false, EarlyControl::partial) &&
        run_early_case(true, false, EarlyControl::malformed) &&
        run_early_case(true, false, EarlyControl::other) &&
        run_early_case(true, false, EarlyControl::eof) &&
        run_early_case(true, false, EarlyControl::cancelled)
#ifndef _WIN32
        && run_real_early_linux(false, false) && run_real_early_linux(false, true) &&
        run_real_early_linux(true, false) && run_real_early_linux(true, true)
#endif
        ? 0 : 1;
}
