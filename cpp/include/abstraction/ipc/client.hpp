#pragma once
#include <abstraction/ipc/client.h>
#include <algorithm>
#include <chrono>
#include <string>
#include <memory>
#include <optional>
#include <utility>
#include <stdexcept>
#include <string_view>
namespace abstraction { namespace ipc {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
enum class Status { ok = OA_IPC_OK, timeout = OA_IPC_TIMEOUT,
    disconnected = OA_IPC_DISCONNECTED, io_error = OA_IPC_IO_ERROR,
    invalid_argument = OA_IPC_INVALID_ARGUMENT, no_memory = OA_IPC_NO_MEMORY,
    internal_error = OA_IPC_INTERNAL_ERROR, cancelled = OA_IPC_CANCELLED,
    untrusted = OA_IPC_UNTRUSTED, proof_unavailable = OA_IPC_PROOF_UNAVAILABLE };

// Independent installation/caller evidence. Values are owned by the copy.
struct ServerExpectation {
    std::uint32_t principal_kind;
    std::string principal, program;
};
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
    friend ServerExpectation SelectRuntime(Deadline, const CancellationToken&);
};

class CancellationSource {
public:
    CancellationSource() {
        oa_ipc_cancellation* handle = nullptr;
        const auto status = oa_ipc_cancellation_create(&handle);
        if (status == OA_IPC_NO_MEMORY) throw std::bad_alloc();
        if (status != OA_IPC_OK) throw std::runtime_error("IPC cancellation creation failed");
        handle_ = std::shared_ptr<oa_ipc_cancellation>(handle, oa_ipc_cancellation_release);
    }
    CancellationToken Token() const { return CancellationToken(handle_); }
    void Cancel() const { oa_ipc_cancellation_signal(handle_.get()); }
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
