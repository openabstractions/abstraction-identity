#pragma once
#include <abstraction/ipc/client.h>
#include <algorithm>
#include <chrono>
#include <string>
#include <string_view>
namespace abstraction { namespace ipc {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
enum class Status { ok = OA_IPC_OK, timeout = OA_IPC_TIMEOUT,
    disconnected = OA_IPC_DISCONNECTED, io_error = OA_IPC_IO_ERROR,
    invalid_argument = OA_IPC_INVALID_ARGUMENT, no_memory = OA_IPC_NO_MEMORY,
    internal_error = OA_IPC_INTERNAL_ERROR };
class Stream {
public:
    Stream(const std::string& path, Deadline deadline) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
        auto ms = left <= 0 ? 0 : static_cast<uint32_t>(std::min<decltype(left)>(left, UINT32_MAX));
        status_ = oa_ipc_open(path.data(), path.size(), ms, &connection_);
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
