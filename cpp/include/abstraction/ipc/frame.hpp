#pragma once
#include <abstraction/ipc/client.hpp>
#include <stdexcept>
#include <utility>

namespace abstraction { namespace ipc {
constexpr uint32_t DefaultMaxFrame = 1024 * 1024;

class FrameError : public std::runtime_error {
public:
    Status status;
    explicit FrameError(const char* message, Status s = Status::io_error)
        : std::runtime_error(message), status(s) {}
};

// Snapshot independently selected installation evidence within the caller budget.
inline ServerExpectation SelectRuntime(Deadline deadline, const CancellationToken& token = {}) {
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    auto ms = left <= 0 ? 0 : static_cast<uint32_t>(std::min<decltype(left)>(left, UINT32_MAX));
    oa_ipc_runtime_selection* raw = nullptr;
    auto status = oa_ipc_select_runtime(ms, token.handle_.get(), &raw);
    std::unique_ptr<oa_ipc_runtime_selection, decltype(&oa_ipc_runtime_selection_release)>
        selection(raw, oa_ipc_runtime_selection_release);
    if (status != OA_IPC_OK) throw FrameError("IPC runtime selection failed", static_cast<Status>(status));
    const auto* value = oa_ipc_selected_server(selection.get());
    if (!value || value->version != 1 || !value->principal || !value->program)
        throw FrameError("IPC runtime selection invalid", Status::proof_unavailable);
    return {value->principal_kind, std::string(value->principal, value->principal_length),
            std::string(value->program, value->program_length)};
}

// New connection per operation. Millisecond timeout spans connect/send/read.
// EOF completion of WriteFrame is not an application success acknowledgement.
class FrameTransport {
public:
    explicit FrameTransport(std::string endpoint, uint32_t timeout_ms = 5000,
                            uint32_t max_frame = DefaultMaxFrame)
        : endpoint_(std::move(endpoint)), timeout_(timeout_ms),
          limit_(max_frame ? max_frame : DefaultMaxFrame) {}

    // An absolute deadline is shared by every exchange using this transport.
    FrameTransport(std::string endpoint, Deadline deadline, uint32_t max_frame = DefaultMaxFrame)
        : endpoint_(std::move(endpoint)), timeout_(0), limit_(max_frame ? max_frame : DefaultMaxFrame),
          deadline_(deadline), fixed_deadline_(true) {}

    // Cancellation affects waiting for calls using this copy. It never sends
    // provider cancellation or changes the original transport.
    FrameTransport WithCancellation(CancellationToken token) const {
        auto copy = *this;
        copy.cancellation_ = std::move(token);
        return copy;
    }

    FrameTransport WithServerExpectation(std::optional<ServerExpectation> server) const {
        auto copy = *this; copy.server_ = std::move(server); return copy;
    }
    void WriteFrame(std::string_view frame) {
        check_size(frame.size());
        Stream stream(endpoint_, operation_deadline(), cancellation_, server_);
        send(stream, frame);
        char byte;
        size_t moved = 0;
        if (stream.read_some(&byte, 1, moved))
            throw FrameError("unexpected response to one-way frame");
        if (stream.status() != Status::disconnected)
            throw FrameError("frame completion failed", stream.status());
    }

    std::string ExchangeFrame(std::string_view frame) {
        check_size(frame.size());
        Stream stream(endpoint_, operation_deadline(), cancellation_, server_);
        send(stream, frame);
        unsigned char header[4];
        read_exact(stream, header, sizeof header);
        const uint32_t size = (uint32_t(header[0]) << 24) |
            (uint32_t(header[1]) << 16) | (uint32_t(header[2]) << 8) | header[3];
        check_size(size); // reject before allocation
        std::string reply(size, '\0');
        read_exact(stream, reply.data(), reply.size());
        return reply;
    }

private:
    Deadline operation_deadline() const {
        const auto now = Clock::now();
        if (fixed_deadline_ && deadline_ <= now)
            throw FrameError("call deadline expired", Status::timeout);
        return fixed_deadline_ ? deadline_ : now + std::chrono::milliseconds(timeout_);
    }
    void check_size(size_t size) const {
        if (size > limit_ || size > UINT32_MAX)
            throw FrameError("frame too large", Status::invalid_argument);
    }
    static void send(Stream& stream, std::string_view frame) {
        const auto size = static_cast<uint32_t>(frame.size());
        const char header[4] = {char(size >> 24), char(size >> 16), char(size >> 8), char(size)};
        if (!stream.valid() || !stream.write_all(std::string_view(header, 4)) ||
            !stream.write_all(frame))
            throw FrameError("frame write failed", stream.status());
    }
    static void read_exact(Stream& stream, void* bytes, size_t count) {
        auto* next = static_cast<char*>(bytes);
        while (count) {
            size_t moved = 0;
            if (!stream.read_some(next, count, moved))
                throw FrameError("truncated frame or read failure", stream.status());
            next += moved;
            count -= moved;
        }
    }
    std::string endpoint_;
    uint32_t timeout_, limit_;
    Deadline deadline_{};
    bool fixed_deadline_ = false;
    CancellationToken cancellation_;
    std::optional<ServerExpectation> server_;
};
}}
