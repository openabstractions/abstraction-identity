#pragma once
#include <abstraction/ipc/client.hpp>
#include <stdexcept>
#include <utility>

namespace abstraction { namespace ipc {
constexpr uint32_t kDefaultMaxFrame = 1024 * 1024;

class FrameError : public std::runtime_error {
public:
    Status status;
    explicit FrameError(const char* message, Status s = Status::IoError)
        : std::runtime_error(message), status(s) {}
    FrameError(const std::string& message, Status s)
        : std::runtime_error(message), status(s) {}
};

inline const char* status_name(Status status) {
    switch (status) {
    case Status::Ok: return "ok";
    case Status::Timeout: return "timeout";
    case Status::Disconnected: return "disconnected";
    case Status::IoError: return "io_error";
    case Status::InvalidArgument: return "invalid_argument";
    case Status::NoMemory: return "no_memory";
    case Status::InternalError: return "internal_error";
    case Status::Cancelled: return "cancelled";
    case Status::Untrusted: return "untrusted";
    case Status::ProofUnavailable: return "proof_unavailable";
    }
    return "unknown";
}

// Names what installed-runtime selection looked for and the next step. The
// Go client reports the same cases as "select installed runtime: ...".
inline std::string runtime_selection_failure(Status status) {
    std::string reason;
    switch (status) {
    case Status::Untrusted: reason = "no trusted runtime installation"; break;
    case Status::ProofUnavailable: reason = "trusted installation selection is not implemented on this platform"; break;
    case Status::Timeout: reason = "timed out"; break;
    case Status::Cancelled: reason = "cancelled"; break;
    default: reason = "installation query failed"; break;
    }
    const char* looked_for =
#ifdef _WIN32
        "the OpenAbstractions runtime MSI registered for the current account";
#elif defined(__linux__)
        "the loaded systemd user unit abstraction-runtime.service";
#else
        "nothing: this platform has no installed-runtime selector";
#endif
    return "select installed runtime: " + reason + " (" + status_name(status) + "); looked for " + looked_for +
        ". Install and start the runtime, or for a runtime you started yourself construct the client with its "
        "endpoint, e.g. ResolutionClient(runtime_endpoint()) to use ABSTRACTION_RUNTIME_ENDPOINT";
}

// Names the endpoint a connection could not reach and the next step.
inline std::string connect_failure(const std::string& endpoint, Status status) {
    std::string reason;
    switch (status) {
    case Status::Untrusted: reason = "the listening process is not the expected runtime"; break;
    case Status::ProofUnavailable: reason = "server identity proof is unavailable on this platform"; break;
    case Status::Timeout: reason = "no runtime accepted the connection before the deadline"; break;
    case Status::Cancelled: reason = "cancelled while connecting"; break;
    default: reason = "no runtime accepted the connection"; break;
    }
    return "connect " + endpoint + ": " + reason + " (" + status_name(status) +
        "). Start the runtime (openabstractions start, or openabstractions serve runtime --isolated <name> "
        "--state-dir <dir>) or correct the endpoint";
}

// Snapshot independently selected installation evidence within the caller budget.
inline ServerExpectation select_runtime(Deadline deadline, const CancellationToken& token = {}) {
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    auto ms = left <= 0 ? 0 : static_cast<uint32_t>(std::min<decltype(left)>(left, UINT32_MAX));
    oa_ipc_runtime_selection* raw = nullptr;
    auto status = oa_ipc_select_runtime(ms, token.handle_.get(), &raw);
    std::unique_ptr<oa_ipc_runtime_selection, decltype(&oa_ipc_runtime_selection_release)>
        selection(raw, oa_ipc_runtime_selection_release);
    if (status != OA_IPC_OK)
        throw FrameError(runtime_selection_failure(static_cast<Status>(status)), static_cast<Status>(status));
    const auto* value = oa_ipc_selected_server(selection.get());
    if (!value || value->version != 1 || !value->principal || !value->program)
        throw FrameError("select installed runtime: the selection returned no usable server identity", Status::ProofUnavailable);
    return {value->principal_kind, std::string(value->principal, value->principal_length),
            std::string(value->program, value->program_length)};
}

// New connection per operation. Millisecond timeout spans connect/send/read.
// EOF completion of write_frame is not an application success acknowledgement.
class FrameTransport {
public:
    explicit FrameTransport(std::string endpoint, uint32_t timeout_ms = 5000,
                            uint32_t max_frame = kDefaultMaxFrame)
        : endpoint_(std::move(endpoint)), timeout_(timeout_ms),
          limit_(max_frame ? max_frame : kDefaultMaxFrame) {}

    // An absolute deadline is shared by every exchange using this transport.
    FrameTransport(std::string endpoint, Deadline deadline, uint32_t max_frame = kDefaultMaxFrame)
        : endpoint_(std::move(endpoint)), timeout_(0), limit_(max_frame ? max_frame : kDefaultMaxFrame),
          deadline_(deadline), fixed_deadline_(true) {}

    // Cancellation affects waiting for calls using this copy. It never sends
    // provider cancellation or changes the original transport.
    FrameTransport with_cancellation(CancellationToken token) const {
        auto copy = *this;
        copy.cancellation_ = std::move(token);
        return copy;
    }

    FrameTransport with_server_expectation(std::optional<ServerExpectation> server) const {
        auto copy = *this; copy.server_ = std::move(server); return copy;
    }
    // A copy that keeps verified connections for later calls through
    // oa_ipc_session_call (FRAMING.md "Sessions"). Ask only where the server
    // answers or closes an oversized header.
    FrameTransport with_sessions(bool sessions = true) const {
        auto copy = *this; copy.sessions_ = sessions; return copy;
    }
    void write_frame(std::string_view frame) {
        check_size(frame.size());
        if (sessions_) { session_call(frame, true); return; }
        Stream stream(endpoint_, operation_deadline(), cancellation_, server_);
        send(stream, frame);
        char byte;
        size_t moved = 0;
        if (stream.read_some(&byte, 1, moved))
            throw FrameError("unexpected response to one-way frame");
        if (stream.status() != Status::Disconnected)
            throw FrameError("frame completion failed", stream.status());
    }

    std::string exchange_frame(std::string_view frame) {
        check_size(frame.size());
        if (sessions_) return session_call(frame, false);
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
            throw FrameError("call deadline expired", Status::Timeout);
        return fixed_deadline_ ? deadline_ : now + std::chrono::milliseconds(timeout_);
    }
    void check_size(size_t size) const {
        if (size > limit_ || size > UINT32_MAX)
            throw FrameError("frame too large", Status::InvalidArgument);
    }
    void send(Stream& stream, std::string_view frame) const {
        const auto size = static_cast<uint32_t>(frame.size());
        const char header[4] = {char(size >> 24), char(size >> 16), char(size >> 8), char(size)};
        if (!stream.valid()) throw FrameError(connect_failure(endpoint_, stream.status()), stream.status());
        if (!stream.write_all(std::string_view(header, 4)) || !stream.write_all(frame))
            throw FrameError("frame write to " + endpoint_ + " failed (" + status_name(stream.status()) +
                "); the request may have reached the runtime", stream.status());
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
    bool sessions_ = false;

    std::string session_call(std::string_view frame, bool one_way) const {
        const auto now = Clock::now();
        const auto deadline = operation_deadline();
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        const auto ms = left <= 0 ? 0 : static_cast<uint32_t>(std::min<decltype(left)>(left, UINT32_MAX));
        oa_ipc_server_expectation expected{};
        if (server_)
            expected = {sizeof(oa_ipc_server_expectation), 1, server_->principal_kind, 0, server_->principal.data(),
                        server_->principal.size(), server_->program.data(), server_->program.size()};
        oa_ipc_reply* raw = nullptr;
        size_t sent = 0;
        const auto status = static_cast<Status>(oa_ipc_session_call(endpoint_.data(), endpoint_.size(), ms,
            cancellation_.handle_.get(), server_ ? &expected : nullptr, frame.data(), frame.size(), limit_,
            one_way ? OA_IPC_CALL_ONE_WAY : 0, &raw, &sent));
        std::unique_ptr<oa_ipc_reply, decltype(&oa_ipc_reply_release)> reply(raw, oa_ipc_reply_release);
        if (status != Status::Ok) {
            if (status == Status::InvalidArgument) throw FrameError("frame too large", status);
            if (sent == 0) throw FrameError(connect_failure(endpoint_, status), status);
            throw FrameError("frame exchange with " + endpoint_ + " failed (" + status_name(status) +
                "); the request may have reached the runtime", status);
        }
        if (one_way) return {};
        size_t length = 0;
        const auto* data = oa_ipc_reply_data(reply.get(), &length);
        return std::string(data ? reinterpret_cast<const char*>(data) : "", length);
    }
};
}}
