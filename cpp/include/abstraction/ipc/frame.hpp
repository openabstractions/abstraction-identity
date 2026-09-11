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

// New connection per operation. Millisecond timeout spans connect/send/read.
// EOF completion of WriteFrame is not an application success acknowledgement.
class FrameTransport {
public:
    explicit FrameTransport(std::string endpoint, uint32_t timeout_ms = 5000,
                            uint32_t max_frame = DefaultMaxFrame)
        : endpoint_(std::move(endpoint)), timeout_(timeout_ms),
          limit_(max_frame ? max_frame : DefaultMaxFrame) {}

    void WriteFrame(std::string_view frame) {
        check_size(frame.size());
        Stream stream(endpoint_, Clock::now() + std::chrono::milliseconds(timeout_));
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
        Stream stream(endpoint_, Clock::now() + std::chrono::milliseconds(timeout_));
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
};
}}
