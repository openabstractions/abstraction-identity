#pragma once
#include <atomic>
#include <memory>
#include <stdexcept>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace abstraction { namespace local_stream {
// A signal owns its native wake handle until all participating streams finish.
// It is monotonic; operations requiring a new budget use a new signal.
class Cancellation {
public:
    Cancellation() {
#ifdef _WIN32
        event_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!event_) throw std::runtime_error("IPC cancellation event unavailable");
#else
#ifdef __linux__
        if (::pipe2(pipe_, O_CLOEXEC | O_NONBLOCK) != 0)
            throw std::runtime_error("IPC cancellation pipe unavailable");
#else
        if (::pipe(pipe_) != 0) throw std::runtime_error("IPC cancellation pipe unavailable");
        for (int fd : pipe_) {
            if (::fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 || ::fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
                ::close(pipe_[0]); ::close(pipe_[1]);
                throw std::runtime_error("IPC cancellation pipe setup failed");
            }
        }
#endif
#endif
    }
    ~Cancellation() {
#ifdef _WIN32
        ::CloseHandle(event_);
#else
        ::close(pipe_[0]); ::close(pipe_[1]);
#endif
    }
    Cancellation(const Cancellation&) = delete;
    Cancellation& operator=(const Cancellation&) = delete;
    bool requested() const { return requested_.load(std::memory_order_acquire); }
    void signal() noexcept {
        if (requested_.exchange(true, std::memory_order_acq_rel)) return;
#ifdef _WIN32
        ::SetEvent(event_);
#else
        const char byte = 1;
        while (::write(pipe_[1], &byte, 1) < 0 && errno == EINTR) {}
#endif
    }
#ifdef _WIN32
    HANDLE wake() const { return event_; }
#else
    int wake() const { return pipe_[0]; }
#endif
private:
    std::atomic<bool> requested_{false};
#ifdef _WIN32
    HANDLE event_ = nullptr;
#else
    int pipe_[2]{-1,-1};
#endif
};
}}
