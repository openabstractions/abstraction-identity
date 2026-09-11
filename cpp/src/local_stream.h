#pragma once

// Internal client byte stream. No framing, discovery, or listener policy.
#include <algorithm>
#include <chrono>
#include <climits>
#include <cstring>
#include <string>
#include <string_view>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif


namespace abstraction { namespace local_stream {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
enum class Status { ok, timeout, disconnected, io_error };
namespace detail {
inline int remaining_ms(Deadline deadline) {
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return left <= 0 ? 0 : static_cast<int>(std::min<decltype(left)>(left, INT_MAX));
}
// ------------------------------------------------------------------ windows ---
//
// Everything in this block exists because of one sentence in the contract, and
// the sentence is right: a synchronous read against a server that accepts and
// never writes hangs forever. There is no timeout above it that helps. The
// pipe's own default timeout applies to WaitNamedPipe — to waiting for a BUSY
// instance — and has nothing to do with how long a read may take. A worker
// thread does not help either: a thread blocked in a synchronous ReadFile on a
// pipe cannot be cancelled, so abandoning it leaks a thread and a handle per
// call and leaves the process unable to exit. FILE_FLAG_OVERLAPPED plus
// CancelIoEx is the only correct answer.

#ifdef _WIN32

// One ReadFile or WriteFile that honours the deadline. Returns false to give up.
//
// The shape that matters: issue the operation; if it comes back
// ERROR_IO_PENDING, wait on the event for the REMAINING budget only. On timeout
// CancelIoEx, and then wait for the cancellation to actually land before the
// OVERLAPPED and the buffer go out of scope — the kernel may write into both
// until the operation completes, and letting them die first corrupts stack that
// is no longer ours. That last wait is the step a first attempt always omits.
template <typename Fn>
inline bool overlapped_io(Fn&& fn, HANDLE handle, void* buffer, DWORD bytes, Deadline deadline,
                   DWORD* moved) {
    OVERLAPPED ov{};
    ov.hEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (ov.hEvent == nullptr) return false;

    bool ok = fn(handle, buffer, bytes, moved, &ov) != 0;
    if (!ok) {
        const DWORD err = ::GetLastError();
        if (err != ERROR_IO_PENDING) {
            ::CloseHandle(ov.hEvent);
            ::SetLastError(err);
            return false;  // including ERROR_BROKEN_PIPE, which is EOF
        }
        if (::WaitForSingleObject(ov.hEvent, remaining_ms(deadline)) != WAIT_OBJECT_0) {
            ::CancelIoEx(handle, &ov);
            // bWait = TRUE: block until the cancelled operation is genuinely
            // finished with our buffer. It returns promptly.
            ::GetOverlappedResult(handle, &ov, moved, TRUE);
            ::CloseHandle(ov.hEvent);
            ::SetLastError(ERROR_TIMEOUT);
            return false;
        }
        ok = ::GetOverlappedResult(handle, &ov, moved, FALSE) != 0;
    }
    const DWORD error = ok ? ERROR_SUCCESS : ::GetLastError();
    ::CloseHandle(ov.hEvent);
    ::SetLastError(error);
    return ok;
}

// CreateFile on the pipe, with rule 8's single retry on ERROR_PIPE_BUSY.
//
// Busy is not absent. It means every instance of a pipe that DOES exist is
// currently talking to somebody, and reporting absent there makes a supervisor
// look dead precisely when it is busiest.
inline HANDLE open_pipe(const std::string& path, Deadline deadline) {
    const std::wstring wide(path.begin(), path.end());  // the name is hex ASCII
    const DWORD flags =
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION;
    for (int attempt = 0; attempt < 2; ++attempt) {
        const HANDLE h = ::CreateFileW(wide.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                       OPEN_EXISTING, flags, nullptr);
        if (h != INVALID_HANDLE_VALUE) return h;
        if (::GetLastError() != ERROR_PIPE_BUSY || attempt == 1) return INVALID_HANDLE_VALUE;
        const int left = remaining_ms(deadline);
        // Wait inside the remaining budget, never beyond it.
        if (left <= 0 || !::WaitNamedPipeW(wide.c_str(), static_cast<DWORD>(left))) {
            return INVALID_HANDLE_VALUE;
        }
    }
    return INVALID_HANDLE_VALUE;
}


#else
// A write to a socket the peer has closed raises SIGPIPE, and the default
// disposition kills the process. A discovery call that terminates its caller
// because a supervisor exited mid-handshake is the loudest possible version of
// the failure rule 1 says must be silent. Linux spells the fix MSG_NOSIGNAL on
// the send; macOS has no such flag and spells it SO_NOSIGPIPE on the socket.
#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif

inline void suppress_sigpipe(int fd) {
#if defined(SO_NOSIGPIPE)
    const int on = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#else
    (void)fd;
#endif
}

inline bool wait_ready(int fd, short events, Deadline deadline) {
    const int left = remaining_ms(deadline);
    if (left <= 0) return false;
    struct pollfd pfd {};
    pfd.fd = fd;
    pfd.events = events;
    for (;;) {
        const int rc = ::poll(&pfd, 1, remaining_ms(deadline));
        if (rc > 0) return true;
        if (rc == 0) return false;                 // the deadline
        if (errno != EINTR) return false;
        if (remaining_ms(deadline) <= 0) return false;  // a signal, then the deadline
    }
}


#endif
} // namespace detail

// A stream owns its connection and ONE absolute budget across all operations.
// A false operation may have transferred a prefix; callers must not retry a
// complete application message on that connection. Destruction closes it.
class Stream {
public:
    Stream(const std::string& path, Deadline deadline) : deadline_(deadline) {
        if (!budget()) return;
        if (path.find('\0') != std::string::npos) { status_ = Status::io_error; return; }
#ifdef _WIN32
        const std::string prefix = "\\\\.\\pipe\\";
        if (path.size() <= prefix.size() || path.compare(0, prefix.size(), prefix) != 0) {
            status_ = Status::io_error; return;
        }
        // Discovery's published pipe names are ASCII. Reject other spelling
        // explicitly until a shared runtime defines endpoint text encoding.
        for (unsigned char c : path) if (c > 127) { status_ = Status::io_error; return; }
        handle_ = detail::open_pipe(path, deadline_);
        if (handle_ == INVALID_HANDLE_VALUE) fail();
#else
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (path.size() >= sizeof(addr.sun_path)) { status_ = Status::io_error; return; }
        std::memcpy(addr.sun_path, path.c_str(), path.size());
        handle_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (handle_ < 0) { fail(); return; }
        detail::suppress_sigpipe(handle_);
        const int flags = ::fcntl(handle_, F_GETFL, 0);
        if (flags < 0 || ::fcntl(handle_, F_SETFL, flags | O_NONBLOCK) < 0) { fail(); return; }
        if (::connect(handle_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            if (errno != EINPROGRESS || !detail::wait_ready(handle_, POLLOUT, deadline_)) { fail(); return; }
            int err = 0;
            socklen_t len = sizeof(err);
            if (::getsockopt(handle_, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) { fail(); return; }
        }
#endif
    }
    ~Stream() {
#ifdef _WIN32
        if (handle_ != INVALID_HANDLE_VALUE) ::CloseHandle(handle_);
#else
        if (handle_ >= 0) ::close(handle_);
#endif
    }
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    bool valid() const { return status_ == Status::ok; }
    Status status() const { return status_; }
    bool write_all(std::string_view bytes, std::size_t* transferred = nullptr) {
        if (transferred) *transferred = 0;
        if (!valid()) return false;
        std::size_t sent = 0;
        while (sent < bytes.size()) {
            if (!budget()) return false;
            const auto count = std::min<std::size_t>(bytes.size() - sent, INT_MAX);
#ifdef _WIN32
            DWORD moved = 0;
            if (!detail::overlapped_io(&::WriteFile, handle_, const_cast<char*>(bytes.data() + sent),
                                      static_cast<DWORD>(count), deadline_, &moved)) return fail();
#else
            if (!detail::wait_ready(handle_, POLLOUT, deadline_)) return fail();
            const ssize_t moved = ::send(handle_, bytes.data() + sent, count, detail::kSendFlags);
            if (moved < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                return fail();
            }
#endif
            if (moved == 0) { status_ = Status::disconnected; return false; }
            sent += static_cast<std::size_t>(moved);
            if (transferred) *transferred = sent;
        }
        return true;
    }
    // Success returns at least one byte. Zero capacity is a caller error.
    bool read_some(void* buffer, std::size_t capacity, std::size_t& moved) {
        moved = 0;
        if (!valid()) return false;
        if (!buffer || capacity == 0) { status_ = Status::io_error; return false; }
        for (;;) {
            if (!budget()) return false;
            const auto count = std::min<std::size_t>(capacity, INT_MAX);
#ifdef _WIN32
            DWORD n = 0;
            if (!detail::overlapped_io(&::ReadFile, handle_, buffer, static_cast<DWORD>(count), deadline_, &n)) return fail();
#else
            if (!detail::wait_ready(handle_, POLLIN, deadline_)) return fail();
            const ssize_t n = ::recv(handle_, buffer, count, 0);
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                return fail();
            }
#endif
            if (n == 0) { status_ = Status::disconnected; return false; }
            moved = static_cast<std::size_t>(n);
            return true;
        }
    }
private:
    bool budget() {
        if (detail::remaining_ms(deadline_) > 0) return true;
        status_ = Status::timeout;
        return false;
    }
    bool fail() {
#ifdef _WIN32
        const auto err = ::GetLastError();
#else
        const auto err = errno;
#endif
        if (!budget()) return false;
#ifdef _WIN32
        if (err == ERROR_TIMEOUT) { status_ = Status::timeout; return false; }
        status_ = (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) ? Status::disconnected : Status::io_error;
#else
        status_ = (err == EPIPE || err == ECONNRESET) ? Status::disconnected : Status::io_error;
#endif
        return false;
    }
    Deadline deadline_;
    Status status_ = Status::ok;
#ifdef _WIN32
    HANDLE handle_ = INVALID_HANDLE_VALUE;
#else
    int handle_ = -1;
#endif
};
}} // namespace abstraction::local_stream
