// Local listener fixture only; no production server API.
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>
#ifdef _WIN32
#include <windows.h>
static HANDLE listener;
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
static int listener;
#endif
static std::thread worker;
static std::string path;
static bool ok;
extern "C" const char* fixture_start() {
    auto suffix = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
#ifdef _WIN32
    path = "\\\\.\\pipe\\oa-c-consumer-" + suffix;
    std::wstring wide(path.begin(), path.end());
    listener = CreateNamedPipeW(wide.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 1024, 1024, 0, nullptr);
    if (listener == INVALID_HANDLE_VALUE) std::abort();
#else
    path = "/tmp/oa-c-consumer-" + suffix;
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{}; addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size());
    if (listener < 0 || bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) || listen(listener, 1)) std::abort();
#endif
    worker = std::thread([] {
#ifdef _WIN32
        if (!ConnectNamedPipe(listener, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED) return;
        auto peer = listener;
#else
        auto peer = accept(listener, nullptr, nullptr);
        if (peer < 0) return;
#ifdef SO_NOSIGPIPE
        int on = 1; setsockopt(peer, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
#endif
        unsigned char bytes[7];
        size_t used = 0;
        while (used < sizeof bytes) {
#ifdef _WIN32
            DWORD n = 0;
            if (!ReadFile(peer, bytes + used, 1, &n, nullptr) || !n) break;
#else
            auto n = recv(peer, bytes + used, 1, 0);
            if (n <= 0) break;
#endif
            used += n;
        }
        if (used == sizeof bytes) {
#ifdef _WIN32
            DWORD n = 0;
            ok = WriteFile(peer, bytes, sizeof bytes, &n, nullptr) && n == sizeof bytes;
            char ack; ReadFile(peer, &ack, 1, &n, nullptr);
#else
            ok = send(peer, bytes, sizeof bytes,
#ifdef MSG_NOSIGNAL
                MSG_NOSIGNAL
#else
                0
#endif
            ) == sizeof bytes;
            char ack; recv(peer, &ack, 1, 0);
#endif
        }
#ifdef _WIN32
        DisconnectNamedPipe(peer);
#else
        close(peer);
#endif
    });
    return path.c_str();
}
extern "C" int fixture_finish() {
    worker.join();
#ifdef _WIN32
    CloseHandle(listener);
#else
    close(listener); unlink(path.c_str());
#endif
    return ok;
}
