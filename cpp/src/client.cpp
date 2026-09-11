#include <abstraction/ipc/client.h>
#include "local_stream.h"
#include <new>
struct oa_ipc_connection {
    abstraction::local_stream::Stream stream;
    oa_ipc_connection(const std::string& path, abstraction::local_stream::Deadline deadline)
        : stream(path, deadline) {}
};
static oa_ipc_status status(const oa_ipc_connection* c) {
    using abstraction::local_stream::Status;
    switch (c->stream.status()) {
    case Status::ok: return OA_IPC_OK;
    case Status::timeout: return OA_IPC_TIMEOUT;
    case Status::disconnected: return OA_IPC_DISCONNECTED;
    default: return OA_IPC_IO_ERROR;
    }
}
extern "C" {
uint32_t oa_ipc_version(void) { return 1; }
oa_ipc_status oa_ipc_open(const char* endpoint, size_t length, uint32_t timeout_ms, oa_ipc_connection** out) {
    if (!out) return OA_IPC_INVALID_ARGUMENT;
    *out = nullptr;
    if (!endpoint || !length) return OA_IPC_INVALID_ARGUMENT;
    const auto deadline = abstraction::local_stream::Clock::now() + std::chrono::milliseconds(timeout_ms);
    try {
        std::string path(endpoint, length);
        if (path.find('\0') != std::string::npos) return OA_IPC_INVALID_ARGUMENT;
        auto* c = new oa_ipc_connection(path, deadline);
        const auto result = status(c);
        if (result != OA_IPC_OK) { delete c; return result; }
        *out = c;
        return OA_IPC_OK;
    } catch (const std::bad_alloc&) { return OA_IPC_NO_MEMORY; }
      catch (...) { return OA_IPC_INTERNAL_ERROR; }
}
oa_ipc_status oa_ipc_write(oa_ipc_connection* c, const void* bytes, size_t length, size_t* moved) {
    if (moved) *moved = 0;
    if (!c || !moved || (!bytes && length)) return OA_IPC_INVALID_ARGUMENT;
    try {
        c->stream.write_all(std::string_view(bytes ? static_cast<const char*>(bytes) : "", length), moved);
        return status(c);
    } catch (const std::bad_alloc&) { return OA_IPC_NO_MEMORY; }
      catch (...) { return OA_IPC_INTERNAL_ERROR; }
}
oa_ipc_status oa_ipc_read(oa_ipc_connection* c, void* bytes, size_t capacity, size_t* moved) {
    if (moved) *moved = 0;
    if (!c || !bytes || !capacity || !moved) return OA_IPC_INVALID_ARGUMENT;
    try {
        c->stream.read_some(bytes, capacity, *moved);
        return status(c);
    } catch (const std::bad_alloc&) { return OA_IPC_NO_MEMORY; }
      catch (...) { return OA_IPC_INTERNAL_ERROR; }
}
void oa_ipc_close(oa_ipc_connection* c) { try { delete c; } catch (...) {} }
}
