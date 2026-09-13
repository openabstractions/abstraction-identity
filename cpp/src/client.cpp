#include <abstraction/ipc/client.h>
#include <abstraction/ipc/bootstrap.hpp>
#include <cstring>
#include <system_error>
#include "local_stream.h"
#include "server_guard.h"
#include "runtime_selection.h"
#include <new>
struct oa_ipc_cancellation {
    std::shared_ptr<abstraction::local_stream::Cancellation> state =
        std::make_shared<abstraction::local_stream::Cancellation>();
};
struct oa_ipc_runtime_selection {
    abstraction::ipc_internal::RuntimeIdentity identity;
    oa_ipc_server_expectation expectation{};
    explicit oa_ipc_runtime_selection(abstraction::ipc_internal::RuntimeIdentity value) : identity(std::move(value)) {
        expectation={sizeof(expectation),1,identity.kind,0,identity.principal.data(),identity.principal.size(),identity.program.data(),identity.program.size()};
    }
};
struct oa_ipc_connection {
    abstraction::local_stream::Stream stream;
    std::unique_ptr<abstraction::ipc_internal::ServerGuard> server;
    oa_ipc_status trust_status = OA_IPC_OK;
    oa_ipc_connection(const std::string& path, abstraction::local_stream::Deadline deadline,
        std::shared_ptr<abstraction::local_stream::Cancellation> cancellation)
        : stream(path, deadline, std::move(cancellation)) {}
};
static oa_ipc_status status(const oa_ipc_connection* c) {
    using abstraction::local_stream::Status;
    switch (c->stream.status()) {
    case Status::ok: return c->trust_status;
    case Status::timeout: return OA_IPC_TIMEOUT;
    case Status::cancelled: return OA_IPC_CANCELLED;
    case Status::disconnected: return OA_IPC_DISCONNECTED;
    default: return OA_IPC_IO_ERROR;
    }
}
static oa_ipc_status checked_status(oa_ipc_connection* c) {
    if (!c->server) return status(c); // Preserve endpoint-only compatibility behavior.
    if (!c->stream.check_budget()) return status(c);
    if (c->trust_status == OA_IPC_OK && c->server && !c->server->check()) c->trust_status = OA_IPC_UNTRUSTED;
    // Preserve cancellation/deadline if a metadata query consumed the budget.
    c->stream.check_budget();
    return status(c);
}
extern "C" {
oa_ipc_status oa_ipc_select_runtime(uint32_t timeout_ms, oa_ipc_cancellation* cancellation, oa_ipc_runtime_selection** out) {
    if(!out)return OA_IPC_INVALID_ARGUMENT;
    *out=nullptr;
    try {
        abstraction::ipc_internal::RuntimeIdentity selected;
        auto deadline=abstraction::local_stream::Clock::now()+std::chrono::milliseconds(timeout_ms);
        auto status=abstraction::ipc_internal::select_runtime_identity(selected,deadline,cancellation?cancellation->state.get():nullptr);
        if(status!=OA_IPC_OK)return status;
        *out=new oa_ipc_runtime_selection(std::move(selected));
        return OA_IPC_OK;
    } catch(const std::bad_alloc&){return OA_IPC_NO_MEMORY;}
      catch(...){return OA_IPC_INTERNAL_ERROR;}
}
const oa_ipc_server_expectation* oa_ipc_selected_server(const oa_ipc_runtime_selection* selected) {
    return selected?&selected->expectation:nullptr;
}
void oa_ipc_runtime_selection_release(oa_ipc_runtime_selection* selected) { delete selected; }
uint32_t oa_ipc_version(void) { return 1; }
oa_ipc_status oa_ipc_runtime_endpoint(char* buffer, size_t capacity, size_t* required) {
    if (!required) return OA_IPC_INVALID_ARGUMENT;
    *required = 0;
    if ((!buffer && capacity) || (buffer && !capacity)) return OA_IPC_INVALID_ARGUMENT;
    try {
        const auto endpoint = abstraction::ipc::runtime_endpoint();
        *required = endpoint.size() + 1;
        if (!buffer) return OA_IPC_OK;
        if (capacity < *required) return OA_IPC_INVALID_ARGUMENT;
        std::memcpy(buffer, endpoint.c_str(), *required);
        return OA_IPC_OK;
    } catch (const std::bad_alloc&) { *required=0; return OA_IPC_NO_MEMORY; }
      catch (const std::system_error&) { *required=0; return OA_IPC_IO_ERROR; }
      catch (...) { *required=0; return OA_IPC_INTERNAL_ERROR; }
}
oa_ipc_status oa_ipc_cancellation_create(oa_ipc_cancellation** out) {
    if (!out) return OA_IPC_INVALID_ARGUMENT;
    *out=nullptr;
    try {*out=new oa_ipc_cancellation;return OA_IPC_OK;}
    catch(const std::bad_alloc&){return OA_IPC_NO_MEMORY;}
    catch(...){return OA_IPC_INTERNAL_ERROR;}
}
void oa_ipc_cancellation_signal(oa_ipc_cancellation* c) {if(c)c->state->signal();}
void oa_ipc_cancellation_release(oa_ipc_cancellation* c) {try{delete c;}catch(...){}}

oa_ipc_status oa_ipc_open(const char* endpoint, size_t length, uint32_t timeout_ms, oa_ipc_connection** out) {
    return oa_ipc_open_cancelable(endpoint,length,timeout_ms,nullptr,out);
}
oa_ipc_status oa_ipc_open_cancelable(const char* endpoint,size_t length,uint32_t timeout_ms,
    oa_ipc_cancellation* cancellation,oa_ipc_connection** out) {
    if (!out) return OA_IPC_INVALID_ARGUMENT;
    *out = nullptr;
    if (!endpoint || !length) return OA_IPC_INVALID_ARGUMENT;
    const auto deadline = abstraction::local_stream::Clock::now() + std::chrono::milliseconds(timeout_ms);
    try {
        std::string path(endpoint, length);
        if (path.find('\0') != std::string::npos) return OA_IPC_INVALID_ARGUMENT;
        auto state=cancellation ? cancellation->state : std::shared_ptr<abstraction::local_stream::Cancellation>{};
        auto* c = new oa_ipc_connection(path, deadline, std::move(state));
        const auto result = status(c);
        if (result != OA_IPC_OK) { delete c; return result; }
        *out = c;
        return OA_IPC_OK;
    } catch (const std::bad_alloc&) { return OA_IPC_NO_MEMORY; }
      catch (...) { return OA_IPC_INTERNAL_ERROR; }
}
oa_ipc_status oa_ipc_open_verified(const char* endpoint, size_t length, uint32_t timeout_ms,
    oa_ipc_cancellation* cancellation, const oa_ipc_server_expectation* expectation, oa_ipc_connection** out) {
    if (!out) return OA_IPC_INVALID_ARGUMENT;
    *out = nullptr;
    if (!endpoint || !length || !abstraction::ipc_internal::ServerGuard::valid_input(expectation)) return OA_IPC_INVALID_ARGUMENT;
    const auto deadline = abstraction::local_stream::Clock::now() + std::chrono::milliseconds(timeout_ms);
    try {
        std::string path(endpoint, length);
        if (path.find('\0') != std::string::npos) return OA_IPC_INVALID_ARGUMENT;
        auto guard = std::make_unique<abstraction::ipc_internal::ServerGuard>(*expectation);
        auto state = cancellation ? cancellation->state : std::shared_ptr<abstraction::local_stream::Cancellation>{};
        auto c = std::make_unique<oa_ipc_connection>(path, deadline, std::move(state));
        if (status(c.get()) != OA_IPC_OK) return status(c.get());
        c->trust_status = guard->capture(c->stream);
        c->server = std::move(guard);
        const auto result = checked_status(c.get());
        if (result != OA_IPC_OK) return result;
        *out = c.release();
        return OA_IPC_OK;
    } catch (const std::bad_alloc&) { return OA_IPC_NO_MEMORY; }
      catch (...) { return OA_IPC_INTERNAL_ERROR; }
}

oa_ipc_status oa_ipc_write(oa_ipc_connection* c, const void* bytes, size_t length, size_t* moved) {
    if (moved) *moved = 0;
    if (!c || !moved || (!bytes && length)) return OA_IPC_INVALID_ARGUMENT;
    try {
        const auto before = checked_status(c);
        if (before != OA_IPC_OK) return before;
        c->stream.write_all(std::string_view(bytes ? static_cast<const char*>(bytes) : "", length), moved);
        return status(c);
    } catch (const std::bad_alloc&) { return OA_IPC_NO_MEMORY; }
      catch (...) { return OA_IPC_INTERNAL_ERROR; }
}
oa_ipc_status oa_ipc_read(oa_ipc_connection* c, void* bytes, size_t capacity, size_t* moved) {
    if (moved) *moved = 0;
    if (!c || !bytes || !capacity || !moved) return OA_IPC_INVALID_ARGUMENT;
    try {
        const auto before = checked_status(c);
        if (before != OA_IPC_OK) return before;
        c->stream.read_some(bytes, capacity, *moved);
        const auto after = checked_status(c);
        if (after == OA_IPC_UNTRUSTED) *moved = 0;
        return after;
    } catch (const std::bad_alloc&) { return OA_IPC_NO_MEMORY; }
      catch (...) { return OA_IPC_INTERNAL_ERROR; }
}
void oa_ipc_close(oa_ipc_connection* c) { try { delete c; } catch (...) {} }
}
