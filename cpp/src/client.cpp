#include <abstraction/ipc/client.h>
#include <abstraction/ipc/bootstrap.hpp>
#include <cstring>
#include <system_error>
#include "local_stream.h"
#include "server_guard.h"
#include "runtime_selection.h"
#include "session_test_hooks.h"
#include <new>
#include <algorithm>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#ifdef __APPLE__
#include "../../xpc_native.h"
#endif
struct oa_ipc_cancellation {
    std::shared_ptr<abstraction::local_stream::Cancellation> state =
        std::make_shared<abstraction::local_stream::Cancellation>();
#ifdef __APPLE__
    oa_xpc_cancel* xpc = nullptr;
    oa_ipc_cancellation() {
        if (oa_xpc_cancel_create(&xpc) != OA_XPC_OK) throw std::bad_alloc();
    }
    ~oa_ipc_cancellation() { oa_xpc_cancel_free(xpc); }
#endif
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
    case Status::Ok: return c->trust_status;
    case Status::Timeout: return OA_IPC_TIMEOUT;
    case Status::Cancelled: return OA_IPC_CANCELLED;
    case Status::Disconnected: return OA_IPC_DISCONNECTED;
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
uint32_t oa_ipc_features(void) {
#ifdef __APPLE__
    if (oa_xpc_available()) return OA_IPC_FEATURE_XPC;
#endif
    return 0;
}
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
void oa_ipc_cancellation_signal(oa_ipc_cancellation* c) {
    if (!c) return;
    c->state->signal();
#ifdef __APPLE__
    oa_xpc_cancel_fire(c->xpc);
#endif
}
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
        if (path.compare(0, 4, "xpc:") == 0) return OA_IPC_INVALID_ARGUMENT;
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
        if (path.compare(0, 4, "xpc:") == 0) return OA_IPC_INVALID_ARGUMENT;
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

// ---------------------------------------------------------------- sessions ---
// The client half of listen/FRAMING.md "Sessions", shared by every language
// that loads this library. Constants and rules match the Go listen package.
struct oa_ipc_reply { std::vector<unsigned char> bytes; };
#ifdef ABSTRACTION_IPC_TEST_HOOKS
namespace abstraction { namespace ipc_internal {
SessionWriteHook session_test_write = nullptr;
SessionOpenHook session_test_open = nullptr;
}}
#endif
namespace {
using SessionClock = abstraction::local_stream::Clock;
constexpr uint32_t kSessionFlag = 0x80000000u, kOneWayFlag = 0x40000000u, kLengthMask = 0x3FFFFFFFu;
constexpr uint32_t kSessionClosing = 0xFFFFFFFFu, kSessionAccept = kSessionFlag, kSessionDecline = 0,
    kSessionUnsupported = kOneWayFlag, kProofRefusal = 0xFFFFFFFEu;
constexpr auto kPoolIdle = std::chrono::seconds(10);
constexpr size_t kPoolPerEndpoint = 4;
constexpr auto kSingleMemory = std::chrono::seconds(30);
constexpr int kSessionAttempts = 3;

struct Idle { oa_ipc_connection* connection; SessionClock::time_point since; };
struct Pool {
    std::mutex mu;
    std::unordered_map<std::string, std::vector<Idle>> idle;
    std::unordered_map<std::string, SessionClock::time_point> single;
};
// Never destroyed: a pooled connection may be in use while the process exits.
Pool& pool() { static Pool* p = new Pool; return *p; }

std::string pool_key(const std::string& endpoint, const oa_ipc_server_expectation* e) {
    std::string key = endpoint;
    if (e) {
        key.push_back('\0'); key += std::to_string(e->principal_kind);
        key.push_back('\0'); key.append(e->principal, e->principal_length);
        key.push_back('\0'); key.append(e->program, e->program_length);
    }
    return key;
}
bool is_single(const std::string& key, SessionClock::time_point now) {
    auto& p = pool();
    std::lock_guard<std::mutex> lock(p.mu);
    auto it = p.single.find(key);
    if (it == p.single.end()) return false;
    if (now < it->second) return true;
    p.single.erase(it);
    return false;
}
void mark_single(const std::string& key) {
    auto& p = pool();
    std::lock_guard<std::mutex> lock(p.mu);
    p.single[key] = SessionClock::now() + kSingleMemory;
}
oa_ipc_connection* take(const std::string& key) {
    auto& p = pool();
    for (;;) {
        Idle last{};
        {
            std::lock_guard<std::mutex> lock(p.mu);
            auto it = p.idle.find(key);
            if (it == p.idle.end() || it->second.empty()) return nullptr;
            last = it->second.back();
            it->second.pop_back();
        }
        if (SessionClock::now() - last.since < kPoolIdle && last.connection->stream.idle_intact() &&
            last.connection->trust_status == OA_IPC_OK)
            return last.connection;
        oa_ipc_close(last.connection);
    }
}
void put(const std::string& key, oa_ipc_connection* c) {
    c->stream.rearm(SessionClock::now(), {});
    std::vector<oa_ipc_connection*> expired;
    const auto now = SessionClock::now();
    {
        auto& p = pool();
        std::lock_guard<std::mutex> lock(p.mu);
        auto& list = p.idle[key];
        while (!list.empty() && now - list.front().since >= kPoolIdle) {
            expired.push_back(list.front().connection);
            list.erase(list.begin());
        }
        if (list.size() < kPoolPerEndpoint) list.push_back({c, now});
        else expired.push_back(c);
    }
    for (auto* e : expired) oa_ipc_close(e);
}
uint32_t remaining_ms(SessionClock::time_point deadline) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - SessionClock::now()).count();
    return left <= 0 ? 0 : static_cast<uint32_t>(std::min<decltype(left)>(left, UINT32_MAX));
}
void put_u32(unsigned char* out, uint32_t v) {
    out[0] = static_cast<unsigned char>(v >> 24); out[1] = static_cast<unsigned char>(v >> 16);
    out[2] = static_cast<unsigned char>(v >> 8); out[3] = static_cast<unsigned char>(v);
}
uint32_t get_u32(const unsigned char* in) {
    return (uint32_t(in[0]) << 24) | (uint32_t(in[1]) << 16) | (uint32_t(in[2]) << 8) | in[3];
}
oa_ipc_status write_all(oa_ipc_connection* c, const unsigned char* bytes, size_t length, size_t* moved) {
#ifdef ABSTRACTION_IPC_TEST_HOOKS
    if (abstraction::ipc_internal::session_test_write)
        return abstraction::ipc_internal::session_test_write(c, bytes, length, moved);
#endif
    return oa_ipc_write(c, bytes, length, moved);
}
oa_ipc_status read_exact(oa_ipc_connection* c, unsigned char* out, size_t length, size_t* got) {
    *got = 0;
    while (*got < length) {
        size_t n = 0;
        const auto status = oa_ipc_read(c, out + *got, length - *got, &n);
        if (status != OA_IPC_OK) return status;
        if (n == 0 || n > length - *got) return OA_IPC_INTERNAL_ERROR;
        *got += n;
    }
    return OA_IPC_OK;
}
oa_ipc_status read_proof_refusal(oa_ipc_connection* c) {
    unsigned char tokens[2];
    size_t got = 0;
    const auto status = read_exact(c, tokens, sizeof tokens, &got);
    if (status != OA_IPC_OK) return status;
    if (tokens[0] > 5 || tokens[1] > 8 || (tokens[0] == 0) != (tokens[1] == 0))
        return OA_IPC_IO_ERROR;
    return OA_IPC_PROOF_UNAVAILABLE;
}
// A receiver may refuse immediately after its request header and close before
// the client finishes writing the body. The caller exclusively owns c (including
// a connection removed from the pool). Inspect only the six-byte terminal
// control; every incomplete or different response preserves the write error.
oa_ipc_status refusal_after_write_error(oa_ipc_connection* c, oa_ipc_status write_error,
                                        bool opening_header = false) {
    if (write_error != OA_IPC_DISCONNECTED && write_error != OA_IPC_IO_ERROR) return write_error;
    unsigned char control[10]{};
    size_t expected = opening_header ? 4 : 6;
    bool accepted = false;
    for (size_t used = 0; used < expected;) {
        if (c->server && !c->server->check()) return write_error;
        size_t moved = 0;
        if (!c->stream.read_after_failed_write(control + used, expected - used, moved)) return write_error;
        if (c->server && !c->server->check()) return write_error;
        if (moved == 0 || moved > expected - used) return write_error;
        used += moved;
        if (opening_header && used >= 4 && expected == 4 &&
            (get_u32(control) == kSessionAccept || get_u32(control) == kSessionDecline ||
             get_u32(control) == kSessionUnsupported)) {
            accepted = true;
            expected = 10;
            continue;
        }
        const size_t offset = accepted ? 4 : 0;
        if (opening_header && !accepted && used < 4) continue;
        for (size_t i = offset; i < used && i < offset + 3; ++i)
            if (control[i] != 0xFF) return write_error;
        if (used >= offset + 4 && control[offset + 3] != 0xFE) return write_error;
        if (opening_header && !accepted && used == 4 && get_u32(control) == kProofRefusal)
            expected = 6;
    }
    const unsigned char* marker = control + (accepted ? 4 : 0);
    if (get_u32(marker) != kProofRefusal || marker[4] > 5 || marker[5] > 8 ||
        (marker[4] == 0) != (marker[5] == 0)) return write_error;
    return OA_IPC_PROOF_UNAVAILABLE;
}
struct Owned {
    oa_ipc_connection* c = nullptr;
    ~Owned() { oa_ipc_close(c); }
    oa_ipc_connection* release() { auto* r = c; c = nullptr; return r; }
};
oa_ipc_status open_for(const std::string& endpoint, SessionClock::time_point deadline, oa_ipc_cancellation* cancellation,
    const oa_ipc_server_expectation* expectation, oa_ipc_connection** out) {
#ifdef ABSTRACTION_IPC_TEST_HOOKS
    if (abstraction::ipc_internal::session_test_open)
        return abstraction::ipc_internal::session_test_open(endpoint, deadline, cancellation, expectation, out);
#endif
    const auto ms = remaining_ms(deadline);
    return expectation
        ? oa_ipc_open_verified(endpoint.data(), endpoint.size(), ms, cancellation, expectation, out)
        : oa_ipc_open_cancelable(endpoint.data(), endpoint.size(), ms, cancellation, out);
}
// The rest of an exchange on a connection answered with a plain header: one
// frame, or for one-way the server's close.
oa_ipc_status finish_single(oa_ipc_connection* c, uint32_t max_reply, bool one_way, oa_ipc_reply** reply) {
    if (one_way) {
        unsigned char byte;
        size_t n = 0;
        const auto status = oa_ipc_read(c, &byte, 1, &n);
        if (status == OA_IPC_OK && n == 1 && byte == 0xFF) {
            unsigned char rest[3];
            size_t got = 0;
            const auto tail = read_exact(c, rest, sizeof rest, &got);
            if (tail != OA_IPC_OK) return tail;
            const unsigned char header[4] = {byte, rest[0], rest[1], rest[2]};
            if (get_u32(header) == kProofRefusal) return read_proof_refusal(c);
        }
        return status == OA_IPC_DISCONNECTED ? OA_IPC_OK : status == OA_IPC_OK ? OA_IPC_IO_ERROR : status;
    }
    unsigned char header[4];
    size_t got = 0;
    auto status = read_exact(c, header, 4, &got);
    if (status != OA_IPC_OK) return status;
    const uint32_t length = get_u32(header);
    if (length == kProofRefusal) return read_proof_refusal(c);
    if (length > max_reply || length > kLengthMask) return OA_IPC_INVALID_ARGUMENT;
    auto out = std::make_unique<oa_ipc_reply>();
    out->bytes.resize(length);
    if (length && (status = read_exact(c, out->bytes.data(), length, &got)) != OA_IPC_OK) return status;
    *reply = out.release();
    return OA_IPC_OK;
}
oa_ipc_status single_call(const std::string& endpoint, SessionClock::time_point deadline, oa_ipc_cancellation* cancellation,
    const oa_ipc_server_expectation* expectation, const unsigned char* frame, size_t frame_length, uint32_t max_reply,
    bool one_way, oa_ipc_reply** reply, size_t* sent) {
    Owned c;
    auto status = open_for(endpoint, deadline, cancellation, expectation, &c.c);
    if (status != OA_IPC_OK) return status;
    std::vector<unsigned char> request(4 + frame_length);
    put_u32(request.data(), static_cast<uint32_t>(frame_length));
    if (frame_length) std::memcpy(request.data() + 4, frame, frame_length);
    size_t moved = 0;
    status = write_all(c.c, request.data(), request.size(), &moved);
    *sent = moved > 4 ? moved - 4 : 0;
    if (status != OA_IPC_OK) return refusal_after_write_error(c.c, status);
    return finish_single(c.c, max_reply, one_way, reply);
}

#ifdef __APPLE__
oa_ipc_status xpc_status(oa_xpc_status value) {
    switch (value) {
    case OA_XPC_OK: return OA_IPC_OK;
    case OA_XPC_CLOSED: return OA_IPC_DISCONNECTED;
    case OA_XPC_TIMEOUT: return OA_IPC_TIMEOUT;
    case OA_XPC_CANCELLED: return OA_IPC_CANCELLED;
    case OA_XPC_INVALID_ARGUMENT: return OA_IPC_INVALID_ARGUMENT;
    case OA_XPC_UNTRUSTED: return OA_IPC_UNTRUSTED;
    case OA_XPC_UNAVAILABLE: return OA_IPC_PROOF_UNAVAILABLE;
    case OA_XPC_CALLER_PROOF_UNMET: return OA_IPC_PROOF_UNAVAILABLE;
    default: return OA_IPC_IO_ERROR;
    }
}

oa_ipc_status xpc_call(const std::string& endpoint, SessionClock::time_point deadline,
    oa_ipc_cancellation* cancellation, const oa_ipc_server_expectation* expectation,
    const void* frame, size_t length, uint32_t max_reply, bool one_way,
    oa_ipc_reply** reply, size_t* sent) {
    // The shared core authenticates the runtime before sending any frame.
    if (!expectation) return OA_IPC_UNTRUSTED;
    if (endpoint.size() == 4) return OA_IPC_INVALID_ARGUMENT;
    uint32_t uid = 0;
    for (size_t i = 0; i < expectation->principal_length; ++i) {
        const unsigned char ch = expectation->principal[i];
        if (ch < '0' || ch > '9' || uid > (UINT32_MAX - (ch - '0')) / 10)
            return OA_IPC_INVALID_ARGUMENT;
        uid = uid * 10 + (ch - '0');
    }
    if (cancellation && cancellation->state->requested()) return OA_IPC_CANCELLED;
    const auto ms = remaining_ms(deadline);
    if (!ms) return OA_IPC_TIMEOUT;
    const uint64_t native_deadline = oa_xpc_now_ns() + uint64_t(ms) * 1000000;
    const std::string program(expectation->program, expectation->program_length);
    oa_xpc_client* raw = nullptr;
    auto result = oa_xpc_client_open(endpoint.c_str() + 4, program.c_str(), uid,
        max_reply, native_deadline, cancellation ? cancellation->xpc : nullptr, &raw);
    std::unique_ptr<oa_xpc_client, decltype(&oa_xpc_client_free)> client(raw, oa_xpc_client_free);
    if (result != OA_XPC_OK) return xpc_status(result);
    void* bytes = nullptr;
    size_t size = 0;
    uint8_t proof_attribute = 0, proof_required = 0;
    result = oa_xpc_client_call(client.get(), frame, length, one_way ? 1 : 0,
        native_deadline, cancellation ? cancellation->xpc : nullptr, sent, &bytes, &size,
        &proof_attribute, &proof_required);
    std::unique_ptr<void, decltype(&oa_xpc_bytes_free)> owned(bytes, oa_xpc_bytes_free);
    if (result != OA_XPC_OK) return xpc_status(result);
    if (size > max_reply || (size && !bytes)) return OA_IPC_IO_ERROR;
    if (!one_way) {
        auto out = std::make_unique<oa_ipc_reply>();
        if (size) {
            const auto* begin = static_cast<const unsigned char*>(bytes);
            out->bytes.assign(begin, begin + size);
        }
        *reply = out.release();
    }
    return OA_IPC_OK;
}
#endif
} // namespace

extern "C" {
oa_ipc_status oa_ipc_session_call(const char* endpoint, size_t length, uint32_t timeout_ms,
    oa_ipc_cancellation* cancellation, const oa_ipc_server_expectation* expectation,
    const void* frame_bytes, size_t frame_length, uint32_t max_reply, uint32_t flags,
    oa_ipc_reply** reply, size_t* sent) {
    if (reply) *reply = nullptr;
    if (sent) *sent = 0;
    if (!endpoint || !length || !reply || !sent || (!frame_bytes && frame_length) || frame_length > kLengthMask ||
        (flags & ~uint32_t(OA_IPC_CALL_ONE_WAY)) ||
        (expectation && !abstraction::ipc_internal::ServerGuard::valid_input(expectation)))
        return OA_IPC_INVALID_ARGUMENT;
    const auto deadline = SessionClock::now() + std::chrono::milliseconds(timeout_ms);
    try {
        const std::string path(endpoint, length);
        if (path.find('\0') != std::string::npos) return OA_IPC_INVALID_ARGUMENT;
        const auto* frame = static_cast<const unsigned char*>(frame_bytes);
        const bool one_way = (flags & OA_IPC_CALL_ONE_WAY) != 0;
        if (path.compare(0, 4, "xpc:") == 0) {
#ifdef __APPLE__
            return xpc_call(path, deadline, cancellation, expectation, frame,
                frame_length, max_reply, one_way, reply, sent);
#else
            return OA_IPC_PROOF_UNAVAILABLE;
#endif
        }
        const auto key = pool_key(path, expectation);
        if (is_single(key, SessionClock::now()))
            return single_call(path, deadline, cancellation, expectation, frame, frame_length, max_reply, one_way, reply, sent);
        const uint32_t request_header = kSessionFlag | (one_way ? kOneWayFlag : 0) | static_cast<uint32_t>(frame_length);
        auto state = cancellation ? cancellation->state : std::shared_ptr<abstraction::local_stream::Cancellation>{};
        for (int attempt = 0; attempt < kSessionAttempts; ++attempt) {
            Owned c;
            c.c = take(key);
            const bool fresh = c.c == nullptr;
            unsigned char header[4];
            size_t moved = 0, got = 0;
            oa_ipc_status status;
            if (fresh) {
                if ((status = open_for(path, deadline, cancellation, expectation, &c.c)) != OA_IPC_OK) return status;
                put_u32(header, request_header);
                if ((status = write_all(c.c, header, 4, &moved)) != OA_IPC_OK)
                    return refusal_after_write_error(c.c, status, true);
                status = read_exact(c.c, header, 4, &got);
                if (status != OA_IPC_OK) {
                    if (got == 0 && (status == OA_IPC_DISCONNECTED || status == OA_IPC_IO_ERROR)) {
                        // Closed before answering and before any body: a server
                        // built before sessions. Serve the call once, anew.
                        mark_single(key);
                        return single_call(path, deadline, cancellation, expectation, frame, frame_length, max_reply, one_way, reply, sent);
                    }
                    return status;
                }
                const uint32_t answer = get_u32(header);
                if (answer == kProofRefusal) return read_proof_refusal(c.c);
                if (answer == kSessionClosing) continue;
                if (answer == kSessionDecline || answer == kSessionUnsupported) {
                    if (answer == kSessionUnsupported) mark_single(key);
                    status = write_all(c.c, frame, frame_length, &moved);
                    *sent = moved;
                    if (status != OA_IPC_OK) return refusal_after_write_error(c.c, status);
                    return finish_single(c.c, max_reply, one_way, reply);
                }
                if (answer != kSessionAccept) return OA_IPC_IO_ERROR;
                status = write_all(c.c, frame, frame_length, &moved);
                *sent = moved;
                if (status != OA_IPC_OK) return refusal_after_write_error(c.c, status);
            } else {
                c.c->stream.rearm(deadline, state);
                std::vector<unsigned char> request(4 + frame_length);
                put_u32(request.data(), request_header);
                if (frame_length) std::memcpy(request.data() + 4, frame, frame_length);
                status = write_all(c.c, request.data(), request.size(), &moved);
                if (status != OA_IPC_OK) {
                    *sent = moved > 4 ? std::min(moved - 4, frame_length) : 0;
                    const auto result = refusal_after_write_error(c.c, status);
                    // A failed write has an uncertain acceptance boundary. An
                    // observed response, including a short one, is never a
                    // replay invitation; zero response bytes cannot prove
                    // that the peer missed the request either.
                    return result;
                }
                *sent = frame_length;
            }
            if ((status = read_exact(c.c, header, 4, &got)) != OA_IPC_OK) return status;
            const uint32_t answer = get_u32(header);
            if (answer == kProofRefusal) return read_proof_refusal(c.c);
            if (answer == kSessionClosing) { *sent = 0; continue; }
            if (answer & kOneWayFlag) return OA_IPC_IO_ERROR;
            const uint32_t reply_length = answer & kLengthMask;
            const bool keep = (answer & kSessionFlag) != 0;
            if (one_way) {
                if (reply_length != 0) return OA_IPC_IO_ERROR;
            } else {
                if (reply_length > max_reply) return OA_IPC_INVALID_ARGUMENT;
                auto out = std::make_unique<oa_ipc_reply>();
                out->bytes.resize(reply_length);
                if (reply_length && (status = read_exact(c.c, out->bytes.data(), reply_length, &got)) != OA_IPC_OK) return status;
                *reply = out.release();
            }
            if (keep && !(state && state->requested())) put(key, c.release());
            return OA_IPC_OK;
        }
        return OA_IPC_IO_ERROR;
    } catch (const std::bad_alloc&) { return OA_IPC_NO_MEMORY; }
      catch (...) { return OA_IPC_INTERNAL_ERROR; }
}
const unsigned char* oa_ipc_reply_data(const oa_ipc_reply* r, size_t* length) {
    if (length) *length = r ? r->bytes.size() : 0;
    return r && !r->bytes.empty() ? r->bytes.data() : nullptr;
}
void oa_ipc_reply_release(oa_ipc_reply* r) { delete r; }
}
