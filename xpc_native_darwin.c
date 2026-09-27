//go:build darwin && cgo

#include "xpc_native.h"

#include <AvailabilityMacros.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>
#include <libproc.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <xpc/xpc.h>

#define OA_PROTOCOL 1
#define OA_WAIT_SLICE_NS (10ull * 1000ull * 1000ull)
#define OA_MAX_CONNECTIONS 512
#define OA_MAX_SESSIONS 128
#define OA_MAX_ACTIVE_REQUESTS 256

struct oa_xpc_cancel {
  atomic_uchar fired;
};
struct oa_xpc_request {
  xpc_object_t message;
  xpc_connection_t remote;
  void *bytes;
  size_t length;
  oa_xpc_identity identity;
  char path[PROC_PIDPATHINFO_MAXSIZE];
  char generation[96];
  char identifier[256], team[128], cdhash[129], status[256];
  atomic_uchar replied, closed;
  uint8_t one_way;
  dispatch_semaphore_t done;
  struct oa_xpc_request *next;
  struct oa_xpc_request *active_next;
  struct oa_xpc_listener *listener;
};
typedef struct oa_xpc_tracked_connection {
  xpc_connection_t connection;
  struct oa_xpc_tracked_connection *next;
} oa_xpc_tracked_connection;
typedef struct oa_xpc_session_state oa_xpc_session_state;
struct oa_xpc_listener {
  xpc_connection_t bootstrap;
  dispatch_queue_t queue;
  pthread_mutex_t mutex;
  pthread_cond_t condition;
  struct oa_xpc_request *head, *tail;
  struct oa_xpc_request *active_requests;
  oa_xpc_tracked_connection *connections;
  oa_xpc_session_state *sessions;
  size_t connection_count, session_count, active_request_count;
  size_t max_frame;
  atomic_uchar closed;
  atomic_uint refs;
};
struct oa_xpc_client {
  xpc_connection_t bootstrap, session;
  dispatch_queue_t queue;
  char *generation, *expected_path, *requirement;
  uint32_t expected_euid;
  size_t max_reply;
  atomic_uchar closed;
};

uint64_t oa_xpc_now_ns(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC_RAW, &t);
  return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}
uint8_t oa_xpc_available(void) {
  if (__builtin_available(macOS 12.0, *))
    return 1;
  return 0;
}
const char *oa_xpc_error_text(oa_xpc_status s) {
  switch (s) {
  case OA_XPC_OK:
    return "ok";
  case OA_XPC_CLOSED:
    return "closed";
  case OA_XPC_TIMEOUT:
    return "timeout";
  case OA_XPC_CANCELLED:
    return "cancelled";
  case OA_XPC_INVALID_ARGUMENT:
    return "invalid argument";
  case OA_XPC_UNTRUSTED:
    return "untrusted";
  case OA_XPC_PROTOCOL:
    return "protocol error";
  case OA_XPC_UNAVAILABLE:
    return "unavailable";
  case OA_XPC_CALLER_PROOF_UNMET:
    return "caller proof unmet";
  default:
    return "system error";
  }
}
oa_xpc_status oa_xpc_cancel_create(oa_xpc_cancel **out) {
  if (!out)
    return OA_XPC_INVALID_ARGUMENT;
  *out = calloc(1, sizeof(**out));
  return *out ? OA_XPC_OK : OA_XPC_SYSTEM;
}
void oa_xpc_cancel_fire(oa_xpc_cancel *c) {
  if (c)
    atomic_store(&c->fired, 1);
}
void oa_xpc_cancel_free(oa_xpc_cancel *c) { free(c); }
static int cancelled(oa_xpc_cancel *c) { return c && atomic_load(&c->fired); }
static int valid_service_name(const char *service) {
  if (!service)
    return 0;
  size_t length = strlen(service);
  return length > 0 && length <= 255 && !strpbrk(service, "/\\\r\n");
}

static void copy_cf(CFTypeRef value, char *out, size_t size) {
  out[0] = 0;
  if (value && CFGetTypeID(value) == CFStringGetTypeID())
    CFStringGetCString((CFStringRef)value, out, size, kCFStringEncodingUTF8);
}
static void copy_hex(CFTypeRef value, char *out, size_t size) {
  out[0] = 0;
  if (!value || CFGetTypeID(value) != CFDataGetTypeID())
    return;
  CFDataRef d = (CFDataRef)value;
  const UInt8 *b = CFDataGetBytePtr(d);
  size_t n = (size_t)CFDataGetLength(d), at = 0;
  for (size_t i = 0; i < n && at + 2 < size; ++i)
    at += (size_t)snprintf(out + at, size - at, "%02x", b[i]);
}
static void copy_url(CFTypeRef value, char *out, size_t size) {
  out[0] = 0;
  if (value && CFGetTypeID(value) == CFURLGetTypeID())
    CFURLGetFileSystemRepresentation((CFURLRef)value, 1, (UInt8 *)out, size);
}
static oa_xpc_status identify(xpc_object_t message,
                              xpc_connection_t handler_peer,
                              oa_xpc_request *r) {
  xpc_connection_t remote = xpc_dictionary_get_remote_connection(message);
  if (!remote || (handler_peer && remote != handler_peer)) {
    return OA_XPC_UNTRUSTED;
  }
  SecCodeRef code = NULL;
  OSStatus st = SecCodeCreateWithXPCMessage(message, kSecCSDefaultFlags, &code);
  if (st != errSecSuccess || !code) {
    return OA_XPC_UNTRUSTED;
  }
  st = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
  if (st != errSecSuccess) {
    CFRelease(code);
    return OA_XPC_UNTRUSTED;
  }
  CFDictionaryRef info = NULL;
  st = SecCodeCopySigningInformation(
      code, kSecCSSigningInformation | kSecCSRequirementInformation, &info);
  if (st != errSecSuccess || !info) {
    CFRelease(code);
    return OA_XPC_UNTRUSTED;
  }
  copy_cf(CFDictionaryGetValue(info, kSecCodeInfoIdentifier), r->identifier,
          sizeof(r->identifier));
  copy_cf(CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), r->team,
          sizeof(r->team));
  copy_hex(CFDictionaryGetValue(info, kSecCodeInfoUnique), r->cdhash,
           sizeof(r->cdhash));
  copy_url(CFDictionaryGetValue(info, kSecCodeInfoMainExecutable), r->path,
           sizeof(r->path));
  CFRelease(info);
  CFRelease(code);
  r->remote = xpc_retain(remote);
  r->message = xpc_retain(message);
  r->identity.connection_pid = xpc_connection_get_pid(remote);
  /* Public XPC exposes PID/EUID on the exact dictionary's remote connection.
     It does not expose audit-token pidversion/session fields for this API. */
  r->identity.message_pid = 0;
  r->identity.connection_euid = xpc_connection_get_euid(remote);
  r->identity.connection_egid = xpc_connection_get_egid(remote);
  r->identity.message_path = r->path;
  r->identity.signing_identifier = r->identifier;
  r->identity.team_identifier = r->team;
  r->identity.cdhash = r->cdhash;
  strcpy(r->status, "valid");
  r->identity.signing_status = r->status;
  r->identity.message_code_valid = 1;
  char pidpath[PROC_PIDPATHINFO_MAXSIZE] = {0};
  if (proc_pidpath(r->identity.connection_pid, pidpath, sizeof(pidpath)) > 0 &&
      r->path[0])
    r->identity.connection_path_matches_message = strcmp(pidpath, r->path) == 0;
  /* The remote connection is obtained from this exact dictionary. Transfer
     probes show its PID/EUID move with the message sender; code and proc path
     must still agree before this conjunction is authority-bearing. */
  r->identity.connection_principal_message_coherent =
      r->identity.message_code_valid &&
      r->identity.connection_path_matches_message;
  return r->identity.connection_path_matches_message ? OA_XPC_OK
                                                     : OA_XPC_UNTRUSTED;
}
static oa_xpc_status validate_expected(xpc_object_t message, const char *path,
                                       uint32_t euid) {
  oa_xpc_request proof = {0};
  oa_xpc_status status = identify(message, NULL, &proof);
  if (status == OA_XPC_OK &&
      (proof.identity.connection_euid != euid || strcmp(proof.path, path) != 0))
    status = OA_XPC_UNTRUSTED;
  if (proof.message)
    xpc_release(proof.message);
  if (proof.remote)
    xpc_release(proof.remote);
  return status;
}
static int deadline_wait(dispatch_semaphore_t sem, uint64_t deadline,
                         oa_xpc_cancel *cancel) {
  for (;;) {
    if (cancelled(cancel))
      return OA_XPC_CANCELLED;
    uint64_t now = oa_xpc_now_ns();
    if (deadline && now >= deadline)
      return OA_XPC_TIMEOUT;
    uint64_t span = deadline ? deadline - now : OA_WAIT_SLICE_NS;
    if (span > OA_WAIT_SLICE_NS)
      span = OA_WAIT_SLICE_NS;
    if (dispatch_semaphore_wait(
            sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)span)) == 0)
      return OA_XPC_OK;
  }
}
static void listener_retain(oa_xpc_listener *l);
static void listener_release(oa_xpc_listener *l);
static int enqueue(oa_xpc_listener *l, oa_xpc_request *r) {
  pthread_mutex_lock(&l->mutex);
  if (atomic_load(&l->closed) ||
      l->active_request_count >= OA_MAX_ACTIVE_REQUESTS) {
    pthread_mutex_unlock(&l->mutex);
    return 0;
  }
  r->listener = l;
  listener_retain(l);
  r->active_next = l->active_requests;
  l->active_requests = r;
  l->active_request_count++;
  if (l->tail)
    l->tail->next = r;
  else
    l->head = r;
  l->tail = r;
  pthread_cond_signal(&l->condition);
  pthread_mutex_unlock(&l->mutex);
  return 1;
}
static void cancel_peer_requests(oa_xpc_listener *l, xpc_connection_t peer) {
  pthread_mutex_lock(&l->mutex);
  for (oa_xpc_request *r = l->active_requests; r; r = r->active_next)
    if (!peer || r->remote == peer)
      oa_xpc_request_cancel(r);
  pthread_mutex_unlock(&l->mutex);
}
static int track_connection(oa_xpc_listener *l, xpc_connection_t connection) {
  oa_xpc_tracked_connection *entry = calloc(1, sizeof(*entry));
  if (!entry)
    return 0;
  entry->connection = xpc_retain(connection);
  pthread_mutex_lock(&l->mutex);
  if (atomic_load(&l->closed) || l->connection_count >= OA_MAX_CONNECTIONS) {
    pthread_mutex_unlock(&l->mutex);
    xpc_release(entry->connection);
    free(entry);
    return 0;
  }
  entry->next = l->connections;
  l->connections = entry;
  l->connection_count++;
  pthread_mutex_unlock(&l->mutex);
  return 1;
}
static void untrack_connection(oa_xpc_listener *l,
                               xpc_connection_t connection) {
  pthread_mutex_lock(&l->mutex);
  oa_xpc_tracked_connection **at = &l->connections;
  while (*at && (*at)->connection != connection)
    at = &(*at)->next;
  oa_xpc_tracked_connection *entry = *at;
  if (entry)
    *at = entry->next;
  if (entry)
    l->connection_count--;
  pthread_mutex_unlock(&l->mutex);
  if (entry) {
    xpc_release(entry->connection);
    free(entry);
  }
}
static void send_refusal(xpc_object_t event, xpc_connection_t peer,
                         const char *generation) {
  if (xpc_get_type(event) != XPC_TYPE_DICTIONARY)
    return;
  xpc_object_t reply = xpc_dictionary_create_reply(event);
  if (!reply)
    return;
  xpc_dictionary_set_string(reply, "status", "refused");
  if (generation)
    xpc_dictionary_set_string(reply, "generation", generation);
  xpc_connection_send_message(peer, reply);
  xpc_release(reply);
}
static void send_busy(xpc_object_t event, xpc_connection_t peer,
                      const char *generation) {
  if (xpc_get_type(event) != XPC_TYPE_DICTIONARY)
    return;
  xpc_object_t reply = xpc_dictionary_create_reply(event);
  if (!reply)
    return;
  xpc_dictionary_set_string(reply, "status", "busy");
  if (generation)
    xpc_dictionary_set_string(reply, "generation", generation);
  xpc_connection_send_message(peer, reply);
  xpc_release(reply);
}
struct oa_xpc_session_state {
  oa_xpc_listener *listener;
  xpc_connection_t anonymous_listener;
  int32_t bootstrap_pid;
  uint32_t bootstrap_euid;
  char generation[96];
  char cdhash[129];
  atomic_uchar closed;
  atomic_uchar bootstrap_active, anonymous_active, retirement_scheduled;
  atomic_uint peer_count;
  oa_xpc_session_state *next;
};

static void listener_retain(oa_xpc_listener *l) { atomic_fetch_add(&l->refs, 1); }
static void listener_destroy(oa_xpc_listener *l) {
  if (l->bootstrap)
    xpc_release(l->bootstrap);
  oa_xpc_tracked_connection *connection = l->connections;
  while (connection) {
    oa_xpc_tracked_connection *next = connection->next;
    xpc_release(connection->connection);
    free(connection);
    connection = next;
  }
  oa_xpc_session_state *session = l->sessions;
  while (session) {
    oa_xpc_session_state *next = session->next;
    if (session->anonymous_listener)
      xpc_release(session->anonymous_listener);
    free(session);
    session = next;
  }
#if !OS_OBJECT_USE_OBJC
  dispatch_release(l->queue);
#endif
  pthread_cond_destroy(&l->condition);
  pthread_mutex_destroy(&l->mutex);
  free(l);
}
static void listener_release(oa_xpc_listener *l) {
  if (atomic_fetch_sub(&l->refs, 1) == 1)
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
      listener_destroy(l);
    });
}

static void maybe_retire_session(oa_xpc_session_state *state) {
  if (!state || atomic_load(&state->bootstrap_active) ||
      atomic_load(&state->anonymous_active) || atomic_load(&state->peer_count) ||
      atomic_load(&state->listener->closed) ||
      atomic_exchange(&state->retirement_scheduled, 1))
    return;
  listener_retain(state->listener);
  dispatch_async(state->listener->queue, ^{
    oa_xpc_listener *l = state->listener;
    if (atomic_load(&l->closed)) {
      listener_release(l);
      return;
    }
    pthread_mutex_lock(&l->mutex);
    oa_xpc_session_state **at = &l->sessions;
    while (*at && *at != state)
      at = &(*at)->next;
    int found = *at == state;
    if (found)
      *at = state->next;
    if (found)
      l->session_count--;
    pthread_mutex_unlock(&l->mutex);
    free(state);
    listener_release(l);
  });
}

static void close_session(oa_xpc_session_state *state) {
  if (!state || atomic_exchange(&state->closed, 1))
    return;
  if (state->anonymous_listener)
    xpc_connection_cancel(state->anonymous_listener);
}

static void session_peer(oa_xpc_session_state *state, xpc_connection_t peer) {
  __block uint8_t finished = 0;
  int same = xpc_connection_get_pid(peer) == state->bootstrap_pid &&
             xpc_connection_get_euid(peer) == state->bootstrap_euid;
  if (!track_connection(state->listener, peer)) {
    xpc_connection_cancel(peer);
    return;
  }
  atomic_fetch_add(&state->peer_count, 1);
  listener_retain(state->listener);
  xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
    if (xpc_get_type(event) != XPC_TYPE_DICTIONARY) {
      if (finished)
        return;
      finished = 1;
      cancel_peer_requests(state->listener, peer);
      xpc_connection_set_event_handler(peer, ^(xpc_object_t ignored) {
        (void)ignored;
      });
      untrack_connection(state->listener, peer);
      atomic_fetch_sub(&state->peer_count, 1);
      maybe_retire_session(state);
      listener_release(state->listener);
      return;
    }
    if (!same || atomic_load(&state->closed)) {
      send_refusal(event, peer, state->generation);
      return;
    }
    const char *got = xpc_dictionary_get_string(event, "generation");
    size_t length = 0;
    const void *bytes = xpc_dictionary_get_data(event, "frame", &length);
    if (!got || strcmp(got, state->generation) || !bytes ||
        length > state->listener->max_frame) {
      send_refusal(event, peer, state->generation);
      return;
    }
    oa_xpc_request *r = calloc(1, sizeof(*r));
    if (!r) {
      send_refusal(event, peer, state->generation);
      return;
    }
    r->done = dispatch_semaphore_create(0);
    if (identify(event, peer, r) != OA_XPC_OK ||
        strcmp(r->cdhash, state->cdhash)) {
      oa_xpc_request_free(r);
      send_refusal(event, peer, state->generation);
      return;
    }
    r->bytes = malloc(length ? length : 1);
    if (!r->bytes) {
      oa_xpc_request_free(r);
      return;
    }
    memcpy(r->bytes, bytes, length);
    r->length = length;
    r->one_way = xpc_dictionary_get_bool(event, "one_way");
    snprintf(r->generation, sizeof(r->generation), "%s", state->generation);
    if (!enqueue(state->listener, r)) {
      atomic_store(&r->replied, 1);
      send_busy(event, peer, state->generation);
      oa_xpc_request_free(r);
    }
  });
  xpc_connection_activate(peer);
}
static void bootstrap_peer(oa_xpc_listener *l, xpc_connection_t peer) {
  __block oa_xpc_session_state *state = NULL;
  __block uint8_t finished = 0;
  if (!track_connection(l, peer)) {
    xpc_connection_cancel(peer);
    return;
  }
  listener_retain(l);
  xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
    if (xpc_get_type(event) != XPC_TYPE_DICTIONARY) {
      if (finished)
        return;
      finished = 1;
      close_session(state);
      xpc_connection_set_event_handler(peer, ^(xpc_object_t ignored) {
        (void)ignored;
      });
      untrack_connection(l, peer);
      if (state) {
        atomic_store(&state->bootstrap_active, 0);
        maybe_retire_session(state);
      }
      listener_release(l);
      return;
    }
    if (state)
      return;
    const char *kind = xpc_dictionary_get_string(event, "kind"),
               *challenge = xpc_dictionary_get_string(event, "challenge");
    if (!kind || strcmp(kind, "bootstrap") || !challenge ||
        xpc_dictionary_get_uint64(event, "protocol") != OA_PROTOCOL ||
        xpc_dictionary_get_value(event, "frame")) {
      send_refusal(event, peer, NULL);
      return;
    }
    oa_xpc_request proof = {0};
    oa_xpc_status proof_status = identify(event, peer, &proof);
    if (proof.message)
      xpc_release(proof.message);
    if (proof.remote)
      xpc_release(proof.remote);
    if (proof_status != OA_XPC_OK) {
      send_refusal(event, peer, NULL);
      return;
    }
    pthread_mutex_lock(&l->mutex);
    int session_available = !atomic_load(&l->closed) &&
                            l->session_count < OA_MAX_SESSIONS;
    if (session_available)
      l->session_count++;
    pthread_mutex_unlock(&l->mutex);
    if (!session_available) {
      send_busy(event, peer, NULL);
      return;
    }
    state = calloc(1, sizeof(*state));
    if (!state) {
      pthread_mutex_lock(&l->mutex);
      l->session_count--;
      pthread_mutex_unlock(&l->mutex);
      send_refusal(event, peer, NULL);
      return;
    }
    state->listener = l;
    atomic_store(&state->bootstrap_active, 1);
    state->bootstrap_pid = proof.identity.connection_pid;
    state->bootstrap_euid = proof.identity.connection_euid;
    snprintf(state->generation, sizeof(state->generation), "%d-%08x%08x",
             getpid(), arc4random(), arc4random());
    snprintf(state->cdhash, sizeof(state->cdhash), "%s", proof.cdhash);
    pthread_mutex_lock(&l->mutex);
    state->next = l->sessions;
    l->sessions = state;
    pthread_mutex_unlock(&l->mutex);
    state->anonymous_listener = xpc_connection_create(NULL, l->queue);
    if (!state->anonymous_listener ||
        !track_connection(l, state->anonymous_listener)) {
      send_refusal(event, peer, NULL);
      close_session(state);
      if (state->anonymous_listener) {
        xpc_release(state->anonymous_listener);
        state->anonymous_listener = NULL;
      }
      return;
    }
    xpc_connection_set_event_handler(
        state->anonymous_listener, ^(xpc_object_t e) {
          if (xpc_get_type(e) == XPC_TYPE_CONNECTION &&
              !atomic_load(&state->closed)) {
            session_peer(state, (xpc_connection_t)e);
          } else if (xpc_get_type(e) != XPC_TYPE_CONNECTION) {
            if (!atomic_exchange(&state->anonymous_active, 0))
              return;
            xpc_connection_t anonymous = state->anonymous_listener;
            state->anonymous_listener = NULL;
            if (anonymous) {
              xpc_connection_set_event_handler(
                  anonymous, ^(xpc_object_t ignored) { (void)ignored; });
              untrack_connection(l, anonymous);
            }
            maybe_retire_session(state);
            listener_release(l);
          }
        });
    listener_retain(l);
    atomic_store(&state->anonymous_active, 1);
    xpc_connection_activate(state->anonymous_listener);
    xpc_release(state->anonymous_listener);
    xpc_endpoint_t endpoint = xpc_endpoint_create(state->anonymous_listener);
    xpc_object_t reply = xpc_dictionary_create_reply(event);
    xpc_dictionary_set_string(reply, "status", "ok");
    xpc_dictionary_set_string(reply, "challenge", challenge);
    xpc_dictionary_set_string(reply, "generation", state->generation);
    xpc_dictionary_set_value(reply, "endpoint", endpoint);
    xpc_connection_send_message(peer, reply);
    xpc_release(reply);
    xpc_release(endpoint);
  });
  xpc_connection_activate(peer);
}
oa_xpc_status oa_xpc_listener_open(const char *service, size_t max,
                                   oa_xpc_listener **out) {
  if (!valid_service_name(service) || !max || !out)
    return OA_XPC_INVALID_ARGUMENT;
  oa_xpc_listener *l = calloc(1, sizeof(*l));
  if (!l)
    return OA_XPC_SYSTEM;
  l->max_frame = max;
  atomic_init(&l->refs, 1);
  pthread_mutex_init(&l->mutex, NULL);
  pthread_cond_init(&l->condition, NULL);
  l->queue = dispatch_queue_create("org.openabstractions.xpc.server",
                                   DISPATCH_QUEUE_SERIAL);
  l->bootstrap = xpc_connection_create_mach_service(
      service, l->queue, XPC_CONNECTION_MACH_SERVICE_LISTENER);
  if (!l->bootstrap) {
    oa_xpc_listener_free(l);
    return OA_XPC_SYSTEM;
  }
  listener_retain(l);
  __block uint8_t bootstrap_finished = 0;
  xpc_connection_set_event_handler(l->bootstrap, ^(xpc_object_t e) {
    if (xpc_get_type(e) == XPC_TYPE_CONNECTION) {
      bootstrap_peer(l, (xpc_connection_t)e);
    } else {
      if (bootstrap_finished)
        return;
      bootstrap_finished = 1;
      xpc_connection_set_event_handler(l->bootstrap, ^(xpc_object_t ignored) {
        (void)ignored;
      });
      // Mach-service creation is intentionally asynchronous. In particular,
      // XPC_ERROR_CONNECTION_INVALID is the registration result for a name the
      // current launchd job does not own. Make that terminal state observable
      // to Accept before releasing the handler's listener reference.
      oa_xpc_listener_close(l);
      listener_release(l);
    }
  });
  xpc_connection_activate(l->bootstrap);
  *out = l;
  return OA_XPC_OK;
}
oa_xpc_status oa_xpc_listener_next(oa_xpc_listener *l, uint64_t deadline,
                                   oa_xpc_cancel *cancel,
                                   oa_xpc_request **out) {
  if (!l || !out)
    return OA_XPC_INVALID_ARGUMENT;
  *out = NULL;
  pthread_mutex_lock(&l->mutex);
  while (!l->head && !atomic_load(&l->closed)) {
    if (cancelled(cancel)) {
      pthread_mutex_unlock(&l->mutex);
      return OA_XPC_CANCELLED;
    }
    uint64_t now = oa_xpc_now_ns();
    if (deadline && now >= deadline) {
      pthread_mutex_unlock(&l->mutex);
      return OA_XPC_TIMEOUT;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 10000000;
    if (ts.tv_nsec >= 1000000000) {
      ts.tv_sec++;
      ts.tv_nsec -= 1000000000;
    }
    pthread_cond_timedwait(&l->condition, &l->mutex, &ts);
  }
  if (!l->head) {
    pthread_mutex_unlock(&l->mutex);
    return OA_XPC_CLOSED;
  }
  *out = l->head;
  l->head = l->head->next;
  if (!l->head)
    l->tail = NULL;
  pthread_mutex_unlock(&l->mutex);
  return OA_XPC_OK;
}
void oa_xpc_listener_close(oa_xpc_listener *l) {
  if (!l || atomic_exchange(&l->closed, 1))
    return;
  if (l->bootstrap)
    xpc_connection_cancel(l->bootstrap);
  pthread_mutex_lock(&l->mutex);
  for (oa_xpc_tracked_connection *e = l->connections; e; e = e->next)
    xpc_connection_cancel(e->connection);
  for (oa_xpc_request *r = l->active_requests; r; r = r->active_next)
    oa_xpc_request_cancel(r);
  pthread_cond_broadcast(&l->condition);
  pthread_mutex_unlock(&l->mutex);
}
void oa_xpc_listener_free(oa_xpc_listener *l) {
  if (!l)
    return;
  oa_xpc_listener_close(l);
  pthread_mutex_lock(&l->mutex);
  oa_xpc_request *queued = l->head;
  l->head = NULL;
  l->tail = NULL;
  pthread_mutex_unlock(&l->mutex);
  while (queued) {
    oa_xpc_request *next = queued->next;
    oa_xpc_request_free(queued);
    queued = next;
  }
  listener_release(l);
}
oa_xpc_status oa_xpc_request_bytes(oa_xpc_request *r, const void **b,
                                   size_t *n) {
  if (!r || !b || !n)
    return OA_XPC_INVALID_ARGUMENT;
  *b = r->bytes;
  *n = r->length;
  return OA_XPC_OK;
}
oa_xpc_status oa_xpc_request_identity(oa_xpc_request *r, oa_xpc_identity *i) {
  if (!r || !i)
    return OA_XPC_INVALID_ARGUMENT;
  *i = r->identity;
  return OA_XPC_OK;
}
oa_xpc_status oa_xpc_request_reply(oa_xpc_request *r, const void *b, size_t n) {
  if (!r || (!b && n) || atomic_load(&r->closed) ||
      atomic_exchange(&r->replied, 1))
    return OA_XPC_INVALID_ARGUMENT;
  xpc_object_t q = xpc_dictionary_create_reply(r->message);
  if (!q)
    return OA_XPC_CLOSED;
  xpc_dictionary_set_string(q, "status", "ok");
  if (!r->one_way)
    xpc_dictionary_set_data(q, "frame", b, n);
  xpc_dictionary_set_string(q, "generation", r->generation);
  xpc_connection_send_message(r->remote, q);
  xpc_release(q);
  dispatch_semaphore_signal(r->done);
  return OA_XPC_OK;
}
oa_xpc_status oa_xpc_request_refuse_unmet_proof(oa_xpc_request *r,
                                                uint8_t attribute,
                                                uint8_t required) {
  if (!r || attribute > 5 || required > 8 ||
      ((attribute == 0) != (required == 0)))
    return OA_XPC_INVALID_ARGUMENT;
  if (atomic_load(&r->closed) || atomic_exchange(&r->replied, 1))
    return OA_XPC_CLOSED;
  xpc_object_t q = xpc_dictionary_create_reply(r->message);
  if (!q)
    return OA_XPC_CLOSED;
  xpc_dictionary_set_string(q, "status", "refused");
  xpc_dictionary_set_string(q, "reason", "unmet_proof");
  xpc_dictionary_set_uint64(q, "proof_attribute", attribute);
  xpc_dictionary_set_uint64(q, "proof_required", required);
  xpc_dictionary_set_string(q, "generation", r->generation);
  xpc_connection_send_message(r->remote, q);
  xpc_release(q);
  dispatch_semaphore_signal(r->done);
  return OA_XPC_OK;
}
oa_xpc_status oa_xpc_request_wait(oa_xpc_request *r, uint64_t d,
                                  oa_xpc_cancel *c) {
  if (!r)
    return OA_XPC_INVALID_ARGUMENT;
  return deadline_wait(r->done, d, c);
}
uint8_t oa_xpc_request_active(oa_xpc_request *r) {
  return r && !atomic_load(&r->closed);
}
void oa_xpc_request_cancel(oa_xpc_request *r) {
  if (!r || atomic_exchange(&r->closed, 1))
    return;
  if (!atomic_exchange(&r->replied, 1) && r->message && r->remote) {
    xpc_object_t q = xpc_dictionary_create_reply(r->message);
    if (q) {
      xpc_dictionary_set_string(q, "status", r->one_way ? "ok" : "closed");
      xpc_dictionary_set_string(q, "generation", r->generation);
      xpc_connection_send_message(r->remote, q);
      xpc_release(q);
    }
  }
  dispatch_semaphore_signal(r->done);
}
void oa_xpc_request_free(oa_xpc_request *r) {
  if (!r)
    return;
  oa_xpc_request_cancel(r);
  oa_xpc_listener *l = r->listener;
  if (l) {
    pthread_mutex_lock(&l->mutex);
    oa_xpc_request **at = &l->active_requests;
    while (*at && *at != r)
      at = &(*at)->active_next;
    int found = *at == r;
    if (found)
      *at = r->active_next;
    if (found)
      l->active_request_count--;
    r->listener = NULL;
    pthread_mutex_unlock(&l->mutex);
    listener_release(l);
  }
  if (r->message)
    xpc_release(r->message);
  if (r->remote)
    xpc_release(r->remote);
  free(r->bytes);
#if !OS_OBJECT_USE_OBJC
  dispatch_release(r->done);
#endif
  free(r);
}

/* Client implementation follows the same content-free bootstrap protocol. */
typedef struct {
  dispatch_semaphore_t sem;
  xpc_object_t reply;
  atomic_uint refs;
} reply_wait;
static void reply_wait_release(reply_wait *w) {
  if (atomic_fetch_sub(&w->refs, 1) == 1) {
    if (w->reply)
      xpc_release(w->reply);
#if !OS_OBJECT_USE_OBJC
    dispatch_release(w->sem);
#endif
    free(w);
  }
}
static xpc_object_t send_wait(xpc_connection_t c, xpc_object_t m, uint64_t d,
                              oa_xpc_cancel *k, oa_xpc_status *out,
                              uint8_t *did_send) {
  *did_send = 0;
  if (cancelled(k)) {
    *out = OA_XPC_CANCELLED;
    return NULL;
  }
  if (d && oa_xpc_now_ns() >= d) {
    *out = OA_XPC_TIMEOUT;
    return NULL;
  }
  reply_wait *w = calloc(1, sizeof(*w));
  if (!w) {
    *out = OA_XPC_SYSTEM;
    return NULL;
  }
  w->sem = dispatch_semaphore_create(0);
  atomic_init(&w->refs, 2);
  xpc_connection_send_message_with_reply(
      c, m, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^(xpc_object_t r) {
        w->reply = xpc_retain(r);
        dispatch_semaphore_signal(w->sem);
        reply_wait_release(w);
      });
  *did_send = 1;
  *out = (oa_xpc_status)deadline_wait(w->sem, d, k);
  xpc_object_t reply = NULL;
  if (*out == OA_XPC_OK && w->reply &&
      xpc_get_type(w->reply) == XPC_TYPE_ERROR) {
#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 120000
    int peer_requirement_failed = 0;
    if (__builtin_available(macOS 12.0, *)) {
      peer_requirement_failed =
          w->reply == XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT;
    }
    if (peer_requirement_failed)
      *out = OA_XPC_UNTRUSTED;
    else
#endif
      *out = (w->reply == XPC_ERROR_CONNECTION_INVALID ||
              w->reply == XPC_ERROR_CONNECTION_INTERRUPTED)
                 ? OA_XPC_CLOSED
                 : OA_XPC_SYSTEM;
  } else if (*out == OA_XPC_OK && w->reply) {
    reply = xpc_retain(w->reply);
  }
  reply_wait_release(w);
  return reply;
}
static char *static_requirement(const char *path) {
  CFURLRef u = CFURLCreateFromFileSystemRepresentation(
      NULL, (const UInt8 *)path, strlen(path), 0);
  SecStaticCodeRef c = NULL;
  SecRequirementRef r = NULL;
  CFStringRef s = NULL;
  char *out = NULL;
  if (u &&
      SecStaticCodeCreateWithPath(u, kSecCSDefaultFlags, &c) == errSecSuccess &&
      SecStaticCodeCheckValidity(c, kSecCSDefaultFlags, NULL) ==
          errSecSuccess &&
      SecCodeCopyDesignatedRequirement(c, kSecCSDefaultFlags, &r) ==
          errSecSuccess &&
      SecRequirementCopyString(r, kSecCSDefaultFlags, &s) == errSecSuccess) {
    CFIndex n = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s),
                                                  kCFStringEncodingUTF8) +
                1;
    out = malloc((size_t)n);
    if (out && !CFStringGetCString(s, out, n, kCFStringEncodingUTF8)) {
      free(out);
      out = NULL;
    }
  }
  if (s)
    CFRelease(s);
  if (r)
    CFRelease(r);
  if (c)
    CFRelease(c);
  if (u)
    CFRelease(u);
  return out;
}
static oa_xpc_status set_requirement(xpc_connection_t c, const char *r) {
  if (__builtin_available(macOS 12.0, *))
    return xpc_connection_set_peer_code_signing_requirement(c, r) == 0
               ? OA_XPC_OK
               : OA_XPC_UNTRUSTED;
  return OA_XPC_UNAVAILABLE;
}
oa_xpc_status oa_xpc_client_open(const char *service, const char *program,
                                 uint32_t euid, size_t max, uint64_t d,
                                 oa_xpc_cancel *k, oa_xpc_client **out) {
  if (!valid_service_name(service) || !program || !*program || !out)
    return OA_XPC_INVALID_ARGUMENT;
  char resolved[PATH_MAX];
  if (!realpath(program, resolved))
    return OA_XPC_UNTRUSTED;
  oa_xpc_client *c = calloc(1, sizeof(*c));
  if (!c)
    return OA_XPC_SYSTEM;
  c->expected_path = strdup(resolved);
  c->expected_euid = euid;
  c->max_reply = max;
  c->requirement = static_requirement(resolved);
  c->queue = dispatch_queue_create("org.openabstractions.xpc.client",
                                   DISPATCH_QUEUE_SERIAL);
  c->bootstrap = xpc_connection_create_mach_service(service, c->queue, 0);
  if (!c->expected_path || !c->requirement || !c->queue || !c->bootstrap) {
    oa_xpc_client_free(c);
    return OA_XPC_UNTRUSTED;
  }
  oa_xpc_status requirement_status =
      set_requirement(c->bootstrap, c->requirement);
  if (requirement_status != OA_XPC_OK) {
    oa_xpc_client_free(c);
    return requirement_status;
  }
  xpc_connection_set_event_handler(c->bootstrap, ^(xpc_object_t e) {
    (void)e;
  });
  xpc_connection_activate(c->bootstrap);
  char challenge[80];
  snprintf(challenge, sizeof(challenge), "%d-%08x%08x", getpid(), arc4random(),
           arc4random());
  xpc_object_t hello = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_string(hello, "kind", "bootstrap");
  xpc_dictionary_set_string(hello, "challenge", challenge);
  xpc_dictionary_set_uint64(hello, "protocol", OA_PROTOCOL);
  oa_xpc_status st;
  uint8_t did_send = 0;
  xpc_object_t reply = send_wait(c->bootstrap, hello, d, k, &st, &did_send);
  (void)did_send;
  xpc_release(hello);
  if (!reply) {
    oa_xpc_client_free(c);
    return st;
  }
  if (validate_expected(reply, c->expected_path, c->expected_euid) !=
      OA_XPC_OK) {
    xpc_release(reply);
    oa_xpc_client_free(c);
    return OA_XPC_UNTRUSTED;
  }
  const char *status = xpc_dictionary_get_string(reply, "status"),
             *echo = xpc_dictionary_get_string(reply, "challenge"),
             *gen = xpc_dictionary_get_string(reply, "generation");
  xpc_object_t endpoint = xpc_dictionary_get_value(reply, "endpoint");
  if (!status || strcmp(status, "ok") || !echo || strcmp(echo, challenge) ||
      !gen || !endpoint || xpc_get_type(endpoint) != XPC_TYPE_ENDPOINT) {
    int refused = status && strcmp(status, "refused") == 0;
    int busy = status && strcmp(status, "busy") == 0;
    xpc_release(reply);
    oa_xpc_client_free(c);
    return refused ? OA_XPC_UNTRUSTED : busy ? OA_XPC_SYSTEM : OA_XPC_PROTOCOL;
  }
  c->generation = strdup(gen);
  c->session = xpc_connection_create_from_endpoint(endpoint);
  xpc_release(reply);
  if (!c->generation || !c->session) {
    oa_xpc_client_free(c);
    return OA_XPC_SYSTEM;
  }
  requirement_status = set_requirement(c->session, c->requirement);
  if (requirement_status != OA_XPC_OK) {
    oa_xpc_client_free(c);
    return requirement_status;
  }
  xpc_connection_set_event_handler(c->session, ^(xpc_object_t e) {
    (void)e;
  });
  xpc_connection_activate(c->session);
  *out = c;
  return OA_XPC_OK;
}
oa_xpc_status oa_xpc_client_call(oa_xpc_client *c, const void *b, size_t n,
                                 uint8_t one, uint64_t d, oa_xpc_cancel *k,
                                 size_t *sent, void **reply, size_t *rn,
                                 uint8_t *proof_attribute,
                                 uint8_t *proof_required) {
  if (!c || (!b && n) || !sent || !reply || !rn)
    return OA_XPC_INVALID_ARGUMENT;
  *sent = 0;
  *reply = NULL;
  *rn = 0;
  if (proof_attribute)
    *proof_attribute = 0;
  if (proof_required)
    *proof_required = 0;
  if (atomic_load(&c->closed))
    return OA_XPC_CLOSED;
  xpc_object_t m = xpc_dictionary_create(NULL, NULL, 0);
  xpc_dictionary_set_string(m, "generation", c->generation);
  xpc_dictionary_set_data(m, "frame", b, n);
  xpc_dictionary_set_bool(m, "one_way", one != 0);
  oa_xpc_status st;
  uint8_t did_send = 0;
  xpc_object_t r = send_wait(c->session, m, d, k, &st, &did_send);
  if (did_send)
    *sent = n;
  xpc_release(m);
  if (!r)
    return st;
  if (validate_expected(r, c->expected_path, c->expected_euid) != OA_XPC_OK) {
    xpc_release(r);
    return OA_XPC_UNTRUSTED;
  }
  const char *status = xpc_dictionary_get_string(r, "status"),
             *reply_generation = xpc_dictionary_get_string(r, "generation");
  if (status && strcmp(status, "refused") == 0) {
    const char *reason = xpc_dictionary_get_string(r, "reason");
    if (reason && strcmp(reason, "unmet_proof") == 0) {
      xpc_object_t attribute_value = xpc_dictionary_get_value(r, "proof_attribute");
      xpc_object_t required_value = xpc_dictionary_get_value(r, "proof_required");
      uint64_t attribute = xpc_dictionary_get_uint64(r, "proof_attribute");
      uint64_t required = xpc_dictionary_get_uint64(r, "proof_required");
      if (!reply_generation || strcmp(reply_generation, c->generation) ||
          !attribute_value || xpc_get_type(attribute_value) != XPC_TYPE_UINT64 ||
          !required_value || xpc_get_type(required_value) != XPC_TYPE_UINT64 ||
          attribute > 5 || required > 8 || ((attribute == 0) != (required == 0))) {
        xpc_release(r);
        return OA_XPC_PROTOCOL;
      }
      if (proof_attribute)
        *proof_attribute = (uint8_t)attribute;
      if (proof_required)
        *proof_required = (uint8_t)required;
      xpc_release(r);
      return OA_XPC_CALLER_PROOF_UNMET;
    }
    xpc_release(r);
    return OA_XPC_UNTRUSTED;
  }
  if (status && strcmp(status, "busy") == 0) {
    xpc_release(r);
    return OA_XPC_SYSTEM;
  }
  if (status && strcmp(status, "closed") == 0) {
    xpc_release(r);
    return OA_XPC_CLOSED;
  }
  if (!status || strcmp(status, "ok") || !reply_generation ||
      strcmp(reply_generation, c->generation)) {
    xpc_release(r);
    return OA_XPC_PROTOCOL;
  }
  size_t len = 0;
  const void *p = xpc_dictionary_get_data(r, "frame", &len);
  if (one) {
    if (p) {
      xpc_release(r);
      return OA_XPC_PROTOCOL;
    }
    xpc_release(r);
    return OA_XPC_OK;
  }
  if (!p || len > c->max_reply) {
    xpc_release(r);
    return p ? OA_XPC_INVALID_ARGUMENT : OA_XPC_PROTOCOL;
  }
  void *copy = malloc(len ? len : 1);
  if (!copy) {
    xpc_release(r);
    return OA_XPC_SYSTEM;
  }
  memcpy(copy, p, len);
  xpc_release(r);
  *reply = copy;
  *rn = len;
  return OA_XPC_OK;
}
void oa_xpc_client_close(oa_xpc_client *c) {
  if (!c || atomic_exchange(&c->closed, 1))
    return;
  if (c->session)
    xpc_connection_cancel(c->session);
  if (c->bootstrap)
    xpc_connection_cancel(c->bootstrap);
}
void oa_xpc_client_free(oa_xpc_client *c) {
  if (!c)
    return;
  oa_xpc_client_close(c);
  if (c->session)
    xpc_release(c->session);
  if (c->bootstrap)
    xpc_release(c->bootstrap);
#if !OS_OBJECT_USE_OBJC
  if (c->queue)
    dispatch_release(c->queue);
#endif
  free(c->generation);
  free(c->expected_path);
  free(c->requirement);
  free(c);
}
void oa_xpc_bytes_free(void *b) { free(b); }
