/* Bounded native check of actual client connection cleanup states. */
#include "../../../xpc_native_darwin.c"

static xpc_connection_t bootstrap(dispatch_queue_t queue) {
  return xpc_connection_create_mach_service("com.openabstractions.a7-cleanup-unregistered", queue, 0);
}

static void check(const char *name, int state, int session) {
  oa_xpc_client *client = calloc(1, sizeof(*client));
  client->queue = dispatch_queue_create("com.openabstractions.a7-cleanup", DISPATCH_QUEUE_SERIAL);
  xpc_connection_t connection;
  xpc_connection_t listener = NULL;
  if (session) {
    listener = xpc_connection_create(NULL, client->queue);
    xpc_endpoint_t endpoint = xpc_endpoint_create(listener);
    connection = xpc_connection_create_from_endpoint(endpoint);
    xpc_release(endpoint);
    client->session = connection;
  } else {
    connection = bootstrap(client->queue);
    client->bootstrap = connection;
  }
  if (!connection) abort();
  if (state == 1 || state == 2) {
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {(void)event;});
    xpc_connection_activate(connection);
  }
  if (state == 2) xpc_connection_cancel(connection);
  if (state == 3 && set_requirement(connection, "invalid requirement syntax )") != OA_XPC_UNTRUSTED) abort();
  oa_xpc_client_close(client);
  oa_xpc_client_close(client);
  oa_xpc_client_free(client);
  if (listener) {
    cancel_with_noop_handler(listener);
    xpc_release(listener);
  }
  printf("PASS %s\n", name);
}
static void check_server_tracking_refusal(const char *name, int closed) {
  oa_xpc_listener listener = {0};
  pthread_mutex_init(&listener.mutex, NULL);
  atomic_store(&listener.refs, 1);
  listener.queue = dispatch_queue_create("com.openabstractions.test.track-refusal", DISPATCH_QUEUE_SERIAL);
  atomic_store(&listener.closed, closed);
  listener.connection_count = closed ? 0 : OA_MAX_CONNECTIONS;
  oa_xpc_session_state state = {.listener = &listener};
  state.anonymous_listener = xpc_connection_create(NULL, listener.queue);
  if (!state.anonymous_listener || track_connection(&listener, state.anonymous_listener)) abort();
  close_untracked_session(&state);
  if (!atomic_load(&state.closed) || state.anonymous_listener || listener.connections ||
      listener.connection_count != (closed ? 0 : OA_MAX_CONNECTIONS) || atomic_load(&listener.refs) != 1) abort();
  pthread_mutex_destroy(&listener.mutex);
#if !OS_OBJECT_USE_OBJC
  dispatch_release(listener.queue);
#endif
  printf("PASS %s\n", name);
}

static void check_active_server_handler(void) {
  dispatch_semaphore_t done = dispatch_semaphore_create(0);
  atomic_uint calls = 0;
  atomic_uint *observed = &calls;
  oa_xpc_session_state state = {0};
  state.anonymous_listener = xpc_connection_create(NULL, NULL);
  xpc_connection_set_event_handler(state.anonymous_listener, ^(xpc_object_t event) {
    if (event == XPC_ERROR_CONNECTION_INVALID) {
      atomic_fetch_add(observed, 1);
      dispatch_semaphore_signal(done);
    }
  });
  xpc_connection_activate(state.anonymous_listener);
  close_session(&state);
  close_session(&state);
  if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 2000000000)) || atomic_load(&calls) != 1) abort();
  xpc_release(state.anonymous_listener);
#if !OS_OBJECT_USE_OBJC
  dispatch_release(done);
#endif
  puts("PASS active server handler retained across idempotent close");
}

int main(void) {
  check("inactive bootstrap / preflight failure",0,0);
  check("active bootstrap / send failure",1,0);
  check("already-cancelled bootstrap / repeated close",2,0);
  check("inactive bootstrap / rejected requirement",3,0);
  check("inactive endpoint session / generation failure",0,1);
  check("active endpoint session / normal close",1,1);
  check("already-cancelled endpoint session / repeated close",2,1);
  check("inactive endpoint session / rejected requirement",3,1);
  check_server_tracking_refusal("owned anonymous listener / capacity refusal",0);
  check_server_tracking_refusal("owned anonymous listener / closed refusal",1);
  check_active_server_handler();
  return 0;
}
