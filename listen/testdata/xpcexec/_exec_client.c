#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

#ifndef OA_VARIANT
#define OA_VARIANT "unspecified"
#endif
static const char build_variant[] __attribute__((used)) = OA_VARIANT;

typedef struct { dispatch_semaphore_t done; xpc_object_t reply; } reply_wait;

static xpc_object_t send_wait(xpc_connection_t connection, xpc_object_t message) {
    reply_wait *wait = calloc(1, sizeof(*wait));
    if (!wait) return NULL;
    wait->done = dispatch_semaphore_create(0);
    xpc_connection_send_message_with_reply(connection, message,
        dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^(xpc_object_t reply) {
            wait->reply = xpc_retain(reply);
            dispatch_semaphore_signal(wait->done);
        });
    if (dispatch_semaphore_wait(wait->done,
            dispatch_time(DISPATCH_TIME_NOW, 5LL * NSEC_PER_SEC)) != 0)
        return NULL;
    xpc_object_t reply = wait->reply;
    dispatch_release(wait->done);
    free(wait);
    return reply;
}

static const char *xpc_error(xpc_object_t object) {
    if (!object || xpc_get_type(object) != XPC_TYPE_ERROR) return NULL;
    const char *description = xpc_dictionary_get_string(
        object, XPC_ERROR_KEY_DESCRIPTION);
    return description ? description : "xpc error";
}

static xpc_connection_t connect_service(const char *service,
                                        const char *requirement) {
    xpc_connection_t connection = xpc_connection_create_mach_service(
        service, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), 0);
    if (!connection || xpc_connection_set_peer_code_signing_requirement(
            connection, requirement) != 0) return NULL;
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        (void)event;
    });
    xpc_connection_activate(connection);
    return connection;
}

static void send_status(xpc_connection_t peer, xpc_object_t request,
                        const char *status, xpc_object_t endpoint,
                        const char *generation) {
    xpc_object_t reply = xpc_dictionary_create_reply(request);
    if (!reply) return;
    xpc_dictionary_set_string(reply, "status", status);
    if (endpoint) xpc_dictionary_set_value(reply, "endpoint", endpoint);
    if (generation) xpc_dictionary_set_string(reply, "generation", generation);
    xpc_connection_send_message(peer, reply);
    xpc_release(reply);
}

static int run_broker(const char *service) {
    __block xpc_object_t saved_endpoint = NULL;
    __block char *saved_generation = NULL;
    xpc_connection_t listener = xpc_connection_create_mach_service(service,
        dispatch_get_main_queue(), XPC_CONNECTION_MACH_SERVICE_LISTENER);
    if (!listener) return 2;
    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) return;
        xpc_connection_t peer = (xpc_connection_t)event;
        xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            if (xpc_get_type(message) != XPC_TYPE_DICTIONARY) return;
            const char *kind = xpc_dictionary_get_string(message, "kind");
            if (kind && strcmp(kind, "put") == 0) {
                xpc_object_t endpoint = xpc_dictionary_get_value(message, "endpoint");
                const char *generation = xpc_dictionary_get_string(message, "generation");
                if (endpoint && xpc_get_type(endpoint) == XPC_TYPE_ENDPOINT && generation) {
                    if (saved_endpoint) xpc_release(saved_endpoint);
                    saved_endpoint = xpc_retain(endpoint);
                    free(saved_generation);
                    saved_generation = strdup(generation);
                    send_status(peer, message, "ok", NULL, NULL);
                } else send_status(peer, message, "refused", NULL, NULL);
            } else if (kind && strcmp(kind, "get") == 0 && saved_endpoint) {
                send_status(peer, message, "ok", saved_endpoint, saved_generation);
            } else send_status(peer, message, "refused", NULL, NULL);
        });
        xpc_connection_activate(peer);
    });
    xpc_connection_activate(listener);
    dispatch_main();
}

static int put_endpoint(const char *broker, const char *requirement,
                        xpc_object_t endpoint, const char *generation) {
    xpc_connection_t connection = connect_service(broker, requirement);
    if (!connection) return 20;
    xpc_object_t request = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(request, "kind", "put");
    xpc_dictionary_set_value(request, "endpoint", endpoint);
    xpc_dictionary_set_string(request, "generation", generation);
    xpc_object_t reply = send_wait(connection, request);
    const char *status = reply && xpc_get_type(reply) == XPC_TYPE_DICTIONARY
        ? xpc_dictionary_get_string(reply, "status") : NULL;
    int result = status && strcmp(status, "ok") == 0 ? 0 : 21;
    if (reply) xpc_release(reply);
    xpc_release(request);
    xpc_connection_cancel(connection);
    return result;
}

static int run_after(const char *broker, const char *broker_requirement,
                     const char *server_requirement, const char *before_pid) {
    xpc_connection_t relay = connect_service(broker, broker_requirement);
    if (!relay) return 30;
    xpc_object_t get = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(get, "kind", "get");
    xpc_object_t got = send_wait(relay, get);
    xpc_release(get);
    xpc_connection_cancel(relay);
    if (!got || xpc_get_type(got) != XPC_TYPE_DICTIONARY) return 31;
    xpc_object_t endpoint = xpc_dictionary_get_value(got, "endpoint");
    const char *generation = xpc_dictionary_get_string(got, "generation");
    if (!endpoint || xpc_get_type(endpoint) != XPC_TYPE_ENDPOINT || !generation)
        return 32;
    char generation_copy[128];
    snprintf(generation_copy, sizeof(generation_copy), "%s", generation);
    xpc_connection_t session = xpc_connection_create_from_endpoint(endpoint);
    if (!session || xpc_connection_set_peer_code_signing_requirement(
            session, server_requirement) != 0) return 33;
    xpc_connection_set_event_handler(session, ^(xpc_object_t event) { (void)event; });
    xpc_connection_activate(session);
    xpc_release(got);

    const char marker[] = "EXEC_IN_PLACE_EFFECT_MARKER";
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "generation", generation_copy);
    xpc_dictionary_set_data(message, "frame", marker, sizeof(marker) - 1);
    xpc_dictionary_set_bool(message, "one_way", false);
    xpc_object_t reply = send_wait(session, message);
    xpc_release(message);
    const char *error = xpc_error(reply);
    const char *status = reply && xpc_get_type(reply) == XPC_TYPE_DICTIONARY
        ? xpc_dictionary_get_string(reply, "status") : NULL;
    int same_pid = atoi(before_pid) == getpid();
    int refused = error || (status && (strcmp(status, "closed") == 0 ||
                                      strcmp(status, "refused") == 0));
    printf("result=%s same_pid=%d pid=%d variant=%s status=%s error=%s\n",
           refused ? "refused" : "unexpected", same_pid, getpid(),
           build_variant, status ? status : "none", error ? error : "none");
    fflush(stdout);
    if (reply) xpc_release(reply);
    xpc_connection_cancel(session);
    return refused && same_pid ? 0 : 34;
}

static int run_before(const char *service, const char *server_requirement,
                      const char *broker, const char *broker_requirement,
                      const char *after) {
    xpc_connection_t bootstrap = connect_service(service, server_requirement);
    if (!bootstrap) return 40;
    char challenge[80];
    snprintf(challenge, sizeof(challenge), "%d-%08x%08x", getpid(),
             arc4random(), arc4random());
    xpc_object_t hello = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(hello, "kind", "bootstrap");
    xpc_dictionary_set_string(hello, "challenge", challenge);
    xpc_dictionary_set_uint64(hello, "protocol", 1);
    xpc_object_t reply = send_wait(bootstrap, hello);
    xpc_release(hello);
    if (!reply || xpc_get_type(reply) != XPC_TYPE_DICTIONARY) return 41;
    const char *status = xpc_dictionary_get_string(reply, "status");
    const char *echo = xpc_dictionary_get_string(reply, "challenge");
    const char *generation = xpc_dictionary_get_string(reply, "generation");
    xpc_object_t endpoint = xpc_dictionary_get_value(reply, "endpoint");
    if (!status || strcmp(status, "ok") || !echo || strcmp(echo, challenge) ||
        !generation || !endpoint || xpc_get_type(endpoint) != XPC_TYPE_ENDPOINT)
        return 42;
    int result = put_endpoint(broker, broker_requirement, endpoint, generation);
    if (result) return result;
    char pid[32];
    snprintf(pid, sizeof(pid), "%d", getpid());
    execl(after, after, "--after", broker, broker_requirement,
          server_requirement, pid, (char *)NULL);
    fprintf(stderr, "exec %s: %s\n", after, strerror(errno));
    return 43;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--broker") == 0)
        return run_broker(argv[2]);
    if (argc == 6 && strcmp(argv[1], "--after") == 0)
        return run_after(argv[2], argv[3], argv[4], argv[5]);
    if (argc == 6)
        return run_before(argv[1], argv[2], argv[3], argv[4], argv[5]);
    fprintf(stderr, "usage: exec_client SERVICE SERVER_REQ BROKER BROKER_REQ AFTER\n");
    return 2;
}
