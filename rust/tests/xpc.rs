use abstraction_ipc::{
    Cancellation, FrameTransport, ServerExpectation, CANCELLED, DISCONNECTED, TIMEOUT, UNTRUSTED,
};
use std::{
    env,
    time::{Duration, Instant},
};

fn fixture() -> Option<(String, ServerExpectation)> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let service = env::var("OA_XPC_TEST_SERVICE").expect("OA_XPC_TEST_SERVICE is required");
    let program = env::var("OA_XPC_TEST_PROGRAM").expect("OA_XPC_TEST_PROGRAM is required");
    let principal = env::var("OA_XPC_TEST_UID").expect("OA_XPC_TEST_UID is required");
    Some((
        format!("xpc:{service}"),
        ServerExpectation {
            principal_kind: 2,
            principal,
            program,
        },
    ))
}

fn transport(endpoint: &str, server: ServerExpectation) -> FrameTransport {
    FrameTransport::new(endpoint, Duration::from_secs(5))
        .unwrap()
        .with_server_expectation(server)
        .unwrap()
}

#[test]
fn shared_xpc_transport_runtime_cases() {
    let Some((endpoint, server)) = fixture() else {
        return;
    };
    for payload in [
        Vec::new(),
        b"rust-xpc-echo".to_vec(),
        vec![0, 10, 255],
        vec![b'x'; 128 * 1024],
    ] {
        assert_eq!(
            transport(&endpoint, server.clone())
                .exchange_frame(&payload)
                .unwrap(),
            payload
        );
    }
    transport(&endpoint, server.clone())
        .write_frame(b"rust-one-way")
        .unwrap();

    let cancellation = Cancellation::new().unwrap();
    cancellation.signal();
    let cancelled = transport(&endpoint, server.clone())
        .with_cancellation(cancellation)
        .exchange_frame(b"must-not-dispatch")
        .unwrap_err();
    assert_eq!(cancelled.status, CANCELLED);

    let expired = transport(&endpoint, server.clone())
        .with_deadline(Instant::now() - Duration::from_millis(1))
        .exchange_frame(b"must-not-dispatch")
        .unwrap_err();
    assert_eq!(expired.status, TIMEOUT);

    let wrong = ServerExpectation {
        program: "/usr/bin/true".into(),
        ..server.clone()
    };
    let refused = transport(&endpoint, wrong)
        .exchange_frame(b"must-not-dispatch")
        .unwrap_err();
    assert!(
        [UNTRUSTED, DISCONNECTED].contains(&refused.status),
        "{refused}"
    );
    assert_eq!(refused.transferred, 0);

    let missing = transport(&(endpoint + ".missing"), server)
        .exchange_frame(b"must-not-dispatch")
        .unwrap_err();
    assert_eq!(missing.status, DISCONNECTED);
    assert_eq!(missing.transferred, 0);
}
