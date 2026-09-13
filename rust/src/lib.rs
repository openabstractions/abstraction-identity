//! Bounded framing over the existing native client ABI. No service or provider.
#![forbid(unsafe_op_in_unsafe_fn)]
use std::{
    ffi::{c_char, c_void},
    fmt,
    ptr::{self, NonNull},
    sync::Arc,
    time::{Duration, Instant},
};

pub const OK: i32 = 0;
pub const TIMEOUT: i32 = 1;
pub const DISCONNECTED: i32 = 2;
pub const IO_ERROR: i32 = 3;
pub const INVALID_ARGUMENT: i32 = 4;
pub const INTERNAL_ERROR: i32 = 6;
pub const CANCELLED: i32 = 7;
pub const UNTRUSTED: i32 = 8;
pub const PROOF_UNAVAILABLE: i32 = 9;
const MAX_FRAME: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerExpectation {
    pub principal_kind: u32,
    pub principal: String,
    pub program: String,
}
#[repr(C)]
struct NativeExpectation {
    struct_size: u32,
    version: u32,
    principal_kind: u32,
    reserved: u32,
    principal: *const c_char,
    principal_length: usize,
    program: *const c_char,
    program_length: usize,
}
extern "C" {
    fn oa_ipc_open_verified(
        endpoint: *const c_char,
        length: usize,
        timeout_ms: u32,
        signal: *mut c_void,
        server: *const NativeExpectation,
        out: *mut *mut c_void,
    ) -> i32;
    fn oa_ipc_version() -> u32;
    fn oa_ipc_runtime_endpoint(buffer: *mut c_char, capacity: usize, required: *mut usize) -> i32;
    fn oa_ipc_cancellation_create(out: *mut *mut c_void) -> i32;
    fn oa_ipc_cancellation_signal(handle: *mut c_void);
    fn oa_ipc_cancellation_release(handle: *mut c_void);
    fn oa_ipc_open_cancelable(
        endpoint: *const c_char,
        length: usize,
        timeout_ms: u32,
        signal: *mut c_void,
        out: *mut *mut c_void,
    ) -> i32;
    fn oa_ipc_write(
        handle: *mut c_void,
        data: *const c_void,
        length: usize,
        transferred: *mut usize,
    ) -> i32;
    fn oa_ipc_read(
        handle: *mut c_void,
        data: *mut c_void,
        capacity: usize,
        transferred: *mut usize,
    ) -> i32;
    fn oa_ipc_close(handle: *mut c_void);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub status: i32,
    pub transferred: usize,
    pub message: &'static str,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (status {}, confirmed prefix {})",
            self.message, self.status, self.transferred
        )
    }
}
impl std::error::Error for Error {}
fn error(status: i32, message: &'static str) -> Error {
    Error {
        status,
        message,
        transferred: 0,
    }
}
fn version() -> Result<(), Error> {
    // No pointers or ownership cross this ABI query.
    if unsafe { oa_ipc_version() } != 1 {
        Err(error(INVALID_ARGUMENT, "unsupported IPC ABI"))
    } else {
        Ok(())
    }
}

pub fn runtime_endpoint() -> Result<String, Error> {
    version()?;
    let mut required = 0usize;
    // Query writes only our live usize. Native code owns no returned allocation.
    let mut status = unsafe { oa_ipc_runtime_endpoint(ptr::null_mut(), 0, &mut required) };
    for _ in 0..3 {
        if status != OK {
            return Err(error(status, "bootstrap query failed"));
        }
        if !(2..=65536).contains(&required) {
            return Err(error(INVALID_ARGUMENT, "bootstrap size invalid"));
        }
        let mut bytes = vec![0u8; required];
        // Buffer and required remain exclusively borrowed throughout the call.
        status = unsafe {
            oa_ipc_runtime_endpoint(bytes.as_mut_ptr().cast(), bytes.len(), &mut required)
        };
        if status == INVALID_ARGUMENT && required > bytes.len() {
            status = OK;
            continue;
        }
        if status != OK {
            return Err(error(status, "bootstrap copy failed"));
        }
        if required < 2 || required > bytes.len() || bytes[required - 1] != 0 {
            return Err(error(INTERNAL_ERROR, "invalid bootstrap result"));
        }
        bytes.truncate(required - 1);
        return String::from_utf8(bytes)
            .map_err(|_| error(INVALID_ARGUMENT, "bootstrap is not UTF-8"));
    }
    Err(error(INVALID_ARGUMENT, "bootstrap changed repeatedly"))
}

struct Signal(NonNull<c_void>);
// The ABI explicitly permits concurrent signal calls. Arc keeps release after
// the last borrowed open/signal call; there is no public raw handle access.
unsafe impl Send for Signal {}
unsafe impl Sync for Signal {}
impl Drop for Signal {
    fn drop(&mut self) {
        unsafe { oa_ipc_cancellation_release(self.0.as_ptr()) }
    }
}
#[derive(Clone)]
pub struct Cancellation(Arc<Signal>);
impl Cancellation {
    pub fn new() -> Result<Self, Error> {
        version()?;
        let mut raw = ptr::null_mut();
        let status = unsafe { oa_ipc_cancellation_create(&mut raw) };
        if status != OK {
            return Err(error(status, "cancellation creation failed"));
        }
        let pointer =
            NonNull::new(raw).ok_or_else(|| error(INTERNAL_ERROR, "native null signal"))?;
        Ok(Self(Arc::new(Signal(pointer))))
    }
    pub fn signal(&self) {
        unsafe { oa_ipc_cancellation_signal(self.0 .0.as_ptr()) }
    }
}

struct Connection(NonNull<c_void>);
impl Drop for Connection {
    fn drop(&mut self) {
        unsafe { oa_ipc_close(self.0.as_ptr()) }
    }
}
impl Connection {
    fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let mut moved = 0;
        let status = unsafe {
            oa_ipc_write(
                self.0.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                &mut moved,
            )
        };
        if status != OK {
            return Err(Error {
                status,
                transferred: moved,
                message: "frame write failed; acceptance may be unknown",
            });
        }
        if moved != bytes.len() {
            return Err(error(INTERNAL_ERROR, "short successful native write"));
        }
        Ok(())
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        let mut total = 0;
        while total < bytes.len() {
            let mut moved = 0;
            let status = unsafe {
                oa_ipc_read(
                    self.0.as_ptr(),
                    bytes[total..].as_mut_ptr().cast(),
                    bytes.len() - total,
                    &mut moved,
                )
            };
            if status != OK {
                return Err(Error {
                    status,
                    transferred: total,
                    message: "truncated frame or read failure",
                });
            }
            if moved == 0 || moved > bytes.len() - total {
                return Err(error(INTERNAL_ERROR, "invalid native read count"));
            }
            total += moved;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct FrameTransport {
    endpoint: String,
    timeout: Duration,
    deadline: Option<Instant>,
    cancellation: Option<Cancellation>,
    limit: usize,
    server: Option<ServerExpectation>,
}
impl FrameTransport {
    pub fn new(endpoint: impl Into<String>, timeout: Duration) -> Result<Self, Error> {
        let endpoint = endpoint.into();
        if endpoint.is_empty()
            || endpoint.as_bytes().contains(&0)
            || timeout.as_millis() > u32::MAX as u128
        {
            return Err(error(INVALID_ARGUMENT, "invalid endpoint or timeout"));
        }
        Ok(Self {
            endpoint,
            timeout,
            deadline: None,
            cancellation: None,
            limit: 1024 * 1024,
            server: None,
        })
    }
    pub fn with_server_expectation(mut self, server: ServerExpectation) -> Result<Self, Error> {
        if ![1, 2].contains(&server.principal_kind)
            || server.principal.is_empty()
            || server.program.is_empty()
            || server.principal.as_bytes().contains(&0)
            || server.program.as_bytes().contains(&0)
        {
            return Err(error(INVALID_ARGUMENT, "invalid server expectation"));
        }
        self.server = Some(server);
        Ok(self)
    }
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }
    pub fn with_cancellation(mut self, signal: Cancellation) -> Self {
        self.cancellation = Some(signal);
        self
    }
    pub fn with_limit(mut self, limit: usize) -> Result<Self, Error> {
        if limit == 0 || limit > MAX_FRAME {
            return Err(error(INVALID_ARGUMENT, "frame limit must be 1..2097152"));
        }
        self.limit = limit;
        Ok(self)
    }
    fn open(&self) -> Result<Connection, Error> {
        version()?;
        let remaining = self
            .deadline
            .map(|d| d.saturating_duration_since(Instant::now()))
            .unwrap_or(self.timeout);
        if remaining.is_zero() {
            return Err(error(TIMEOUT, "call deadline expired"));
        }
        let millis = remaining
            .as_millis()
            .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0))
            .min(u32::MAX as u128) as u32;
        let signal = self
            .cancellation
            .as_ref()
            .map(|s| s.0 .0.as_ptr())
            .unwrap_or(ptr::null_mut());
        let mut raw = ptr::null_mut();
        // self borrows the Arc signal until open returns; native connection then
        // retains its independent shared cancellation state.
        let status = if let Some(server) = &self.server {
            let expected = NativeExpectation {
                struct_size: std::mem::size_of::<NativeExpectation>() as u32,
                version: 1,
                principal_kind: server.principal_kind,
                reserved: 0,
                principal: server.principal.as_ptr().cast(),
                principal_length: server.principal.len(),
                program: server.program.as_ptr().cast(),
                program_length: server.program.len(),
            };
            // All spans are borrowed through this synchronous open; native copies them.
            unsafe {
                oa_ipc_open_verified(
                    self.endpoint.as_ptr().cast(),
                    self.endpoint.len(),
                    millis,
                    signal,
                    &expected,
                    &mut raw,
                )
            }
        } else {
            unsafe {
                oa_ipc_open_cancelable(
                    self.endpoint.as_ptr().cast(),
                    self.endpoint.len(),
                    millis,
                    signal,
                    &mut raw,
                )
            }
        };
        if status != OK {
            return Err(error(status, "IPC open failed"));
        }
        Ok(Connection(NonNull::new(raw).ok_or_else(|| {
            error(INTERNAL_ERROR, "native null connection")
        })?))
    }
    fn send(&self, frame: &[u8]) -> Result<Connection, Error> {
        if frame.len() > self.limit {
            return Err(error(INVALID_ARGUMENT, "outbound frame too large"));
        }
        let mut bytes = Vec::with_capacity(frame.len() + 4);
        bytes.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        bytes.extend_from_slice(frame);
        let mut connection = self.open()?;
        connection.write(&bytes)?;
        Ok(connection)
    }
    pub fn exchange_frame(&self, frame: &[u8]) -> Result<Vec<u8>, Error> {
        let mut connection = self.send(frame)?;
        let mut header = [0u8; 4];
        connection.read(&mut header)?;
        let size = u32::from_be_bytes(header) as usize;
        if size > self.limit {
            return Err(error(INVALID_ARGUMENT, "response frame too large"));
        }
        let mut reply = vec![0; size];
        connection.read(&mut reply)?;
        Ok(reply)
    }
    pub fn write_frame(&self, frame: &[u8]) -> Result<(), Error> {
        let mut connection = self.send(frame)?;
        match connection.read(&mut [0]) {
            Err(e) if e.status == DISCONNECTED => Ok(()),
            Err(e) => Err(e),
            Ok(()) => Err(error(IO_ERROR, "unexpected one-way reply")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scopes_retain_server_evidence() {
        let server = ServerExpectation {
            principal_kind: 2,
            principal: "123".into(),
            program: "/installed/runtime".into(),
        };
        let transport = FrameTransport::new("unused", Duration::from_secs(1))
            .unwrap()
            .with_server_expectation(server.clone())
            .unwrap();
        let scoped = transport.clone().with_deadline(Instant::now());
        assert_eq!(scoped.server, Some(server.clone()));
        assert_eq!(
            transport.clone().with_deadline(Instant::now()).server,
            Some(server.clone())
        );
        assert_eq!(
            transport
                .with_cancellation(Cancellation::new().unwrap())
                .server,
            Some(server)
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn native_verified_server_refuses_before_payload() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;
        let uid = std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned();
        for wrong in [false, true] {
            let path = std::env::temp_dir().join(format!(
                "oa-rust-trust-{}-{}",
                std::process::id(),
                wrong
            ));
            let listener = UnixListener::bind(&path).unwrap();
            let worker = std::thread::spawn(move || {
                let (mut peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut header = [0u8; 4];
                if wrong {
                    let mut b = [0u8; 1];
                    assert_eq!(peer.read(&mut b).unwrap(), 0);
                } else {
                    peer.read_exact(&mut header).unwrap();
                    let mut b = vec![0u8; u32::from_be_bytes(header) as usize];
                    peer.read_exact(&mut b).unwrap();
                    peer.write_all(&header).unwrap();
                    peer.write_all(&b).unwrap();
                }
            });
            let expected = ServerExpectation {
                principal_kind: 2,
                principal: uid.clone(),
                program: if wrong {
                    "/untrusted/other".into()
                } else {
                    std::env::current_exe().unwrap().to_str().unwrap().into()
                },
            };
            let result = FrameTransport::new(path.to_str().unwrap(), Duration::from_secs(1))
                .unwrap()
                .with_server_expectation(expected)
                .unwrap()
                .exchange_frame(b"private");
            if wrong {
                assert_eq!(result.unwrap_err().status, UNTRUSTED);
            } else {
                assert_eq!(result.unwrap(), b"private");
            }
            worker.join().unwrap();
            std::fs::remove_file(path).unwrap();
        }
    }
    #[test]
    fn invalid_native_expectation_does_not_open() {
        let server = ServerExpectation {
            principal_kind: if cfg!(windows) { 1 } else { 2 },
            principal: "123".into(),
            program: "relative".into(),
        };
        let result = FrameTransport::new("unused", Duration::from_secs(1))
            .unwrap()
            .with_server_expectation(server)
            .unwrap()
            .exchange_frame(b"private");
        assert_eq!(result.unwrap_err().status, INVALID_ARGUMENT);
    }
    #[test]
    fn invalid_before_open() {
        assert!(FrameTransport::new("bad\0endpoint", Duration::from_secs(1)).is_err());
        let t = FrameTransport::new("unused", Duration::ZERO).unwrap();
        assert_eq!(t.exchange_frame(b"x").unwrap_err().status, TIMEOUT);
        assert_eq!(
            t.with_limit(1)
                .unwrap()
                .exchange_frame(b"xx")
                .unwrap_err()
                .status,
            INVALID_ARGUMENT
        );
    }
    #[test]
    fn cancelled_before_open() {
        let signal = Cancellation::new().unwrap();
        signal.signal();
        let t = FrameTransport::new("unused", Duration::from_secs(1))
            .unwrap()
            .with_cancellation(signal);
        assert_eq!(t.exchange_frame(b"x").unwrap_err().status, CANCELLED);
    }
}

// All generated service protocols share this transport implementation.
impl abstraction_frame::FrameTransport for FrameTransport {
    type Error = Error;
    fn write_frame(&self, frame: &[u8]) -> Result<(), Self::Error> {
        FrameTransport::write_frame(self, frame)
    }
    fn exchange_frame(&self, frame: &[u8]) -> Result<Vec<u8>, Self::Error> {
        FrameTransport::exchange_frame(self, frame)
    }
}
