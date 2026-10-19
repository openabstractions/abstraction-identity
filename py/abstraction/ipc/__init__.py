"""Shared native client transport. The operator supplies an installed ABI library."""
from dataclasses import dataclass
import ctypes as C
import math
import os
import sys
from pathlib import Path
import threading
import time

# The status codes, frame bounds and call budget come from identity.thrift
# (abstraction-ipc CONTRACT.md IPC-E1, IPC-F1, IPC-D1), generated beside this file.
from .constants import (
    IPC_OK as OK, IPC_TIMEOUT as TIMEOUT, IPC_DISCONNECTED as DISCONNECTED,
    IPC_IO_ERROR as IO_ERROR, IPC_INVALID_ARGUMENT as INVALID_ARGUMENT,
    IPC_NO_MEMORY as NO_MEMORY, IPC_INTERNAL_ERROR as INTERNAL_ERROR,
    IPC_CANCELLED as CANCELLED, IPC_UNTRUSTED as UNTRUSTED,
    IPC_PROOF_UNAVAILABLE as PROOF_UNAVAILABLE,
    IPC_DEFAULT_MAX_FRAME, IPC_CLIENT_MAX_FRAME, IPC_DEFAULT_CALL_BUDGET_MS)

ACTIVATION_NONE = 0
ACTIVATION_REQUEST_COMPLETED = 1
ACTIVATION_ENDPOINT_PRESENT = 2
ACTIVATION_UPGRADE_IN_PROGRESS = 3
ACTIVATION_REFUSED = 4
# Optional ABI-1 native status; generated service/wire statuses are unchanged.
OPEN_IO_ERROR = 10


class FrameError(OSError):
    def __init__(self, status, message, transferred=0):
        super().__init__(message)
        self.status = status
        self.transferred = transferred


@dataclass(frozen=True)
class ServerExpectation:
    """Independent server evidence; principal_kind is 1 SID or 2 POSIX uid."""
    principal_kind: int
    principal: str
    program: str

    def __post_init__(self):
        if self.principal_kind not in (1, 2) or any(
                not isinstance(v, str) or not v or "\0" in v for v in (self.principal, self.program)):
            raise ValueError("invalid server expectation")

    @classmethod
    def current_account(cls, program, *, library=None):
        """Pair an absolute program with this process's native principal.

        This supplies no connection or authority. The default native loader
        accepts only this client's bundle or explicit configuration, without
        reading an installation registration.
        """
        try:
            program = os.fspath(program)
        except TypeError as error:
            raise ValueError("server program must be an absolute path") from error
        if not isinstance(program, str) or not os.path.isabs(program) or "\0" in program:
            raise ValueError("server program must be an absolute path")
        if library is None:
            library = Library(allow_installed=False)
        kind, principal = library.current_principal()
        return cls(kind, principal, os.path.normpath(program))


class _Expectation(C.Structure):
    _fields_ = [("struct_size", C.c_uint32), ("version", C.c_uint32),
                ("principal_kind", C.c_uint32), ("reserved", C.c_uint32),
                ("principal", C.c_char_p), ("principal_length", C.c_size_t),
                ("program", C.c_char_p), ("program_length", C.c_size_t)]


class Library:
    """Load one explicitly installed native library; no PATH or cwd search.
    Without arguments: the wheel's bundled library, ABSTRACTION_IPC_LIBRARY,
    ABSTRACTION_IPC_PREFIX, then the installed runtime's recorded ipc_library."""
    def __init__(self, path=None, *, prefix=None, allow_installed=True):
        if path is None:
            if prefix is None:
                from . import _native
                path = _native.bundled_library_path()
                if path is None:
                    path = os.environ.get("ABSTRACTION_IPC_LIBRARY")
                    if not path:
                        prefix = os.environ.get("ABSTRACTION_IPC_PREFIX")
                        if not prefix:
                            prefix = None
                            if allow_installed:
                                path = _native.installed_library_path()
            if prefix is not None:
                prefix = Path(prefix)
                if not prefix.is_absolute():
                    raise ValueError("IPC prefix must be absolute")
                relative = ("bin/abstraction_ipc.dll" if sys.platform == "win32" else
                            "lib/libabstraction_ipc.dylib" if sys.platform == "darwin" else
                            "lib/libabstraction_ipc.so")
                path = prefix / relative
        if path is None:
            if not allow_installed:
                raise ValueError("supply a bundled native client or configure ABSTRACTION_IPC_LIBRARY or ABSTRACTION_IPC_PREFIX")
            raise ValueError("install OpenAbstractions or configure ABSTRACTION_IPC_LIBRARY or ABSTRACTION_IPC_PREFIX")
        path = Path(path)
        if not path.is_absolute():
            raise ValueError("IPC library path must be absolute")
        self._dll = C.CDLL(str(path.resolve(strict=True)))
        specs = {
            "version": (C.c_uint32, []),
            "runtime_endpoint": (C.c_int32, [C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]),
            "cancellation_create": (C.c_int32, [C.POINTER(C.c_void_p)]),
            "cancellation_signal": (None, [C.c_void_p]),
            "cancellation_release": (None, [C.c_void_p]),
            "open_cancelable": (C.c_int32, [C.c_char_p, C.c_size_t, C.c_uint32, C.c_void_p, C.POINTER(C.c_void_p)]),
            "write": (C.c_int32, [C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]),
            "read": (C.c_int32, [C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]),
            "close": (None, [C.c_void_p]),
        }
        for name, (result, args) in specs.items():
            fn = getattr(self._dll, "oa_ipc_" + name)
            fn.restype, fn.argtypes = result, args
            setattr(self, "_" + name, fn)
        # Old ABI-1 libraries remain usable for unverified explicit bindings.
        self._open_verified = getattr(self._dll, "oa_ipc_open_verified", None)
        if self._open_verified is not None:
            self._open_verified.restype = C.c_int32
            self._open_verified.argtypes = [C.c_char_p,C.c_size_t,C.c_uint32,C.c_void_p,C.POINTER(_Expectation),C.POINTER(C.c_void_p)]
        self._current_principal = getattr(self._dll, "oa_ipc_current_principal", None)
        if self._current_principal is not None:
            self._current_principal.restype = C.c_int32
            self._current_principal.argtypes = [C.POINTER(C.c_uint32), C.c_void_p,
                                               C.c_size_t, C.POINTER(C.c_size_t)]
        # Session calls (listen/FRAMING.md "Sessions") are an additive ABI-1 extension.
        self._session_call = getattr(self._dll, "oa_ipc_session_call", None)
        self._features = getattr(self._dll, "oa_ipc_features", None)
        if self._features is not None:
            self._features.restype, self._features.argtypes = C.c_uint32, []
        if self._session_call is not None:
            self._session_call.restype = C.c_int32
            self._session_call.argtypes = [C.c_char_p, C.c_size_t, C.c_uint32, C.c_void_p, C.POINTER(_Expectation),
                                           C.c_char_p, C.c_size_t, C.c_uint32, C.c_uint32,
                                           C.POINTER(C.c_void_p), C.POINTER(C.c_size_t)]
            self._reply_data = self._dll.oa_ipc_reply_data
            self._reply_data.restype, self._reply_data.argtypes = C.c_void_p, [C.c_void_p, C.POINTER(C.c_size_t)]
            self._reply_release = self._dll.oa_ipc_reply_release
            self._reply_release.restype, self._reply_release.argtypes = None, [C.c_void_p]
        if self._version() != 1:
            raise RuntimeError("unsupported IPC ABI version")

    def cancellation(self):
        return Cancellation(self)

    def current_principal(self):
        """Read this process's principal through the optional shared ABI-1 query."""
        query = getattr(self, "_current_principal", None)
        if query is None:
            raise FrameError(PROOF_UNAVAILABLE, "native current-principal query unavailable")
        kind, required = C.c_uint32(), C.c_size_t()
        status = query(C.byref(kind), None, 0, C.byref(required))
        if status != OK:
            raise FrameError(status, "current process principal unavailable")
        expected_kind = kind.value
        if expected_kind not in (1, 2):
            raise FrameError(INTERNAL_ERROR, "invalid native principal kind")
        for _ in range(3):
            if not 1 < required.value <= 65536:
                raise FrameError(INTERNAL_ERROR, "invalid native principal size")
            buffer = C.create_string_buffer(required.value)
            status = query(C.byref(kind), buffer, len(buffer), C.byref(required))
            if status == INVALID_ARGUMENT and required.value > len(buffer):
                continue
            if status != OK:
                raise FrameError(status, "current process principal query failed")
            if (kind.value != expected_kind or not 1 < required.value <= len(buffer)
                    or buffer.raw[required.value-1] != 0
                    or b"\0" in buffer.raw[:required.value-1]):
                raise FrameError(INTERNAL_ERROR, "invalid native principal result")
            try:
                principal = buffer.raw[:required.value-1].decode("utf-8", errors="strict")
            except UnicodeError as error:
                raise FrameError(INTERNAL_ERROR, "invalid native principal encoding") from error
            return kind.value, principal
        raise FrameError(INVALID_ARGUMENT, "current process principal changed repeatedly")

    def select_runtime(self, *, timeout=IPC_DEFAULT_CALL_BUDGET_MS / 1000, deadline=None, cancellation=None):
        """Select independent installed-runtime trust through the shared C ABI."""
        from .runtime import select_runtime
        return select_runtime(self, timeout=timeout, deadline=deadline, cancellation=cancellation)

    def activate_runtime(self, expected, *, timeout=IPC_DEFAULT_CALL_BUDGET_MS / 1000, deadline=None, cancellation=None):
        """Request the selected runtime under the caller's existing budget."""
        from .runtime import activate_runtime
        return activate_runtime(self, expected, timeout=timeout, deadline=deadline, cancellation=cancellation)

    def runtime_endpoint(self):
        required = C.c_size_t()
        status = self._runtime_endpoint(None, 0, C.byref(required))
        for _ in range(3):
            if status != OK or not 1 < required.value <= 65536:
                raise FrameError(status if status != OK else INVALID_ARGUMENT, "runtime bootstrap unavailable or oversized")
            buffer = C.create_string_buffer(required.value)
            status = self._runtime_endpoint(buffer, len(buffer), C.byref(required))
            if status == INVALID_ARGUMENT and required.value > len(buffer):
                status = OK
                continue
            if status != OK:
                raise FrameError(status, "runtime bootstrap failed")
            if not 1 < required.value <= len(buffer) or buffer.raw[required.value-1] != 0:
                raise FrameError(INTERNAL_ERROR, "invalid native bootstrap length")
            return buffer.raw[:required.value-1].decode("utf-8", errors="strict")
        raise FrameError(INVALID_ARGUMENT, "runtime bootstrap changed repeatedly")


class Cancellation:
    """Monotonic native signal. close may wait for an in-progress open to finish."""
    def __init__(self, library):
        self._library = library
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._opening = 0
        self._closing = False
        self._signaled = False
        self._children = set()
        self._parent = None
        self._handle = C.c_void_p()
        status = library._cancellation_create(C.byref(self._handle))
        if status != OK:
            raise FrameError(status, "cannot create cancellation signal")

    def signal(self):
        with self._lock:
            self._signaled = True
            if self._handle.value:
                self._library._cancellation_signal(self._handle)
            for child in tuple(self._children):
                child.signal()

    def child(self):
        """A one-way linked signal: parent cancellation reaches this child.

        The child can cancel its own calls without changing the caller's token.
        Close the child when its scoped calls have drained.
        """
        child = Cancellation(self._library)
        with self._lock:
            if self._signaled or self._closing or not self._handle.value:
                child.signal()
            else:
                child._parent = self
                self._children.add(child)
        return child

    def close(self):
        parent = self._parent
        if parent is not None:
            with parent._lock:
                parent._children.discard(self)
                self._parent = None
        with self._condition:
            self._closing = True
            if parent is not None and self._handle.value:
                self._signaled = True
                self._library._cancellation_signal(self._handle)
            for child in tuple(self._children):
                child.signal()
            self._children.clear()
            while self._opening:
                self._condition.wait()
            if self._handle.value:
                self._library._cancellation_release(self._handle)
                self._handle = C.c_void_p()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class FrameTransport:
    """Framed calls on a fixed endpoint with bounded frames.

    deadline is an absolute time.monotonic() value shared across calls. Without
    it, each call receives timeout seconds. Cancellation stops waiting only.
    Each call opens a native connection unless sessions is true: then verified
    connections are kept for later calls by the shared library's session pool
    (listen/FRAMING.md "Sessions"). Ask for sessions only where the server
    answers or closes an oversized header.
    Explicit xpc: endpoints always use the shared framed ABI and currently
    establish a fresh authenticated session for each call.
    """
    def __init__(self, library, endpoint, *, timeout=IPC_DEFAULT_CALL_BUDGET_MS / 1000, deadline=None,
                 cancellation=None, max_frame=IPC_DEFAULT_MAX_FRAME, server=None, sessions=False):
        if not isinstance(endpoint, str) or not endpoint or "\0" in endpoint:
            raise ValueError("nonempty endpoint without NUL required")
        if not isinstance(max_frame, int) or not 1 <= max_frame <= IPC_CLIENT_MAX_FRAME:
            raise ValueError(f"frame limit must be 1..{IPC_CLIENT_MAX_FRAME}")
        if not math.isfinite(timeout) or timeout < 0 or timeout > 4294967:
            raise ValueError("invalid timeout")
        if deadline is not None and not math.isfinite(deadline):
            raise ValueError("invalid deadline")
        if cancellation is not None and cancellation._library is not library:
            raise ValueError("cancellation belongs to another library")
        if server is not None and not isinstance(server, ServerExpectation):
            raise ValueError("server must be a ServerExpectation")
        self.server, self.sessions = server, bool(sessions)
        self.library, self.endpoint = library, endpoint.encode("utf-8")
        self.timeout, self.deadline = timeout, deadline
        self.cancellation, self.max_frame = cancellation, max_frame

    def with_waiting(self, *, deadline=None, cancellation=None):
        """Replace waiting policy on this endpoint; omitted cancellation clears it.

        Without an explicit absolute deadline, each call receives timeout.
        The original transport, native library and frame limit are preserved.
        """
        return FrameTransport(
            self.library, self.endpoint.decode("utf-8"), timeout=self.timeout,
            deadline=deadline,
            cancellation=cancellation, max_frame=self.max_frame, server=self.server, sessions=self.sessions)

    def call_scope(self):
        """Return an independent transport sharing one composite-call deadline.

        Existing absolute deadlines and cancellation are retained. Custom frame
        transports used by composite clients implement this same method and
        enforce their waiting budget across all exchanges on the returned view.
        """
        deadline = self.deadline if self.deadline is not None else time.monotonic() + self.timeout
        return FrameTransport(self.library, self.endpoint.decode("utf-8"),
                              timeout=self.timeout, deadline=deadline,
                              cancellation=self.cancellation, max_frame=self.max_frame, server=self.server,
                              sessions=self.sessions)

    def _millis(self):
        seconds = self.timeout if self.deadline is None else self.deadline - time.monotonic()
        if seconds <= 0:
            raise FrameError(TIMEOUT, "call deadline expired")
        return min(4294967295, max(1, math.ceil(seconds * 1000)))

    def _expectation(self):
        principal, program = self.server.principal.encode("utf-8"), self.server.program.encode("utf-8")
        return _Expectation(C.sizeof(_Expectation), 1, self.server.principal_kind, 0,
                            principal, len(principal), program, len(program))

    def _session(self, frame, reply, single, report_open):
        millis = self._millis()
        token = self.cancellation
        if token is not None:
            with token._lock:
                if token._closing or not token._handle.value:
                    raise FrameError(CANCELLED, "cancellation signal closed")
                token._opening += 1
                signal = token._handle
        else:
            signal = None
        answer, sent = C.c_void_p(), C.c_size_t()
        try:
            expected = self._expectation() if self.server is not None else None
            status = self.library._session_call(
                self.endpoint, len(self.endpoint), millis, signal, C.byref(expected) if expected is not None else None,
                frame, len(frame), self.max_frame,
                (0 if reply else 1) | (2 if single else 0) | (4 if report_open else 0), C.byref(answer), C.byref(sent))
        finally:
            if token is not None:
                with token._lock:
                    token._opening -= 1
                    token._condition.notify_all()
        try:
            if status != OK:
                raise FrameError(status, "IPC open failed" if status == OPEN_IO_ERROR else
                                 "frame exchange failed; acceptance may be unknown",
                                 sent.value)
            if not reply:
                return None
            length = C.c_size_t()
            data = self.library._reply_data(answer, C.byref(length))
            return C.string_at(data, length.value) if length.value else b""
        finally:
            if answer.value:
                self.library._reply_release(answer)

    def _call(self, frame, reply):
        if not isinstance(frame, bytes) or len(frame) > self.max_frame:
            raise FrameError(INVALID_ARGUMENT, "frame must be bounded bytes")
        message_endpoint = self.endpoint.startswith(b"xpc:")
        features = getattr(self.library, "_features", None)
        available = features() if features is not None else 0
        if message_endpoint and not available & 1:
            raise FrameError(PROOF_UNAVAILABLE, "native message transport unavailable")
        single = not self.sessions and not message_endpoint
        if (getattr(self.library, "_session_call", None) is None or
                (single and not available & 4)):
            raise FrameError(PROOF_UNAVAILABLE, "native framed transport unavailable")
        return self._session(frame, reply, single, not message_endpoint and bool(available & 8))

    def exchange_frame(self, frame):
        return self._call(frame, True)

    def write_frame(self, frame):
        self._call(frame, False)
