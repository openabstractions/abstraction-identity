"""Shared native client transport. The operator supplies an installed ABI library."""
from dataclasses import dataclass
import ctypes as C
import math
import os
import sys
from pathlib import Path
import struct
import threading
import time

OK, TIMEOUT, DISCONNECTED, IO_ERROR, INVALID_ARGUMENT, NO_MEMORY, INTERNAL_ERROR, CANCELLED = range(8)
UNTRUSTED, PROOF_UNAVAILABLE = 8, 9


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


class _Expectation(C.Structure):
    _fields_ = [("struct_size", C.c_uint32), ("version", C.c_uint32),
                ("principal_kind", C.c_uint32), ("reserved", C.c_uint32),
                ("principal", C.c_char_p), ("principal_length", C.c_size_t),
                ("program", C.c_char_p), ("program_length", C.c_size_t)]


class Library:
    """Load one explicitly installed native library; no PATH or cwd search."""
    def __init__(self, path=None, *, prefix=None):
        if path is None:
            if prefix is None:
                path = os.environ.get("ABSTRACTION_IPC_LIBRARY")
                if not path:
                    prefix = os.environ.get("ABSTRACTION_IPC_PREFIX")
            if prefix is not None:
                prefix = Path(prefix)
                if not prefix.is_absolute():
                    raise ValueError("IPC prefix must be absolute")
                relative = ("bin/abstraction_ipc.dll" if sys.platform == "win32" else
                            "lib/libabstraction_ipc.dylib" if sys.platform == "darwin" else
                            "lib/libabstraction_ipc.so")
                path = prefix / relative
        if path is None:
            raise ValueError("configure ABSTRACTION_IPC_LIBRARY or ABSTRACTION_IPC_PREFIX")
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
        if self._version() != 1:
            raise RuntimeError("unsupported IPC ABI version")

    def cancellation(self):
        return Cancellation(self)

    def select_runtime(self, *, timeout=5.0, deadline=None, cancellation=None):
        """Select independent installed-runtime trust through the shared C ABI."""
        from .runtime import select_runtime
        return select_runtime(self, timeout=timeout, deadline=deadline, cancellation=cancellation)

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
        self._handle = C.c_void_p()
        status = library._cancellation_create(C.byref(self._handle))
        if status != OK:
            raise FrameError(status, "cannot create cancellation signal")

    def signal(self):
        with self._lock:
            if self._handle.value:
                self._library._cancellation_signal(self._handle)

    def close(self):
        with self._condition:
            self._closing = True
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
    """One native connection per call, fixed endpoint and bounded frames.

    deadline is an absolute time.monotonic() value shared across calls. Without
    it, each call receives timeout seconds. Cancellation stops waiting only.
    """
    def __init__(self, library, endpoint, *, timeout=5.0, deadline=None,
                 cancellation=None, max_frame=1024 * 1024, server=None):
        if not isinstance(endpoint, str) or not endpoint or "\0" in endpoint:
            raise ValueError("nonempty endpoint without NUL required")
        if not isinstance(max_frame, int) or not 1 <= max_frame <= 2 * 1024 * 1024:
            raise ValueError("frame limit must be 1..2097152")
        if not math.isfinite(timeout) or timeout < 0 or timeout > 4294967:
            raise ValueError("invalid timeout")
        if deadline is not None and not math.isfinite(deadline):
            raise ValueError("invalid deadline")
        if cancellation is not None and cancellation._library is not library:
            raise ValueError("cancellation belongs to another library")
        if server is not None and not isinstance(server, ServerExpectation):
            raise ValueError("server must be a ServerExpectation")
        self.server = server
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
            cancellation=cancellation, max_frame=self.max_frame, server=self.server)

    def call_scope(self):
        """Return an independent transport sharing one composite-call deadline.

        Existing absolute deadlines and cancellation are retained. Custom frame
        transports used by composite clients implement this same method and
        enforce their waiting budget across all exchanges on the returned view.
        """
        deadline = self.deadline if self.deadline is not None else time.monotonic() + self.timeout
        return FrameTransport(self.library, self.endpoint.decode("utf-8"),
                              timeout=self.timeout, deadline=deadline,
                              cancellation=self.cancellation, max_frame=self.max_frame, server=self.server)

    def _open(self):
        seconds = self.timeout if self.deadline is None else self.deadline - time.monotonic()
        if seconds <= 0:
            raise FrameError(TIMEOUT, "call deadline expired")
        millis = min(4294967295, max(1, math.ceil(seconds * 1000)))
        handle = C.c_void_p()
        token = self.cancellation
        # Retain a cancellation handle during open; the native connection then
        # holds its signal independently. A signal must remain callable while
        # open blocks, so only release uses the active-open reference count.
        if token is not None:
            with token._lock:
                if token._closing or not token._handle.value:
                    raise FrameError(CANCELLED, "cancellation signal closed")
                token._opening += 1
                signal = token._handle
        else:
            signal = None
        try:
            if self.server is None:
                status = self.library._open_cancelable(self.endpoint, len(self.endpoint), millis, signal, C.byref(handle))
            else:
                verified = getattr(self.library, "_open_verified", None)
                if verified is None:
                    raise FrameError(PROOF_UNAVAILABLE, "native server proof unavailable")
                principal, program = self.server.principal.encode("utf-8"), self.server.program.encode("utf-8")
                expected = _Expectation(C.sizeof(_Expectation), 1, self.server.principal_kind, 0,
                                        principal, len(principal), program, len(program))
                status = verified(self.endpoint, len(self.endpoint), millis, signal, C.byref(expected), C.byref(handle))
        finally:
            if token is not None:
                with token._lock:
                    token._opening -= 1
                    token._condition.notify_all()
        if status != OK:
            raise FrameError(status, "IPC open failed")
        return handle

    def _write(self, handle, data):
        moved = C.c_size_t()
        buf = C.create_string_buffer(data)
        status = self.library._write(handle, buf, len(data), C.byref(moved))
        if status != OK:
            raise FrameError(status, "frame write failed; acceptance may be unknown", moved.value)
        if moved.value != len(data):
            raise FrameError(INTERNAL_ERROR, "native short successful write", moved.value)

    def _read(self, handle, size):
        data = bytearray()
        while len(data) < size:
            buf = C.create_string_buffer(size - len(data))
            moved = C.c_size_t()
            status = self.library._read(handle, buf, len(buf), C.byref(moved))
            if status != OK:
                raise FrameError(status, "truncated frame or read failure", len(data))
            if not 0 < moved.value <= len(buf):
                raise FrameError(INTERNAL_ERROR, "invalid native read count")
            data.extend(buf.raw[:moved.value])
        return bytes(data)

    def _call(self, frame, reply):
        if not isinstance(frame, bytes) or len(frame) > self.max_frame:
            raise FrameError(INVALID_ARGUMENT, "frame must be bounded bytes")
        handle = self._open()
        try:
            self._write(handle, struct.pack("!I", len(frame)) + frame)
            if reply:
                size = struct.unpack("!I", self._read(handle, 4))[0]
                if size > self.max_frame:
                    raise FrameError(INVALID_ARGUMENT, "response frame too large")
                return self._read(handle, size)
            buf, moved = C.create_string_buffer(1), C.c_size_t()
            status = self.library._read(handle, buf, 1, C.byref(moved))
            if status != DISCONNECTED:
                raise FrameError(status if status != OK else IO_ERROR, "unexpected one-way completion")
        finally:
            self.library._close(handle)

    def exchange_frame(self, frame):
        return self._call(frame, True)

    def write_frame(self, frame):
        self._call(frame, False)
