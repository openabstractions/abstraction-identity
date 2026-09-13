"""Installed runtime identity selected by the shared native implementation."""
import ctypes as C
import math
import time

from . import (ServerExpectation, _Expectation, FrameError, OK, TIMEOUT,
              CANCELLED, PROOF_UNAVAILABLE, INTERNAL_ERROR)


def select_runtime(library, *, timeout=5.0, deadline=None, cancellation=None):
    """Copy an installed identity under one budget, then release native storage."""
    if not math.isfinite(timeout) or not 0 <= timeout <= 4294967:
        raise ValueError("invalid timeout")
    if deadline is not None and not math.isfinite(deadline):
        raise ValueError("invalid deadline")
    if cancellation is not None and cancellation._library is not library:
        raise ValueError("cancellation belongs to another library")
    end = time.monotonic() + timeout if deadline is None else deadline
    seconds = end - time.monotonic()
    if seconds <= 0:
        raise FrameError(TIMEOUT, "runtime selection deadline expired")
    try:
        select = library._dll.oa_ipc_select_runtime
        selected = library._dll.oa_ipc_selected_server
        release = library._dll.oa_ipc_runtime_selection_release
    except AttributeError:
        raise FrameError(PROOF_UNAVAILABLE, "native runtime selection unavailable") from None
    select.restype, select.argtypes = C.c_int32, [C.c_uint32, C.c_void_p, C.POINTER(C.c_void_p)]
    selected.restype, selected.argtypes = C.POINTER(_Expectation), [C.c_void_p]
    release.restype, release.argtypes = None, [C.c_void_p]
    token = cancellation
    signal = None
    if token is not None:
        with token._lock:
            if token._closing or not token._handle.value:
                raise FrameError(CANCELLED, "cancellation signal closed")
            token._opening += 1
            signal = token._handle
    handle = C.c_void_p()
    try:
        seconds = end - time.monotonic()
        if seconds <= 0:
            raise FrameError(TIMEOUT, "runtime selection deadline expired")
        status = select(min(4294967295, max(1, math.ceil(seconds * 1000))), signal, C.byref(handle))
        if status != OK:
            raise FrameError(status, "installed runtime selection failed")
        if not handle.value:
            raise FrameError(INTERNAL_ERROR, "native runtime selection absent")
        pointer = selected(handle)
        if not pointer:
            raise FrameError(INTERNAL_ERROR, "native runtime identity absent")
        value = pointer.contents
        if (value.struct_size != C.sizeof(_Expectation) or value.version != 1 or value.reserved
                or not value.principal or not value.program
                or not 0 < value.principal_length <= 65536 or not 0 < value.program_length <= 65536
                or len(value.principal) != value.principal_length or len(value.program) != value.program_length):
            raise FrameError(INTERNAL_ERROR, "invalid native runtime identity")
        result = ServerExpectation(value.principal_kind,
                                   value.principal.decode("utf-8"), value.program.decode("utf-8"))
        if time.monotonic() >= end:
            raise FrameError(TIMEOUT, "runtime selection deadline expired")
        return result
    finally:
        if handle.value:
            release(handle)
        if token is not None:
            with token._lock:
                token._opening -= 1
                token._condition.notify_all()
