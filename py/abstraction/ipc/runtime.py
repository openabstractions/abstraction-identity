"""Installed runtime identity selected by the shared native implementation."""
import ctypes as C
import math
import time

from . import (ServerExpectation, _Expectation, FrameError, OK, TIMEOUT,
              CANCELLED, PROOF_UNAVAILABLE, INTERNAL_ERROR, IPC_DEFAULT_CALL_BUDGET_MS)


def activate_runtime(library, expected, *, timeout=IPC_DEFAULT_CALL_BUDGET_MS / 1000,
                     deadline=None, cancellation=None):
    """Use the optional native activation entry with independent server evidence."""
    if not isinstance(expected, ServerExpectation):
        raise ValueError("invalid server expectation")
    if not math.isfinite(timeout) or not 0 <= timeout <= 4294967:
        raise ValueError("invalid timeout")
    if deadline is not None and not math.isfinite(deadline):
        raise ValueError("invalid deadline")
    if cancellation is not None and cancellation._library is not library:
        raise ValueError("cancellation belongs to another library")
    end = time.monotonic() + timeout if deadline is None else deadline
    if end <= time.monotonic():
        raise FrameError(TIMEOUT, "runtime activation deadline expired")
    try:
        features = library._dll.oa_ipc_features
        activate = library._dll.oa_ipc_activate_runtime
    except AttributeError:
        raise FrameError(PROOF_UNAVAILABLE, "native runtime activation unavailable") from None
    features.restype, features.argtypes = C.c_uint32, []
    if not features() & 2:
        raise FrameError(PROOF_UNAVAILABLE, "native runtime activation unavailable")
    activate.restype, activate.argtypes = C.c_int32, [C.POINTER(_Expectation), C.c_uint32,
                                                   C.c_void_p, C.POINTER(C.c_int32)]
    principal, program = expected.principal.encode("utf-8"), expected.program.encode("utf-8")
    value = _Expectation(C.sizeof(_Expectation), 1, expected.principal_kind, 0,
                         principal, len(principal), program, len(program))
    token, signal = cancellation, None
    if token is not None:
        with token._lock:
            if token._closing or not token._handle.value:
                raise FrameError(CANCELLED, "cancellation signal closed")
            token._opening += 1
            signal = token._handle
    try:
        seconds = end - time.monotonic()
        if seconds <= 0:
            raise FrameError(TIMEOUT, "runtime activation deadline expired")
        outcome = C.c_int32()
        status = activate(C.byref(value), min(4294967295, max(1, math.ceil(seconds * 1000))),
                          signal, C.byref(outcome))
        if status != OK:
            raise FrameError(status, "installed runtime activation failed")
        if outcome.value not in (1, 2, 3, 4):
            raise FrameError(INTERNAL_ERROR, "invalid native activation outcome")
        if time.monotonic() >= end:
            raise FrameError(TIMEOUT, "runtime activation deadline expired")
        return outcome.value
    finally:
        if token is not None:
            with token._lock:
                token._opening -= 1
                token._condition.notify_all()


def select_runtime(library, *, timeout=IPC_DEFAULT_CALL_BUDGET_MS / 1000, deadline=None, cancellation=None):
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
