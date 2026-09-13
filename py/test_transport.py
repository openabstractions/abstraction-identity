import ctypes as C
import threading
import time
import unittest
from unittest.mock import patch
from abstraction.ipc import Library, Cancellation, FrameTransport, FrameError, CANCELLED, INVALID_ARGUMENT, IO_ERROR, ServerExpectation, UNTRUSTED, PROOF_UNAVAILABLE


class Native:
    def __init__(self):
        self.opened = threading.Event()
        self.signalled = threading.Event()
        self.release_count = 0
        self.in_open = False

    def _cancellation_create(self, out):
        out._obj.value = 7
        return 0

    def _cancellation_signal(self, handle):
        self.signalled.set()

    def _cancellation_release(self, handle):
        assert not self.in_open
        self.release_count += 1

    def _open_cancelable(self, endpoint, length, millis, token, out):
        self.in_open = True
        self.opened.set()
        assert self.signalled.wait(2)
        self.in_open = False
        return CANCELLED


class TransportTests(unittest.TestCase):
    def test_verified_expectation_is_owned_and_preserved(self):
        server=ServerExpectation(2,"123","/installed/runtime")
        seen=[]
        class Verified:
            def _open_verified(self, endpoint,length,millis,signal,expected,out):
                value=expected._obj
                seen.append((value.version,value.principal_kind,value.principal,value.program))
                return UNTRUSTED
            def _open_cancelable(self,*args):
                raise AssertionError("trust was dropped")
        original=FrameTransport(Verified(),"endpoint",server=server)
        for transport in (original,original.call_scope(),original.with_waiting()):
            self.assertIs(transport.server,server)
            with self.assertRaises(FrameError) as caught:transport.exchange_frame(b"private")
            self.assertEqual(caught.exception.status,UNTRUSTED)
        self.assertEqual(seen,[(1,2,b"123",b"/installed/runtime")]*3)
        with self.assertRaises(FrameError) as caught:
            FrameTransport(object(),"endpoint",server=server).exchange_frame(b"private")
        self.assertEqual(caught.exception.status,PROOF_UNAVAILABLE)

    def test_call_scope_preserves_explicit_deadline_and_cancellation(self):
        library = Native()
        token = Cancellation(library)
        with token, patch("abstraction.ipc.time.monotonic", return_value=100):
            original = FrameTransport(library, "endpoint", timeout=5, deadline=102,
                                      cancellation=token, max_frame=123)
            scoped = original.call_scope()
            self.assertIsNot(scoped, original)
            self.assertEqual(scoped.deadline, 102)
            self.assertEqual(scoped.endpoint, original.endpoint)
            self.assertEqual(scoped.max_frame, 123)
            self.assertIs(scoped.cancellation, token)
            token.signal()
            with self.assertRaises(FrameError) as caught: scoped.exchange_frame(b"x")
            self.assertEqual(caught.exception.status, CANCELLED)
            self.assertEqual(original.deadline, 102)

    def test_bootstrap_size_change_retries_with_bound(self):
        library = Library.__new__(Library)
        calls = []
        def endpoint(buffer, capacity, required):
            calls.append(capacity)
            required._obj.value = 2 if buffer is None else 9
            if buffer is None: return 0
            if capacity < 9: return INVALID_ARGUMENT
            C.memmove(buffer, b"endpoint\0", 9)
            return 0
        library._runtime_endpoint = endpoint
        self.assertEqual(library.runtime_endpoint(), "endpoint")
        self.assertEqual(calls, [0, 2, 9])
        def oversized(buffer, capacity, required):
            required._obj.value = 65537
            return 0
        library._runtime_endpoint = oversized
        with self.assertRaises(FrameError) as caught:
            library.runtime_endpoint()
        self.assertEqual(caught.exception.status, INVALID_ARGUMENT)

    def test_library_configuration_rejects_relative_search(self):
        with self.assertRaises(ValueError): Library("abstraction_ipc.dll")
        with self.assertRaises(ValueError): Library(prefix=".")

    def test_release_during_open_retains_signal_until_native_return(self):
        native = Native()
        token = Cancellation(native)
        failures = []
        def opening():
            try:
                FrameTransport(native, "endpoint", cancellation=token).exchange_frame(b"x")
            except FrameError as error:
                failures.append(error.status)
        worker = threading.Thread(target=opening)
        worker.start()
        self.assertTrue(native.opened.wait(1))
        closer = threading.Thread(target=token.close)
        closer.start()
        token.signal()
        worker.join(2); closer.join(2)
        self.assertFalse(worker.is_alive() or closer.is_alive())
        self.assertEqual(failures, [CANCELLED])
        self.assertEqual(native.release_count, 1)
        token.close()
        self.assertEqual(native.release_count, 1)

    def test_invalid_outbound_size_does_not_open(self):
        native = Native()
        with self.assertRaises(FrameError) as caught:
            FrameTransport(native, "endpoint", max_frame=2).exchange_frame(b"abc")
        self.assertEqual(caught.exception.status, INVALID_ARGUMENT)
        self.assertFalse(native.opened.is_set())

    def test_partial_write_failure_preserves_count_and_closes_once(self):
        class Partial:
            def __init__(self): self.closes = 0
            def _open_cancelable(self, ep, n, ms, token, out):
                out._obj.value = 1
                return 0
            def _write(self, h, buf, n, moved):
                moved._obj.value = 3
                return IO_ERROR
            def _close(self, h): self.closes += 1
        native = Partial()
        with self.assertRaises(FrameError) as caught:
            FrameTransport(native, "endpoint").exchange_frame(b"abc")
        self.assertEqual(caught.exception.transferred, 3)
        self.assertEqual(caught.exception.status, IO_ERROR)
        self.assertEqual(native.closes, 1)


if __name__ == "__main__":
    unittest.main()
