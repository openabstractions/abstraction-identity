import ctypes as C
import unittest
import threading
from types import SimpleNamespace
from unittest.mock import patch
from abstraction.ipc import Library, ServerExpectation, _Expectation, FrameError, PROOF_UNAVAILABLE, TIMEOUT, UNTRUSTED


class RuntimeTests(unittest.TestCase):
    def test_activation_holds_cancellation_and_releases_on_native_error(self):
        lib = Library.__new__(Library)
        token = SimpleNamespace(_library=lib, _lock=threading.Lock(), _closing=False,
                                _handle=C.c_void_p(17), _opening=0)
        token._condition=threading.Condition(token._lock)
        def features(): return 2
        def activate(expected, ms, signal, out):
            self.assertEqual(token._opening,1)
            self.assertEqual(signal.value,17)
            return UNTRUSTED
        lib._dll=SimpleNamespace(oa_ipc_features=features,oa_ipc_activate_runtime=activate)
        with self.assertRaises(FrameError) as caught:
            lib.activate_runtime(ServerExpectation(2,"1000","/fixture"),cancellation=token)
        self.assertEqual(caught.exception.status,UNTRUSTED)
        self.assertEqual(token._opening,0)

    def test_activation_native_entry_and_closed_outcomes(self):
        lib = Library.__new__(Library)
        seen = []
        def features(): return 2
        def activate(expected, ms, signal, out):
            value = expected._obj
            seen.append((value.principal_kind, value.principal, value.program, ms, signal))
            out._obj.value = 2
            return 0
        lib._dll = SimpleNamespace(oa_ipc_features=features, oa_ipc_activate_runtime=activate)
        expected = ServerExpectation(2, "1000", "/installed/runtime")
        with patch("abstraction.ipc.runtime.time.monotonic", return_value=10):
            self.assertEqual(lib.activate_runtime(expected, deadline=11), 2)
        self.assertEqual(seen, [(2, b"1000", b"/installed/runtime", 1000, None)])
        def invalid(expected, ms, signal, out): out._obj.value = 0; return 0
        lib._dll.oa_ipc_activate_runtime = invalid
        with self.assertRaises(FrameError) as caught: lib.activate_runtime(expected)
        self.assertEqual(caught.exception.status, 6)
        lib._dll = SimpleNamespace()
        with self.assertRaises(FrameError) as caught: lib.activate_runtime(expected)
        self.assertEqual(caught.exception.status, PROOF_UNAVAILABLE)

    def fixture(self, status=0):
        lib = Library.__new__(Library)
        value = _Expectation(C.sizeof(_Expectation), 1, 2, 0, b"1000", 4, b"/installed/runtime", 18)
        released = []
        def select(ms, signal, out):
            if status == 0: out._obj.value = 7
            return status
        def selected(handle): return C.pointer(value)
        def release(handle): released.append(handle.value)
        lib._dll = SimpleNamespace(oa_ipc_select_runtime=select, oa_ipc_selected_server=selected,
                                   oa_ipc_runtime_selection_release=release)
        return lib, value, released

    def test_copies_owned_native_snapshot_and_releases(self):
        lib, value, released = self.fixture()
        result = lib.select_runtime()
        value.program = b"/changed"
        self.assertEqual(result, ServerExpectation(2, "1000", "/installed/runtime"))
        self.assertEqual(released, [7])

    def test_refusal_and_missing_extension(self):
        lib, _, released = self.fixture(UNTRUSTED)
        with self.assertRaises(FrameError) as caught: lib.select_runtime()
        self.assertEqual(caught.exception.status, UNTRUSTED)
        self.assertEqual(released, [])
        lib._dll = SimpleNamespace()
        with self.assertRaises(FrameError) as caught: lib.select_runtime()
        self.assertEqual(caught.exception.status, PROOF_UNAVAILABLE)

    def test_deadline_after_selection_releases(self):
        lib, _, released = self.fixture()
        with patch("abstraction.ipc.runtime.time.monotonic", side_effect=[10, 11, 12, 20]):
            with self.assertRaises(FrameError) as caught: lib.select_runtime(timeout=5)
        self.assertEqual(caught.exception.status, TIMEOUT)
        self.assertEqual(released, [7])


if __name__ == "__main__": unittest.main()
