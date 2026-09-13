import ctypes as C
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from abstraction.ipc import Library, ServerExpectation, _Expectation, FrameError, PROOF_UNAVAILABLE, TIMEOUT, UNTRUSTED


class RuntimeTests(unittest.TestCase):
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
