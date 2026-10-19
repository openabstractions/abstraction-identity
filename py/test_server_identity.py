"""PT-5a through the installed C ABI: the server image is matched by file identity.

Runs when ABSTRACTION_IPC_LIBRARY or ABSTRACTION_IPC_PREFIX names an installed
shared library. This process serves one local endpoint; its own image (the
Python interpreter) is the server program. Another name for that file keeps the
check; a different file at a name the expectation uses fails it.
"""
import ctypes as C
import os
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

from abstraction.ipc import FrameError, FrameTransport, Library, ServerExpectation, UNTRUSTED, IO_ERROR, OPEN_IO_ERROR

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from personfolders import setUpModule, tearDownModule  # noqa: E402,F401 (per-user folders in a stand-in)

CONFIGURED = bool(os.environ.get("ABSTRACTION_IPC_LIBRARY") or os.environ.get("ABSTRACTION_IPC_PREFIX"))
SUPPORTED = sys.platform == "win32" or sys.platform.startswith("linux")


def own_image():
    if sys.platform == "win32":
        buf = C.create_unicode_buffer(32768)
        n = C.windll.kernel32.GetModuleFileNameW(None, buf, len(buf))
        assert 0 < n < len(buf)
        return buf.value
    return os.readlink("/proc/self/exe")


class Echo:
    """One connection: echo a frame back, or read until the client closes."""
    def __init__(self, *, listen=True):
        stamp = f"{os.getpid()}-{time.monotonic_ns()}"
        self.received = 0
        if sys.platform == "win32":
            k = C.WinDLL("kernel32", use_last_error=True)
            k.CreateNamedPipeW.restype = C.c_void_p
            k.CreateNamedPipeW.argtypes = [C.c_wchar_p, C.c_uint32, C.c_uint32, C.c_uint32, C.c_uint32,
                                           C.c_uint32, C.c_uint32, C.c_void_p]
            for name in ("ConnectNamedPipe", "ReadFile", "WriteFile", "DisconnectNamedPipe", "CloseHandle"):
                getattr(k, name).argtypes = None
            self.k = k
            self.endpoint = "\\\\.\\pipe\\oa-py-identity-" + stamp
            if not listen:
                return
            self.pipe = k.CreateNamedPipeW(self.endpoint, 3, 0, 1, 4096, 4096, 0, None)
            assert self.pipe not in (None, C.c_void_p(-1).value)
        else:
            self.endpoint = os.path.join(tempfile.gettempdir(), "oa-py-identity-" + stamp)
            if not listen:
                return
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(self.endpoint)
            self.sock.listen(1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        if sys.platform == "win32":
            k, pipe = self.k, C.c_void_p(self.pipe)
            if not k.ConnectNamedPipe(pipe, None) and C.get_last_error() != 535:
                return
            buf, n = C.create_string_buffer(65536), C.c_uint32()
            while k.ReadFile(pipe, buf, len(buf), C.byref(n), None) and n.value:
                self.received += n.value
                k.WriteFile(pipe, buf, n.value, C.byref(C.c_uint32()), None)
            k.DisconnectNamedPipe(pipe)
        else:
            try:
                peer, _ = self.sock.accept()
            except OSError:
                return
            with peer:
                while data := peer.recv(65536):
                    self.received += len(data)
                    peer.sendall(data)

    def finish(self):
        self.thread.join(5)
        if sys.platform == "win32":
            self.k.CloseHandle(C.c_void_p(self.pipe))
        else:
            self.sock.close()
            os.unlink(self.endpoint)
        return self.received


@unittest.skipUnless(CONFIGURED and SUPPORTED, "installed IPC library and Windows or Linux required")
class ServerImageIdentity(unittest.TestCase):
    def setUp(self):
        self.library = Library()
        self.kind, self.principal = self.library.current_principal()
        self.image = own_image()
        self.folder = tempfile.mkdtemp(prefix="oa-py-identity-")
        self.addCleanup(shutil.rmtree, self.folder, True)

    def test_native_single_exchange_empty_binary_and_unknown_empty_failure(self):
        expected = ServerExpectation(self.kind, self.principal, self.image)
        for payload in (b"", b"\0\xff\n"):
            peer = Echo()
            try:
                transport = FrameTransport(self.library, peer.endpoint, timeout=2, server=expected)
                self.assertEqual(transport.exchange_frame(payload), payload)
            finally:
                peer.finish()
        peer = Echo()
        try:
            with self.assertRaises(FrameError) as caught:
                FrameTransport(self.library, peer.endpoint, timeout=2, server=expected).write_frame(b"")
            self.assertEqual(caught.exception.status, IO_ERROR)
            self.assertEqual(caught.exception.transferred, 0)
            self.assertIn("acceptance may be unknown", str(caught.exception))
        finally:
            peer.finish()

    def test_missing_endpoint_projects_affirmative_native_open_failure(self):
        endpoint = Echo(listen=False).endpoint
        for payload in (b"", b"request"):
            with self.subTest(payload=payload), self.assertRaises(FrameError) as caught:
                FrameTransport(self.library, endpoint, timeout=2).exchange_frame(payload)
            self.assertEqual(caught.exception.status, OPEN_IO_ERROR)
            self.assertEqual(caught.exception.transferred, 0)

    def call(self, program):
        server = Echo()
        expected = ServerExpectation(self.kind, self.principal, program)
        try:
            return FrameTransport(self.library, server.endpoint, timeout=2.0, server=expected).exchange_frame(b"private")
        finally:
            server.finish()

    def test_rename_keeps_the_check_and_another_file_fails_it(self):
        suffix = ".exe" if sys.platform == "win32" else ""
        link = os.path.join(self.folder, "linked" + suffix)
        try:
            os.link(self.image, link)
        except OSError as error:
            self.skipTest(f"hard link beside the interpreter's volume unavailable: {error}")
        self.assertEqual(self.call(link), b"private")
        moved = os.path.join(self.folder, "moved" + suffix)
        os.rename(link, moved)
        self.assertEqual(self.call(moved), b"private")
        shutil.copyfile(self.image, link)
        with self.assertRaises(FrameError) as caught:
            self.call(link)
        self.assertEqual(caught.exception.status, UNTRUSTED)


if __name__ == "__main__":
    unittest.main()
