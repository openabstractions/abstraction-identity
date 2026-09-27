"""Run against the isolated Go XPC echo fixture; no service is installed here."""
import os
import sys
import unittest

from abstraction.ipc import (
    CANCELLED, UNTRUSTED, DISCONNECTED,
    Cancellation, FrameError, FrameTransport, Library, ServerExpectation,
)


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("OA_XPC_TEST_SERVICE"),
                     "requires the isolated Darwin XPC echo fixture")
class XPCIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.library = Library(os.environ["OA_XPC_TEST_LIBRARY"])
        self.endpoint = "xpc:" + os.environ["OA_XPC_TEST_SERVICE"]
        self.server = ServerExpectation(2, str(os.geteuid()), os.environ["OA_XPC_TEST_PROGRAM"])

    def test_payloads_use_default_framed_routing(self):
        client = FrameTransport(self.library, self.endpoint, server=self.server)
        for payload in (b"", b"python-xpc-echo", b"\x00\n\xff", b"x" * (128 * 1024)):
            self.assertEqual(client.exchange_frame(payload), payload)

    def test_cancelled_request_sends_nothing(self):
        with Cancellation(self.library) as token:
            token.signal()
            client = FrameTransport(self.library, self.endpoint, server=self.server,
                                    cancellation=token)
            with self.assertRaises(FrameError) as caught:
                client.exchange_frame(b"must-not-dispatch")
            self.assertEqual(caught.exception.status, CANCELLED)

    def test_one_way_completion(self):
        client = FrameTransport(self.library, self.endpoint, server=self.server)
        self.assertIsNone(client.write_frame(b"one-way"))

    def test_wrong_program_is_refused(self):
        server = ServerExpectation(2, str(os.geteuid()), "/usr/bin/true")
        client = FrameTransport(self.library, self.endpoint, server=server)
        with self.assertRaises(FrameError) as caught:
            client.exchange_frame(b"must-not-dispatch")
        self.assertIn(caught.exception.status, (UNTRUSTED, DISCONNECTED))

    def test_unregistered_service_is_disconnected(self):
        client = FrameTransport(self.library, self.endpoint + ".missing", server=self.server)
        with self.assertRaises(FrameError) as caught:
            client.exchange_frame(b"must-not-dispatch")
        self.assertEqual(caught.exception.status, DISCONNECTED)
        self.assertEqual(caught.exception.transferred, 0)


if __name__ == "__main__":
    unittest.main()
