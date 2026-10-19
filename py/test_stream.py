import io
import json
from pathlib import Path
import unittest

from abstraction.ipc import FrameError, INVALID_ARGUMENT, IO_ERROR
from abstraction.ipc.stream import read_frame_from, write_frame_to


class StreamTests(unittest.TestCase):
    def test_shared_vectors_fragmentation_and_consecutive_frames(self):
        vectors = json.loads((Path(__file__).parents[1] / "testdata/stream_frames.json").read_text())
        for vector in vectors:
            body, wire = bytes.fromhex(vector["body"]), bytes.fromhex(vector["wire"])
            output = bytearray()
            def short_write(part):
                output.extend(part[:2])
                return len(part[:2])
            write_frame_to(short_write, body)
            self.assertEqual(bytes(output), wire)
            source = io.BytesIO(wire + wire)
            short_read = lambda size: source.read(min(size, 1))
            self.assertEqual(read_frame_from(short_read), body)
            self.assertEqual(read_frame_from(short_read), body)
            self.assertIsNone(read_frame_from(short_read))

    def test_complete_limit_precedes_write_and_body_read(self):
        limit = 1 << 20
        output = io.BytesIO()
        write_frame_to(output.write, b"x" * limit)
        self.assertEqual(read_frame_from(io.BytesIO(output.getvalue()).read), b"x" * limit)
        writes = []
        with self.assertRaises(FrameError) as failure:
            write_frame_to(lambda part: writes.append(part), b"x" * (limit + 1))
        self.assertEqual((failure.exception.status, writes), (INVALID_ARGUMENT, []))
        source = io.BytesIO((limit + 1).to_bytes(4, "big") + b"must not read")
        with self.assertRaises(FrameError):
            read_frame_from(source.read)
        self.assertEqual(source.tell(), 4)

    def test_partial_and_zero_progress_never_restart_a_frame(self):
        for truncated in (b"\0", b"\0\0", b"\0\0\0", b"\0\0\0\2x"):
            with self.assertRaises(FrameError) as failure:
                read_frame_from(io.BytesIO(truncated).read)
            self.assertEqual(failure.exception.status, IO_ERROR)
        for bad in (0, -1, None, True, 100):
            calls = []
            with self.assertRaises(FrameError):
                write_frame_to(lambda part: calls.append(part) or bad, b"x")
            self.assertEqual(len(calls), 1)
        calls = []
        def failed_write(part):
            calls.append(bytes(part))
            if len(calls) == 1:
                return 2
            raise OSError("partial failure")
        with self.assertRaises(OSError):
            write_frame_to(failed_write, b"x")
        self.assertEqual([len(part) for part in calls], [5, 3])
        with self.assertRaises(FrameError):
            read_frame_from(lambda size: None)


if __name__ == "__main__":
    unittest.main()
