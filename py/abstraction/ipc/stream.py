"""IPC-F1 framing on caller-owned read/write callbacks, without endpoint activation.

read(size) returns at most size bytes; b"" is EOF. write(bytes) returns the
accepted count. Callers serialize writes and retire their channel on any error;
transferred counts describe progress and never authorize replay.
"""
import struct

from . import FrameError, INVALID_ARGUMENT, IO_ERROR, IPC_DEFAULT_MAX_FRAME, IPC_CLIENT_MAX_FRAME


def _limit(limit):
    if type(limit) is not int or not 1 <= limit <= IPC_CLIENT_MAX_FRAME:
        raise FrameError(INVALID_ARGUMENT, "invalid frame limit")
    return limit


def read_frame_from(read, limit=IPC_DEFAULT_MAX_FRAME):
    """Read one bounded body, or None for clean EOF before its first header byte."""
    _limit(limit)

    def exact(size, clean=False):
        held = bytearray()
        while len(held) < size:
            part = read(size - len(held))
            if not isinstance(part, bytes) or len(part) > size - len(held):
                raise FrameError(IO_ERROR, "invalid stream read progress", len(held))
            if not part:
                if clean and not held:
                    return None
                raise FrameError(IO_ERROR, "truncated frame", len(held))
            held.extend(part)
        return bytes(held)

    header = exact(4, True)
    if header is None:
        return None
    size = struct.unpack("!I", header)[0]
    if size > limit:
        raise FrameError(INVALID_ARGUMENT, "frame exceeds limit", 4)
    return exact(size)


def write_frame_to(write, frame, limit=IPC_DEFAULT_MAX_FRAME):
    """Validate the complete body before writing, then write its header/body exactly."""
    _limit(limit)
    if not isinstance(frame, bytes) or len(frame) > limit:
        raise FrameError(INVALID_ARGUMENT, "frame must be bounded bytes")
    encoded, moved = struct.pack("!I", len(frame)) + frame, 0
    while moved < len(encoded):
        count = write(encoded[moved:])
        if type(count) is not int or not 0 < count <= len(encoded) - moved:
            raise FrameError(IO_ERROR, "invalid stream write progress", moved)
        moved += count
