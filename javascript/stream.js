// IPC-F1 on caller-owned byte callbacks. No endpoint, activation or authentication
// is supplied here. The caller serializes frames and retires on any I/O error.
import {FrameError, Status} from './index.js';
import {ipcDefaultMaxFrame, ipcClientMaxFrame} from './js/abstraction/ipc/constants/index.mjs';

function limitOf(limit) {
  if (!Number.isInteger(limit) || limit < 1 || limit > ipcClientMaxFrame) throw new FrameError(Status.InvalidArgument, 'invalid frame limit');
  return limit;
}

/** read(size) returns at most size bytes; an empty Uint8Array is EOF. */
export async function readFrameFrom(read, limit = ipcDefaultMaxFrame) {
  limitOf(limit);
  async function exact(size, clean = false) {
    const held = new Uint8Array(size);
    let moved = 0;
    while (moved < size) {
      const part = await read(size - moved);
      if (!(part instanceof Uint8Array) || part.length > size - moved) throw new FrameError(Status.IoError, 'invalid stream read progress', moved);
      if (!part.length) {
        if (clean && !moved) return null;
        throw new FrameError(Status.IoError, 'truncated frame', moved);
      }
      held.set(part, moved);
      moved += part.length;
    }
    return held;
  }
  const header = await exact(4, true);
  if (header === null) return null;
  const size = new DataView(header.buffer).getUint32(0, false);
  if (size > limit) throw new FrameError(Status.InvalidArgument, 'frame exceeds limit', 4);
  return exact(size);
}

/** write(bytes) returns its accepted count. Complete body bounds precede all I/O. */
export async function writeFrameTo(write, frame, limit = ipcDefaultMaxFrame) {
  limitOf(limit);
  if (!(frame instanceof Uint8Array) || frame.length > limit) throw new FrameError(Status.InvalidArgument, 'frame must be bounded Uint8Array');
  const encoded = new Uint8Array(frame.length + 4);
  new DataView(encoded.buffer).setUint32(0, frame.length, false);
  encoded.set(frame, 4);
  for (let moved = 0; moved < encoded.length;) {
    const count = await write(encoded.subarray(moved));
    if (!Number.isInteger(count) || count <= 0 || count > encoded.length - moved) throw new FrameError(Status.IoError, 'invalid stream write progress', moved);
    moved += count;
  }
}

/** Adapt an ordinary async byte stream to the same bounded callback reader. */
export async function* framesFrom(input, limit = ipcDefaultMaxFrame) {
  const iterator = input[Symbol.asyncIterator]();
  let held = new Uint8Array(0), ended = false;
  const read = async (size) => {
    while (!held.length && !ended) {
      const next = await iterator.next();
      ended = next.done === true;
      if (!ended && !(next.value instanceof Uint8Array)) throw new FrameError(Status.InvalidArgument, 'stream must yield bytes');
      if (!ended && !next.value.length) throw new FrameError(Status.IoError, 'stream made no progress');
      held = ended ? new Uint8Array(0) : next.value;
    }
    const part = held.subarray(0, size);
    held = held.subarray(part.length);
    return part;
  };
  try {
    for (;;) {
      const frame = await readFrameFrom(read, limit);
      if (frame === null) return;
      yield frame;
    }
  } finally {
    if (iterator.return) await iterator.return();
  }
}
