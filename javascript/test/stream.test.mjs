import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {FrameError, Status} from '../index.js';
import {readFrameFrom, writeFrameTo, framesFrom} from '@openabstractions/ipc/stream';

function reader(wire, fragment = 1) {
  let offset = 0;
  return (size) => { const part = wire.subarray(offset, offset + Math.min(size, fragment)); offset += part.length; return part; };
}

test('shared Go/Python/JS vectors preserve all bytes under fragmented I/O', async () => {
  const vectors = JSON.parse(readFileSync(new URL('../../testdata/stream_frames.json', import.meta.url)));
  for (const vector of vectors) {
    const body = Buffer.from(vector.body, 'hex'), wire = Buffer.from(vector.wire, 'hex'), output = [];
    await writeFrameTo((part) => { output.push(Buffer.from(part.subarray(0, 2))); return Math.min(part.length, 2); }, body);
    assert.deepEqual(Buffer.concat(output), wire);
    const read = reader(Buffer.concat([wire, wire]));
    assert.deepEqual(Buffer.from(await readFrameFrom(read)), body);
    assert.deepEqual(Buffer.from(await readFrameFrom(read)), body);
    assert.equal(await readFrameFrom(read), null);
    async function* chunks() { for (const byte of Buffer.concat([wire, wire])) yield Uint8Array.of(byte); }
    const frames = [];
    for await (const frame of framesFrom(chunks())) frames.push(Buffer.from(frame));
    assert.deepEqual(frames, [body, body]);
  }
});

test('complete body limit precedes any write or oversized body read', async () => {
  const limit = 1 << 20, body = Buffer.alloc(limit, 1), output = [];
  await writeFrameTo((part) => { output.push(Buffer.from(part)); return part.length; }, body);
  assert.deepEqual(Buffer.from(await readFrameFrom(reader(Buffer.concat(output), limit))), body);
  let writes = 0;
  await assert.rejects(writeFrameTo(() => { writes++; }, Buffer.alloc(limit + 1)), (e) => e.status === Status.InvalidArgument);
  assert.equal(writes, 0);
  let reads = 0;
  await assert.rejects(readFrameFrom(() => { reads++; return Uint8Array.of(0, 16, 0, 1); }), (e) => e.status === Status.InvalidArgument);
  assert.equal(reads, 1);
});

test('partial/zero progress errors terminate without restarting the frame', async () => {
  for (const wire of [Buffer.from([0]), Buffer.from([0, 0]), Buffer.from([0, 0, 0]), Buffer.from([0, 0, 0, 2, 1])]) {
    await assert.rejects(readFrameFrom(reader(wire)), (e) => e instanceof FrameError && e.status === Status.IoError);
  }
  for (const bad of [0, -1, undefined, true, 100]) {
    let calls = 0;
    await assert.rejects(writeFrameTo(() => { calls++; return bad; }, Uint8Array.of(1)), FrameError);
    assert.equal(calls, 1);
  }
  const sizes = [];
  await assert.rejects(writeFrameTo((part) => { sizes.push(part.length); if (sizes.length === 1) return 2; throw Error('partial failure'); }, Uint8Array.of(1)), /partial failure/);
  assert.deepEqual(sizes, [5, 3]);
  await assert.rejects(readFrameFrom(() => undefined), FrameError);
  async function* stalled() { yield new Uint8Array(0); }
  await assert.rejects(async () => {for await (const frame of framesFrom(stalled())) assert.fail(frame);}, FrameError);
});
