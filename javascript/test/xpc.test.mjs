import assert from 'node:assert/strict';
import test from 'node:test';
import {FrameError, FrameTransport, Status} from '../index.js';

const service = process.env.OA_XPC_TEST_SERVICE;
const program = process.env.OA_XPC_TEST_PROGRAM;
const uid = process.env.OA_XPC_TEST_UID;
const enabled = Boolean(process.platform === 'darwin' && service && program && uid);
const server = enabled ? {principalKind: 2, principal: uid, program} : null;
const endpoint = enabled ? `xpc:${service}` : '';

function transport(options = {}) {
  return new FrameTransport(endpoint, {timeout: 5000, server, ...options});
}

test('Node uses the shared XPC transport for bounded frames', {skip: !enabled}, async () => {
  for (const payload of [
    new Uint8Array(),
    new TextEncoder().encode('node-xpc-echo'),
    Uint8Array.from([0, 10, 255]),
    new Uint8Array(128 * 1024).fill(0x78),
  ]) {
    assert.deepEqual(await transport().exchangeFrame(payload), Buffer.from(payload));
  }
});

test('Node completes one-way XPC delivery', {skip: !enabled}, async () => {
  assert.equal(await transport().writeFrame(new TextEncoder().encode('node-one-way')), undefined);
});

test('Node cancels and expires before dispatch', {skip: !enabled}, async () => {
  const cancelled = new AbortController();
  cancelled.abort();
  await assert.rejects(
    transport({cancellation: cancelled.signal}).exchangeFrame(new TextEncoder().encode('must-not-dispatch')),
    (error) => error instanceof FrameError && error.status === Status.Cancelled,
  );
  await assert.rejects(
    transport({deadline: performance.now() - 1}).exchangeFrame(new TextEncoder().encode('must-not-dispatch')),
    (error) => error instanceof FrameError && error.status === Status.Timeout,
  );
});

test('Node refuses the wrong server before sending a frame', {skip: !enabled}, async () => {
  const wrong = {...server, program: '/usr/bin/true'};
  await assert.rejects(
    transport({server: wrong}).exchangeFrame(new TextEncoder().encode('must-not-dispatch')),
    (error) => error instanceof FrameError &&
      [Status.Untrusted, Status.Disconnected].includes(error.status) && error.transferred === 0,
  );
});

test('Node reports an unregistered XPC service before transfer', {skip: !enabled}, async () => {
  await assert.rejects(
    new FrameTransport(`${endpoint}.missing`, {timeout: 1000, server})
      .exchangeFrame(new TextEncoder().encode('must-not-dispatch')),
    (error) => error instanceof FrameError &&
      error.status === Status.Disconnected && error.transferred === 0,
  );
});
