// Waiting calls never hold the runtime's shared worker pool. OpenCode
// Desktop, 2026-11-01: the plugin's 30 s long-polls (the inventory watch per
// heading, the Messages header watch) held libuv's four pool threads, and the
// title-generation calls queued behind them reached the native library after
// their own 5 s deadline and failed before their exchange ("Error: open",
// status timeout). Each call now runs on a thread of its own, so its deadline
// counts from the moment it is made. Runs where the native addon is built.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import net from 'node:net';
import test from 'node:test';
import {addonPath, FrameTransport, Status} from '../index.js';

function addonBuilt() {
  try { createRequire(new URL('../index.js', import.meta.url)).resolve(addonPath()); return true; }
  catch { return false; }
}
const enabled = !globalThis.Bun && (process.platform === 'win32' || process.platform === 'linux') && addonBuilt();

test('a short call completes within its budget while six long-polls wait', {skip: !enabled, timeout: 20000}, async () => {
  const folder = mkdtempSync(join(tmpdir(), 'oa-node-waiting-'));
  const endpoint = process.platform === 'win32' ? `\\\\.\\pipe\\oa-node-waiting-${process.pid}-${process.hrtime.bigint()}` : join(folder, 'endpoint');
  const sockets = new Set();
  let held = 0;
  // A request whose first byte is 1 waits like a long-poll; any other is answered at once.
  const server = net.createServer((socket) => {
    sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => {});
    let bytes = Buffer.alloc(0);
    socket.on('data', (part) => {
      bytes = Buffer.concat([bytes, part]);
      if (bytes.length < 4) return;
      const size = bytes.readUInt32BE();
      if (bytes.length < 4 + size) return;
      if (size > 0 && bytes[4] === 1) { held++; return; }
      socket.end(bytes.subarray(0, 4 + size));
    });
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(endpoint, resolve); });
  const polls = new AbortController();
  try {
    const waiting = Array.from({length: 6}, () =>
      new FrameTransport(endpoint, {timeout: 15000, cancellation: polls.signal}).exchangeFrame(Uint8Array.of(1))
        .then(() => 'answered', (e) => e.status));
    // At least four long-polls, as many as libuv's pool holds, are connected
    // and waiting before the short call is made.
    const deadline = Date.now() + 5000;
    while (held < 4 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 10));
    assert(held >= 4, 'the long-polls are waiting');
    const started = performance.now();
    const answer = await new FrameTransport(endpoint, {timeout: 1500}).exchangeFrame(Uint8Array.of(2, 3))
      .catch((e) => assert.fail(`the short call failed at ${e.message} with status ${e.status} behind waiting calls`));
    assert.deepEqual(Buffer.from(answer), Buffer.from([2, 3]));
    assert(performance.now() - started < 1500, 'the short call finished within its own budget');
    while (held < 6 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 10));
    assert.equal(held, 6, 'every long-poll reached the server, none waited for a pool thread');
    polls.abort();
    assert.deepEqual(await Promise.all(waiting), Array(6).fill(Status.Cancelled), 'each long-poll ends by its cancellation');
  } finally {
    polls.abort();
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    rmSync(folder, {recursive: true, force: true});
  }
});
