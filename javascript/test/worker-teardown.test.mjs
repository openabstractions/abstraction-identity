// A call in flight outlives its environment. Review, 2026-11-01: with calls
// on their own threads, a Worker terminated while four calls waited freed
// each call's thread-safe function under its running thread, and the
// process died (exit 139) when the server answered. The addon cancels a
// torn-down environment's calls and waits for their threads before Node
// frees anything, so the process lives through every round. The probe runs
// in a child process: a crash is its exit status, never this runner's.
// Runs where the native addon is built.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import net from 'node:net';
import {fileURLToPath} from 'node:url';
import {Worker} from 'node:worker_threads';
import test from 'node:test';
import {addonPath} from '../index.js';

const self = fileURLToPath(import.meta.url);
const index = new URL('../index.js', import.meta.url);

async function probe(rounds) {
  const endpoint = process.platform === 'win32' ? `\\\\.\\pipe\\oa-node-teardown-${process.pid}`
    : `${process.env.TMPDIR ?? '/tmp'}/oa-node-teardown-${process.pid}.sock`;
  const held = [];
  const server = net.createServer((socket) => {
    socket.on('error', () => {});
    let bytes = Buffer.alloc(0);
    socket.on('data', (part) => {
      bytes = Buffer.concat([bytes, part]);
      if (bytes.length >= 4 && bytes.length >= 4 + bytes.readUInt32BE()) held.push([socket, bytes]);
    });
  });
  await new Promise((resolve) => server.listen(endpoint, resolve));
  const code = `
const {FrameTransport} = await import(${JSON.stringify(index.href)});
const {parentPort, workerData} = await import('node:worker_threads');
for (let i = 0; i < 4; i++) new FrameTransport(workerData, {timeout: 15000}).exchangeFrame(Uint8Array.of(1)).catch(() => {});
parentPort.postMessage('started');
`;
  for (let round = 0; round < rounds; round++) {
    const worker = new Worker(code, {eval: true, workerData: endpoint, type: 'module'});
    await new Promise((resolve) => worker.once('message', resolve));
    const deadline = Date.now() + 5000;
    while (held.length < 4 && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
    if (held.length < 4) throw new Error(`round ${round}: ${held.length} of 4 calls reached the server`);
    await worker.terminate();
    // Every held call is answered after its environment is gone.
    for (const [socket, bytes] of held.splice(0)) socket.end(bytes);
    await new Promise((resolve) => setTimeout(resolve, 500));
    console.log(`round ${round} alive`);
  }
  await new Promise((resolve) => server.close(resolve));
  console.log('probe alive');
}

function addonBuilt() {
  try { createRequire(index).resolve(addonPath()); return true; }
  catch { return false; }
}
const enabled = !globalThis.Bun && (process.platform === 'win32' || process.platform === 'linux') && addonBuilt();

if (process.argv[2] === '--probe') {
  await probe(Number(process.argv[3]));
} else {
  test('terminating a Worker with calls in flight keeps the process alive, five rounds', {skip: !enabled, timeout: 60000}, () => {
    const result = spawnSync(process.execPath, [self, '--probe', '5'], {encoding: 'utf8', timeout: 50000, windowsHide: true});
    assert.equal(result.status, 0, `probe exited ${result.status} (${result.signal}):\n${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /round 4 alive\s+probe alive/);
  });
}
