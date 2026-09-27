import assert from 'node:assert/strict';
import test from 'node:test';
import {BunNativeConnector} from '../bun.js';
import {FrameError, Status} from '../index.js';

const expectation = {principalKind: 1, principal: 'fixture-user', program: '/fixture/runtime'};
const library = process.platform === 'win32' ? 'C:\\fixture\\libabstraction_ipc.dll' : '/fixture/libabstraction_ipc.so';

test('Bun rejects XPC without a server expectation before loading the native transport', () => {
  assert.throws(() => new BunNativeConnector().connect('xpc:org.openabstractions.test'),
    (error) => error instanceof FrameError && error.status === Status.ProofUnavailable);
});

test('Bun connector binds a server expectation and refuses a malformed one', () => {
  const connector = new BunNativeConnector();
  const transport = connector.connect('fixture-endpoint', {server: expectation});
  assert.deepEqual(transport.server, expectation);
  assert.ok(Object.isFrozen(transport.server));
  assert.deepEqual(transport.callScope().server, expectation);
  assert.deepEqual(connector.connect('xpc:org.openabstractions.test', {server: expectation}).server, expectation);
  assert.throws(() => connector.connect('fixture-endpoint', {server: {principalKind: 1}}), TypeError);
  assert.throws(() => connector.connect('fixture-endpoint', {server: {...expectation, principal: 'a\0b'}}), TypeError);
});

test('Bun connector requires an absolute shared-library path before any native use', async () => {
  const saved = process.env.ABSTRACTION_IPC_LIBRARY;
  try {
    delete process.env.ABSTRACTION_IPC_LIBRARY;
    const connector = new BunNativeConnector();
    assert.throws(() => connector.runtimeEndpoint(), TypeError);
    await assert.rejects(connector.selectRuntime(), TypeError);
    process.env.ABSTRACTION_IPC_LIBRARY = 'relative/library';
    assert.throws(() => connector.runtimeEndpoint(), TypeError);
    await assert.rejects(connector.connect('fixture-endpoint', {server: expectation}).exchangeFrame(new Uint8Array(1)), TypeError);
  } finally {
    if (saved === undefined) delete process.env.ABSTRACTION_IPC_LIBRARY; else process.env.ABSTRACTION_IPC_LIBRARY = saved;
  }
});

test('Bun connector reports the Bun runtime as unavailable outside Bun instead of skipping verification', async () => {
  const saved = process.env.ABSTRACTION_IPC_LIBRARY;
  try {
    process.env.ABSTRACTION_IPC_LIBRARY = library;
    const connector = new BunNativeConnector();
    const outsideBun = (error) => error instanceof FrameError && error.status === Status.ProofUnavailable &&
      /Bun runtime/.test(error.message);
    assert.throws(() => connector.runtimeEndpoint(), outsideBun);
    await assert.rejects(connector.selectRuntime(), outsideBun);
    await assert.rejects(connector.connect('fixture-endpoint', {server: expectation}).exchangeFrame(new Uint8Array(1)), outsideBun);
    await assert.rejects(connector.selectRuntime({timeout: -1}), TypeError);
  } finally {
    if (saved === undefined) delete process.env.ABSTRACTION_IPC_LIBRARY; else process.env.ABSTRACTION_IPC_LIBRARY = saved;
  }
});
