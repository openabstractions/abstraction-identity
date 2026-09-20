import assert from 'node:assert/strict';
import test from 'node:test';
import {BunNativeConnector} from '../bun.js';
import {FrameError, Status} from '../index.js';

const expectation = {principalKind: 1, principal: 'fixture-user', program: '/fixture/runtime'};

test('Bun connector explicitly refuses unavailable identity verification', () => {
  const connector = new BunNativeConnector();
  assert.throws(() => connector.connect('fixture-endpoint', {server: expectation}), (error) => {
    assert.ok(error instanceof FrameError);
    assert.equal(error.status, Status.ProofUnavailable);
    assert.match(error.message, /cannot enforce.*server expectation/);
    return true;
  });
  assert.throws(() => connector.connect('fixture-endpoint', {server: {principalKind: 1}}), TypeError);
});

test('Bun connector explicitly refuses unavailable installed selection', async () => {
  const connector = new BunNativeConnector();
  assert.throws(() => connector.runtimeEndpoint(), (error) =>
    error instanceof FrameError && error.status === Status.ProofUnavailable);
  await assert.rejects(connector.selectRuntime(), (error) =>
    error instanceof FrameError && error.status === Status.ProofUnavailable);
});
