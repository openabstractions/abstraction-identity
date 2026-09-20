import test from 'node:test';
import assert from 'node:assert/strict';
import {NativeConnector} from '../index.js';

test('native connector supports concrete execution placements through OA IPC', () => {
  const connector = new NativeConnector();
  assert.equal(connector.supports('local', 'oa-framed-local@1'), true);
  assert.equal(connector.supports('remote', 'oa-framed-local@1'), true);
  assert.equal(connector.supports('any', 'oa-framed-local@1'), false);
  assert.equal(connector.supports('remote', 'https'), false);
});
