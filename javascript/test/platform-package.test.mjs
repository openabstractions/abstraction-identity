// Where the connectors look for the native client, and in which order. A stub
// addon is not loadable, so these check the resolution decision: addonPath()
// and libraryPath() answer before anything is loaded. Each case runs in a child
// process under a temporary package tree, because module resolution is decided
// by where the installed copy of this package sits.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';

const source = dirname(dirname(fileURLToPath(import.meta.url)));
const identity = `${process.platform}-${process.arch}`;
const libraries = {
  'win32-x64': 'abstraction_ipc.dll',
  'linux-x64': 'libabstraction_ipc.so',
  'darwin-x64': 'libabstraction_ipc.dylib',
  'darwin-arm64': 'libabstraction_ipc.dylib',
};

const probe = `
const fake = process.env.OA_FAKE_PLATFORM;
if (fake) {
  const [platform, arch] = fake.split('-');
  Object.defineProperty(process, 'platform', {value: platform});
  Object.defineProperty(process, 'arch', {value: arch});
}
const {addonPath} = await import('@openabstractions/ipc');
const {libraryPath} = await import('@openabstractions/ipc/bun');
const attempt = (call) => {
  try { return {ok: true, value: call()}; }
  catch (error) { return {ok: false, name: error.constructor.name, status: error.status ?? null, message: error.message}; }
};
console.log(JSON.stringify({addon: attempt(addonPath), library: attempt(libraryPath)}));
`;

/** A package tree holding this package, and optionally a fake platform package. */
function tree(platformPackage) {
  const root = mkdtempSync(join(tmpdir(), 'oa-platform-'));
  const modules = join(root, 'node_modules', '@openabstractions');
  mkdirSync(modules, {recursive: true});
  cpSync(source, join(modules, 'ipc'), {recursive: true});
  rmSync(join(modules, 'ipc', 'test'), {recursive: true, force: true});
  if (platformPackage !== null) {
    const name = `ipc-${platformPackage}`;
    const directory = join(modules, name);
    mkdirSync(directory, {recursive: true});
    writeFileSync(join(directory, 'package.json'), JSON.stringify({
      name: `@openabstractions/${name}`, version: '0.0.0',
      os: [platformPackage.split('-')[0]], cpu: [platformPackage.split('-')[1]],
    }));
    writeFileSync(join(directory, 'oa_ipc_node.node'), 'not a loadable addon');
    writeFileSync(join(directory, libraries[platformPackage]), 'not a loadable library');
  }
  writeFileSync(join(root, 'probe.mjs'), probe);
  return root;
}

function resolution(root, environment = {}) {
  const inherited = {...process.env};
  delete inherited.ABSTRACTION_IPC_NODE;
  delete inherited.ABSTRACTION_IPC_LIBRARY;
  const output = execFileSync(process.execPath, [join(root, 'probe.mjs')],
    {cwd: root, env: {...inherited, ...environment}, encoding: 'utf8'});
  return JSON.parse(output);
}

test('an installed platform package supplies both native files without any environment override', {
  skip: libraries[identity] === undefined ? `no platform package is published for ${identity}` : false,
}, () => {
  const root = tree(identity);
  try {
    const resolved = resolution(root);
    assert.equal(resolved.addon.ok, true, resolved.addon.message);
    assert.equal(resolved.addon.value, join(root, 'node_modules', '@openabstractions', `ipc-${identity}`, 'oa_ipc_node.node'));
    assert.equal(resolved.library.ok, true, resolved.library.message);
    assert.equal(resolved.library.value,
      join(root, 'node_modules', '@openabstractions', `ipc-${identity}`, libraries[identity]));
  } finally { rmSync(root, {recursive: true, force: true}); }
});

test('the development overrides win over an installed platform package and must be absolute', {
  skip: libraries[identity] === undefined ? `no platform package is published for ${identity}` : false,
}, () => {
  const root = tree(identity);
  const addon = join(root, 'development.node');
  const library = join(root, `development-${libraries[identity]}`);
  try {
    const absolute = resolution(root, {ABSTRACTION_IPC_NODE: addon, ABSTRACTION_IPC_LIBRARY: library});
    assert.equal(absolute.addon.value, addon);
    assert.equal(absolute.library.value, library);
    const relative = resolution(root, {ABSTRACTION_IPC_NODE: 'development.node', ABSTRACTION_IPC_LIBRARY: 'development.so'});
    assert.equal(relative.addon.name, 'TypeError');
    assert.equal(relative.library.name, 'TypeError');
  } finally { rmSync(root, {recursive: true, force: true}); }
});

test('without the platform package the addon falls back to a source build and the library is refused by name', {
  skip: libraries[identity] === undefined ? `no platform package is published for ${identity}` : false,
}, () => {
  const root = tree(null);
  try {
    const resolved = resolution(root);
    assert.equal(resolved.addon.value, './native/oa_ipc_node.node');
    assert.equal(resolved.library.ok, false);
    assert.equal(resolved.library.name, 'TypeError');
    assert.match(resolved.library.message, new RegExp(`@openabstractions/ipc-${identity}`));
  } finally { rmSync(root, {recursive: true, force: true}); }
});

test('a platform with no published package is refused by name before any native load', () => {
  const root = tree(null);
  try {
    const resolved = resolution(root, {OA_FAKE_PLATFORM: 'linux-arm64'});
    for (const attempt of [resolved.addon, resolved.library]) {
      assert.equal(attempt.ok, false);
      assert.equal(attempt.name, 'FrameError');
      assert.equal(attempt.status, 9);
      assert.match(attempt.message, /linux-arm64/);
    }
  } finally { rmSync(root, {recursive: true, force: true}); }
});
