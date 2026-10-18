import assert from 'node:assert/strict';
import {mkdtemp, mkdir, rmdir, rm, stat, symlink, unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import test from 'node:test';
import {within} from '../path.js';

const sameDirectory = (left, right) => left.dev === right.dev && left.ino !== 0n && left.ino === right.ino;

test('within follows existing directory identity through links and rejects a distinct Unicode twin', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'oa-path-identity-'));
  const project = join(parent, 'link');
  const twin = join(parent, 'lin\u212a');
  const outside = join(parent, 'outside');
  const insideAlias = join(parent, 'inside-alias');
  const outsideAlias = join(project, 'outside-alias');
  let insideLinked = false;
  let outsideLinked = false;
  await mkdir(project);
  await mkdir(outside);
  try {
    try { await mkdir(twin); } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    const [projectIdentity, twinIdentity] = await Promise.all([stat(project, {bigint: true}), stat(twin, {bigint: true})]);
    assert.equal(await within(join(project, 'new', 'image.png'), project), true);
    assert.equal(await within(join(outside, 'image.png'), project), false);

    const aliases = sameDirectory(projectIdentity, twinIdentity);
    assert.equal(await within(join(twin, 'image.png'), project), aliases,
      'directory containment follows the filesystem identity, including when its names are Unicode twins');

    try {
      await symlink(project, insideAlias, 'junction');
      insideLinked = true;
      await symlink(outside, outsideAlias, 'junction');
      outsideLinked = true;
    } catch (error) {
      if (!['EPERM', 'EACCES', 'ENOTSUP'].includes(error?.code)) throw error;
    }
    if (insideLinked) assert.equal(await within(join(insideAlias, 'image.png'), project), true);
    if (outsideLinked) assert.equal(await within(join(outsideAlias, 'image.png'), project), false);
  } finally {
    if (outsideLinked) await unlink(outsideAlias).catch(() => rmdir(outsideAlias));
    if (insideLinked) await unlink(insideAlias).catch(() => rmdir(insideAlias));
    await rm(parent, {recursive: true, force: true});
  }
});

test('within requires absolute paths and propagates filesystem errors', async () => {
  await assert.rejects(within('relative/file', 'relative'), /absolute paths/);
  await assert.rejects(within(join(tmpdir(), 'missing-oa-identity-root'), join(tmpdir(), 'missing-oa-identity-folder')),
    {code: 'ENOENT'});
});

if (process.platform === 'win32') {
  test('within refuses paths ID-F1 marks off-local before native file access', async () => {
    const folder = tmpdir();
    const refused = {code: 'ERR_NOT_LOCAL_PATH'};
    await assert.rejects(within('\\\\192.0.2.1\\share\\image.png', folder), refused);
    await assert.rejects(within('\\\\.\\pipe\\oa-path-identity', folder), refused);
    await assert.rejects(within(join(folder, 'NUL.txt', 'image.png'), folder), refused);
    await assert.rejects(within(join(folder, 'COM¹:stream', 'image.png'), folder), refused);
  });
}
