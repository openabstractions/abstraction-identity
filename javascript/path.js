import {lstat, realpath, stat} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {dirname, isAbsolute} from 'node:path';
import {addonPath} from './index.js';

const require = createRequire(import.meta.url);
let windowsIdentity;

function sameDirectory(left, right) {
  return left.ino !== 0n && right.ino !== 0n && left.dev === right.dev && left.ino === right.ino;
}

/**
 * Whether the deepest existing folder above `path`, resolved through links,
 * is `folder` or one of its descendants by filesystem identity.
 *
 * Both arguments must be absolute paths. Filesystem errors reject the promise;
 * an unreadable path never counts as contained. The folder must already exist.
 */
export async function within(path, folder) {
  if (typeof path !== 'string' || typeof folder !== 'string'
      || !isAbsolute(path) || !isAbsolute(folder) || path.includes('\0') || folder.includes('\0')) {
    throw new TypeError('within requires absolute paths without NUL bytes');
  }

  if (process.platform === 'win32') {
    windowsIdentity ??= require(addonPath());
    if (typeof windowsIdentity.withinPath !== 'function') {
      const error = new Error('the Windows identity addon does not provide Within');
      error.code = 'ERR_PATH_IDENTITY_UNAVAILABLE';
      throw error;
    }
    return windowsIdentity.withinPath(path, folder);
  }

  const canonicalFolder = await realpath(folder);
  const folderIdentity = await stat(canonicalFolder, {bigint: true});
  if (!folderIdentity.isDirectory()) return false;

  let candidate = dirname(path);
  for (;;) {
    try {
      const canonical = await realpath(candidate);
      const identity = await stat(canonical, {bigint: true});
      if (!identity.isDirectory()) return false;
      if (sameDirectory(identity, folderIdentity)) return true;

      const parent = dirname(canonical);
      if (parent === canonical) return false;
      candidate = parent;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      // A dangling symlink has an entry but no resolved directory identity.
      // Refuse it rather than treating its lexical parent as proof of containment.
      const entry = await lstat(candidate, {bigint: true}).catch((lookupError) => {
        if (lookupError?.code === 'ENOENT') return null;
        throw lookupError;
      });
      if (entry?.isSymbolicLink()) throw error;

      const parent = dirname(candidate);
      if (parent === candidate) throw error;
      candidate = parent;
    }
  }
}
