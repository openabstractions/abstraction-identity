/**
 * Which platform package carries the client's native files, and what they are
 * called there. `@openabstractions/ipc` declares one optional dependency per
 * qualified platform; each carries the shared C ABI library and the Node addon
 * built on that platform at the runtime's version. A platform absent from this
 * table has no package: the connectors refuse it by name rather than loading a
 * native file nobody qualified.
 */
export const platformLibraries = Object.freeze({
  'win32-x64': 'abstraction_ipc.dll',
  'linux-x64': 'libabstraction_ipc.so',
  'darwin-x64': 'libabstraction_ipc.dylib',
  'darwin-arm64': 'libabstraction_ipc.dylib',
});

/** The fixed addon file name inside every platform package. */
export const addonFile = 'oa_ipc_node.node';

/** This process's platform identity, the key of the table above. */
export function platformIdentity() {
  return `${process.platform}-${process.arch}`;
}

/** The package name for a platform identity, qualified or not. */
export function platformPackage(identity) {
  return `@openabstractions/ipc-${identity}`;
}

/** The shared library file name a platform package carries, or null when none is published. */
export function platformLibrary(identity) {
  return Object.hasOwn(platformLibraries, identity) ? platformLibraries[identity] : null;
}

/**
 * The absolute path of one file inside this platform's package, or null when the
 * package is not installed. `resolve` is a createRequire(...).resolve bound to
 * the calling connector, so the package is found beside the caller's own copy.
 */
export function platformFile(resolve, identity, file) {
  try {
    return resolve(`${platformPackage(identity)}/${file}`);
  } catch {
    return null;
  }
}
