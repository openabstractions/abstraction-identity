import {createRequire} from 'node:module';
import {isAbsolute} from 'node:path';
import {FrameError, Status} from './index.js';
import {platformFile, platformIdentity, platformLibrary, platformPackage} from './platform.js';

let installed;
let active = 0;
const maxActive = 32;
const require = createRequire(import.meta.url);

/**
 * The shared C ABI library this connector opens, resolved before any native use:
 * `ABSTRACTION_IPC_LIBRARY` as a development override, then this platform's
 * package. A platform with no published package is refused by name.
 */
export function libraryPath() {
  const explicit = process.env.ABSTRACTION_IPC_LIBRARY;
  if (explicit) {
    if (!isAbsolute(explicit)) {
      throw new TypeError('ABSTRACTION_IPC_LIBRARY must be an absolute shared-library path');
    }
    return explicit;
  }
  const identity = platformIdentity();
  const file = platformLibrary(identity);
  if (file === null) {
    throw new FrameError(Status.ProofUnavailable,
      `@openabstractions/ipc publishes no native client for ${identity}`);
  }
  const resolved = platformFile((specifier) => require.resolve(specifier), identity, file);
  if (resolved === null) {
    throw new TypeError(`install ${platformPackage(identity)}, or set ABSTRACTION_IPC_LIBRARY ` +
      'to an absolute shared-library path');
  }
  return resolved;
}

/** The shared library's main-thread symbols; blocking entry points stay in the worker. */
function native() {
  if (installed) return installed;
  const path = libraryPath();
  let ffi;
  try { ffi = require('bun:ffi'); } catch {
    throw new FrameError(Status.ProofUnavailable, 'Bun binding requires the Bun runtime');
  }
  const api = ffi.dlopen(path, {
    oa_ipc_cancellation_create: {args: ['ptr'], returns: 'i32'},
    oa_ipc_cancellation_signal: {args: ['ptr'], returns: 'void'},
    oa_ipc_cancellation_release: {args: ['ptr'], returns: 'void'},
    oa_ipc_runtime_endpoint: {args: ['ptr', 'u64', 'ptr'], returns: 'i32'},
  });
  installed = {symbols: api.symbols, path};
  return installed;
}

function validCancellation(cancellation) {
  return cancellation === null || (typeof cancellation?.addEventListener === 'function' &&
    typeof cancellation?.removeEventListener === 'function');
}

function validExpectation(server) {
  return [1, 2].includes(server?.principalKind) &&
    [server?.principal, server?.program].every((value) => typeof value === 'string' && value && !value.includes('\0'));
}

function freezeExpectation(server) {
  return Object.freeze({principalKind: server.principalKind, principal: server.principal, program: server.program});
}

/**
 * One bounded native operation in a worker, with a shared cancellation object the
 * main thread signals on abort or deadline. The worker answers {status, ...}.
 */
async function bounded(deadline, cancellation, request) {
  if (cancellation?.aborted) throw new FrameError(Status.Cancelled, 'waiting cancelled');
  if (deadline - performance.now() <= 0) throw new FrameError(Status.Timeout, 'waiting budget exhausted');
  if (active >= maxActive) throw new FrameError(Status.InternalError, 'native call capacity exhausted');
  active++;
  let api;
  try { api = native(); } catch (error) { active--; throw error; }
  const pointer = new BigUint64Array(1);
  let created;
  try { created = api.symbols.oa_ipc_cancellation_create(pointer); } catch (error) { active--; throw error; }
  if (created !== Status.Ok) {
    active--;
    throw new FrameError(created, 'native cancellation allocation failed');
  }
  // Bun represents virtual-address pointers as safe JavaScript numbers.
  const nativeCancellation = Number(pointer[0]);
  let stopped = null;
  let timer;
  const signal = (reason) => {
    stopped ??= reason;
    api.symbols.oa_ipc_cancellation_signal(nativeCancellation);
  };
  const abort = () => signal('cancel');
  const expire = () => {
    const remaining = deadline - performance.now();
    if (remaining > 0) timer = setTimeout(expire, Math.min(2147483647, Math.ceil(remaining)));
    else signal('timeout');
  };
  expire();
  cancellation?.addEventListener('abort', abort, {once: true});
  if (cancellation?.aborted) abort();
  let worker;
  try {
    worker = new Worker(new URL('./bun-worker.js', import.meta.url), {type: 'module'});
    const result = await new Promise((resolve, reject) => {
      worker.onmessage = (event) => resolve(event.data);
      worker.onerror = reject;
      worker.postMessage({...request, library: api.path, cancellation: nativeCancellation,
        timeout: Math.min(0xffffffff, Math.max(0, Math.floor(deadline - performance.now())))});
    });
    if (result.status !== Status.Ok) {
      const status = stopped === 'timeout' && result.status === Status.Cancelled ? Status.Timeout : result.status;
      throw new FrameError(status, result.message || 'native operation failed', result.sent ?? 0);
    }
    return result;
  } finally {
    clearTimeout(timer);
    cancellation?.removeEventListener('abort', abort);
    worker?.terminate();
    api.symbols.oa_ipc_cancellation_release(nativeCancellation);
    active--;
  }
}

/** Bun binding for the shared C ABI. Blocking calls run in a worker. */
export class BunNativeConnector {
  supports(scope, transport) {
    return (scope === 'local' || scope === 'remote') && transport === 'oa-framed-local@1';
  }

  connect(endpoint, options = {}) { return new BunFrameTransport(endpoint, options); }

  /**
   * The installed runtime's endpoint from the shared library's bootstrap query.
   * It connects to nothing and starts nothing.
   */
  runtimeEndpoint() {
    const api = native();
    const required = new BigUint64Array(1);
    let status = api.symbols.oa_ipc_runtime_endpoint(null, 0n, required);
    if (status !== Status.Ok) throw new FrameError(status, 'installed runtime endpoint unavailable');
    const size = Number(required[0]);
    if (size < 2 || size > 65536) throw new FrameError(Status.InternalError, 'invalid runtime endpoint size');
    const buffer = new Uint8Array(size);
    status = api.symbols.oa_ipc_runtime_endpoint(buffer, BigInt(size), required);
    if (status !== Status.Ok) throw new FrameError(status, 'installed runtime endpoint unavailable');
    const end = buffer.indexOf(0);
    if (end <= 0) throw new FrameError(Status.InternalError, 'invalid runtime endpoint');
    return new TextDecoder('utf-8', {fatal: true}).decode(buffer.subarray(0, end));
  }

  /**
   * The installed runtime's identity from the shared native selector, the one the
   * Go, C++, Python and Node defaults use. Missing or ambiguous installation
   * rejects with Status.Untrusted; unsupported facilities with Status.ProofUnavailable.
   */
  async selectRuntime({timeout = 5000, deadline = null, cancellation = null} = {}) {
    if (!Number.isFinite(timeout) || timeout < 0 || timeout > 0xffffffff ||
        (deadline !== null && !Number.isFinite(deadline)) || !validCancellation(cancellation)) {
      throw new TypeError('invalid selection waiting');
    }
    const result = await bounded(deadline ?? performance.now() + timeout, cancellation, {op: 'select'});
    const server = {principalKind: result.principalKind, principal: result.principal, program: result.program};
    if (!validExpectation(server)) throw new FrameError(Status.InternalError, 'invalid native runtime identity');
    return freezeExpectation(server);
  }
}

export class BunFrameTransport {
  /**
   * A server expectation is enforced by the shared library on every call, before
   * any application byte is sent. XPC endpoints require one.
   */
  constructor(endpoint, {timeout = 5000, deadline = null, cancellation = null,
    maxFrame = 1048576, server = null, sessions = false} = {}) {
    if (typeof endpoint !== 'string' || !endpoint || endpoint.includes('\0') ||
        !Number.isFinite(timeout) || timeout < 0 || timeout > 0xffffffff ||
        (deadline !== null && !Number.isFinite(deadline)) ||
        !Number.isInteger(maxFrame) || maxFrame < 1 || maxFrame > 2097152 ||
        !validCancellation(cancellation) || typeof sessions !== 'boolean') {
      throw new TypeError('invalid frame binding');
    }
    if (server !== null && !validExpectation(server)) {
      throw new TypeError('invalid server expectation');
    }
    if (server === null && endpoint.startsWith('xpc:')) {
      throw new FrameError(Status.ProofUnavailable, 'XPC requires a server identity expectation');
    }
    this.endpoint = endpoint;
    this.timeout = timeout;
    this.deadline = deadline;
    this.cancellation = cancellation;
    this.maxFrame = maxFrame;
    this.sessions = sessions;
    this.server = server === null ? null : freezeExpectation(server);
    Object.freeze(this);
  }

  callScope() {
    return new BunFrameTransport(this.endpoint, {...this,
      deadline: this.deadline ?? performance.now() + this.timeout});
  }

  withWaiting({deadline = null, cancellation = null} = {}) {
    return new BunFrameTransport(this.endpoint, {...this, deadline, cancellation});
  }

  async #call(frame, reply) {
    if (!(frame instanceof Uint8Array) || frame.byteLength > this.maxFrame) {
      throw new FrameError(Status.InvalidArgument, 'frame must be bounded Uint8Array');
    }
    const result = await bounded(this.deadline ?? performance.now() + this.timeout, this.cancellation,
      {op: 'call', endpoint: this.endpoint, server: this.server, frame, maxFrame: this.maxFrame, reply});
    return reply ? new Uint8Array(result.reply) : undefined;
  }

  exchangeFrame(frame) { return this.#call(frame, true); }
  writeFrame(frame) { return this.#call(frame, false); }
}
