import {isAbsolute} from 'node:path';
import {FrameError, Status} from './index.js';

let installed;
let active = 0;
const maxActive = 32;

async function native() {
  if (installed) return installed;
  const path = process.env.ABSTRACTION_IPC_LIBRARY;
  if (!path || !isAbsolute(path)) {
    throw new TypeError('ABSTRACTION_IPC_LIBRARY must be an absolute shared-library path');
  }
  const {dlopen} = await import('bun:ffi');
  installed = dlopen(path, {
    oa_ipc_cancellation_create: {args: ['ptr'], returns: 'i32'},
    oa_ipc_cancellation_signal: {args: ['ptr'], returns: 'void'},
    oa_ipc_cancellation_release: {args: ['ptr'], returns: 'void'},
  });
  return installed;
}

function validCancellation(cancellation) {
  return cancellation === null || (typeof cancellation?.addEventListener === 'function' &&
    typeof cancellation?.removeEventListener === 'function');
}

/** Bun binding for the shared C ABI. Blocking calls run in a worker. */
export class BunNativeConnector {
  supports(scope, transport) {
    return (scope === 'local' || scope === 'remote') && transport === 'oa-framed-local@1';
  }

  connect(endpoint, options = {}) { return new BunFrameTransport(endpoint, options); }

  runtimeEndpoint() {
    throw new FrameError(Status.ProofUnavailable,
      'Bun binding requires an explicit controlled runtime endpoint');
  }

  selectRuntime() {
    return Promise.reject(new FrameError(Status.ProofUnavailable,
      'Bun binding does not yet support installed runtime selection'));
  }
}

export class BunFrameTransport {
  constructor(endpoint, {timeout = 5000, deadline = null, cancellation = null,
    maxFrame = 1048576, server = null, sessions = false} = {}) {
    if (typeof endpoint !== 'string' || !endpoint || endpoint.includes('\0') ||
        !Number.isFinite(timeout) || timeout < 0 || timeout > 0xffffffff ||
        (deadline !== null && !Number.isFinite(deadline)) ||
        !Number.isInteger(maxFrame) || maxFrame < 1 || maxFrame > 2097152 ||
        !validCancellation(cancellation) || typeof sessions !== 'boolean') {
      throw new TypeError('invalid frame binding');
    }
    if (server !== null && (![1, 2].includes(server?.principalKind) ||
        [server?.principal, server?.program].some((value) => typeof value !== 'string' || !value || value.includes('\0')))) {
      throw new TypeError('invalid server expectation');
    }
    if (server !== null) {
      throw new FrameError(Status.ProofUnavailable,
        'Bun binding cannot enforce the configured server expectation');
    }
    this.endpoint = endpoint;
    this.timeout = timeout;
    this.deadline = deadline;
    this.cancellation = cancellation;
    this.maxFrame = maxFrame;
    this.sessions = sessions;
    this.server = null;
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
    const deadline = this.deadline ?? performance.now() + this.timeout;
    if (this.cancellation?.aborted) throw new FrameError(Status.Cancelled, 'waiting cancelled');
    if (deadline - performance.now() <= 0) throw new FrameError(Status.Timeout, 'waiting budget exhausted');

    if (active >= maxActive) throw new FrameError(Status.InternalError, 'native call capacity exhausted');
    active++;

    let api;
    try { api = await native(); } catch (error) { active--; throw error; }
    const pointer = new BigUint64Array(1);
    let created;
    try { created = api.symbols.oa_ipc_cancellation_create(pointer); } catch (error) { active--; throw error; }
    if (created !== Status.Ok) {
      active--;
      throw new FrameError(created, 'native cancellation allocation failed');
    }
    // Bun represents virtual-address pointers as safe JavaScript numbers.
    const cancellation = Number(pointer[0]);
    let stopped = null;
    let timer;
    const signal = (reason) => {
      stopped ??= reason;
      api.symbols.oa_ipc_cancellation_signal(cancellation);
    };
    const abort = () => signal('cancel');
    const expire = () => {
      const remaining = deadline - performance.now();
      if (remaining > 0) timer = setTimeout(expire, Math.min(2147483647, Math.ceil(remaining)));
      else signal('timeout');
    };
    expire();
    this.cancellation?.addEventListener('abort', abort, {once: true});
    if (this.cancellation?.aborted) abort();

    let worker;
    try {
      worker = new Worker(new URL('./bun-worker.js', import.meta.url), {type: 'module'});
      const result = await new Promise((resolve, reject) => {
        worker.onmessage = (event) => resolve(event.data);
        worker.onerror = reject;
        worker.postMessage({library: process.env.ABSTRACTION_IPC_LIBRARY, endpoint: this.endpoint,
          timeout: Math.min(0xffffffff, Math.max(0, Math.floor(deadline - performance.now()))),
          cancellation, frame, maxFrame: this.maxFrame, reply});
      });
      if (result.status !== Status.Ok) {
        const status = stopped === 'timeout' && result.status === Status.Cancelled ? Status.Timeout : result.status;
        throw new FrameError(status, result.message || 'native frame call failed', result.sent ?? 0);
      }
      return reply ? new Uint8Array(result.reply) : undefined;
    } finally {
      clearTimeout(timer);
      this.cancellation?.removeEventListener('abort', abort);
      worker?.terminate();
      api.symbols.oa_ipc_cancellation_release(cancellation);
      active--;
    }
  }

  exchangeFrame(frame) { return this.#call(frame, true); }
  writeFrame(frame) { return this.#call(frame, false); }
}
