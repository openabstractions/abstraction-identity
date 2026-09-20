import {createRequire} from 'node:module';
import {isAbsolute} from 'node:path';
const require = createRequire(import.meta.url);
export const Status = Object.freeze({Ok:0, Timeout:1, Disconnected:2, IoError:3,
  InvalidArgument:4, NoMemory:5, InternalError:6, Cancelled:7, Untrusted:8, ProofUnavailable:9});
let installed;
function native() {
  if (!installed) {
    const path = process.env.ABSTRACTION_IPC_NODE;
    if (path && !isAbsolute(path)) throw new TypeError('ABSTRACTION_IPC_NODE must be absolute');
    installed = require(path || './native/oa_ipc_node.node');
  }
  return installed;
}
export class FrameError extends Error {
  constructor(status, message, transferred=0) {
    super(message); this.status=status; this.transferred=transferred;
  }
}
/** Runs one native wait under an absolute deadline and an optional AbortSignal. */
async function waiting(deadline, cancellation, invoke) {
  if (cancellation?.aborted) throw new FrameError(Status.Cancelled,'waiting cancelled');
  if (deadline-performance.now()<=0) throw new FrameError(Status.Timeout,'waiting budget exhausted');
  const api=native();
  const signal=api.createCancellation();
  let stopped=null,timer;
  const abort=()=>{stopped??='cancel';api.cancel(signal);};
  const expire=()=>{
    const remaining=deadline-performance.now();
    if(remaining>0)timer=setTimeout(expire,Math.min(2147483647,Math.ceil(remaining)));
    else {stopped??='timeout';api.cancel(signal);}
  };
  expire();
  cancellation?.addEventListener('abort',abort,{once:true});
  // Abort can occur between the initial check and listener installation.
  if (cancellation?.aborted) abort();
  try {
    return await invoke(api,signal,Math.min(0xffffffff,Math.max(0,Math.floor(deadline-performance.now()))));
  } catch (error) {
    const status=stopped==='timeout'&&error.status===Status.Cancelled?Status.Timeout:error.status;
    throw new FrameError(status??Status.InternalError,error.message,error.transferred??0);
  } finally { clearTimeout(timer);cancellation?.removeEventListener('abort',abort); }
}
export function runtimeEndpoint() { return native().runtimeEndpoint(); }
/**
 * The installed runtime's identity from the shared native selector, the one the
 * Go, C++ and Python defaults use. It connects to nothing and starts nothing.
 * No installation, or an ambiguous one, rejects with Status.Untrusted; a platform
 * without the required facilities rejects with Status.ProofUnavailable.
 */
export function selectRuntime({timeout=5000, deadline=null, cancellation=null}={}) {
  if (!Number.isFinite(timeout)||timeout<0||timeout>0xffffffff||(deadline!==null&&!Number.isFinite(deadline)) ||
      (cancellation!==null && (typeof cancellation.addEventListener!=='function'||typeof cancellation.removeEventListener!=='function')))
    return Promise.reject(new TypeError('invalid selection waiting'));
  return waiting(deadline??performance.now()+timeout,cancellation,async (api,signal,ms)=>{
    const s=await api.selectRuntime(ms,signal);
    return Object.freeze({principalKind:s.principalKind,principal:s.principal,program:s.program});
  });
}
/** One native implementation; alternate connectors implement the same frame contract. */
export class NativeConnector {
  supports(scope, transport) { return (scope==='local'||scope==='remote') && transport==='oa-framed-local@1'; }
  connect(endpoint, options={}) { return new FrameTransport(endpoint, options); }
  runtimeEndpoint() { return runtimeEndpoint(); }
  selectRuntime(options={}) { return selectRuntime(options); }
}
export class FrameTransport {
  /**
   * sessions keeps verified connections for later calls in the shared library's
   * pool (FRAMING.md "Sessions"); ask only where the server answers or closes an
   * oversized header.
   */
  constructor(endpoint, {timeout=5000, deadline=null, cancellation=null, maxFrame=1048576, server=null, sessions=false}={}) {
    if (typeof endpoint!=='string'||!endpoint||endpoint.includes('\0') ||
        !Number.isFinite(timeout)||timeout<0||timeout>0xffffffff ||
        (deadline!==null&&!Number.isFinite(deadline)) ||
        !Number.isInteger(maxFrame)||maxFrame<1||maxFrame>2097152 ||
        (cancellation!==null && (typeof cancellation.addEventListener!=='function'||typeof cancellation.removeEventListener!=='function')))
      throw new TypeError('invalid frame binding');
    if(server!==null && (![1,2].includes(server.principalKind)||
        [server.principal,server.program].some(v=>typeof v!=='string'||!v||v.includes('\0'))))
      throw new TypeError('invalid server expectation');
    this.server=server===null?null:Object.freeze({principalKind:server.principalKind,principal:server.principal,program:server.program});
    if (typeof sessions!=='boolean') throw new TypeError('invalid frame binding');
    this.sessions=sessions;
    this.endpoint=endpoint; this.timeout=timeout; this.deadline=deadline;
    this.cancellation=cancellation; this.maxFrame=maxFrame;
    Object.freeze(this);
  }
  /** Independent view with one total budget; original reusable binding stays unchanged. */
  callScope() {
    return new FrameTransport(this.endpoint, {...this,
      deadline:this.deadline??performance.now()+this.timeout});
  }
  withWaiting({deadline=null, cancellation=null}={}) {
    return new FrameTransport(this.endpoint,{...this,deadline,cancellation});
  }
  #call(frame, reply) {
    if (!(frame instanceof Uint8Array)||frame.byteLength>this.maxFrame)
      return Promise.reject(new FrameError(Status.InvalidArgument,'frame must be bounded Uint8Array'));
    return waiting(this.deadline??performance.now()+this.timeout,this.cancellation,
      (api,signal,ms)=>api.call(this.endpoint,frame,ms,signal,this.maxFrame,reply,this.server,this.sessions));
  }
  exchangeFrame(frame) { return this.#call(frame,true); }
  writeFrame(frame) { return this.#call(frame,false); }
}
