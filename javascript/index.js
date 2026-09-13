import {createRequire} from 'node:module';
import {isAbsolute} from 'node:path';
const require = createRequire(import.meta.url);
export const Status = Object.freeze({ok:0, timeout:1, disconnected:2, ioError:3,
  invalidArgument:4, noMemory:5, internalError:6, cancelled:7, untrusted:8, proofUnavailable:9});
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
export function runtimeEndpoint() { return native().runtimeEndpoint(); }
/** One native implementation; alternate connectors implement the same frame contract. */
export class NativeConnector {
  supports(scope, transport) { return scope==='local' && transport==='oa-framed-local@1'; }
  connect(endpoint, options={}) { return new FrameTransport(endpoint, options); }
  runtimeEndpoint() { return runtimeEndpoint(); }
}
export class FrameTransport {
  constructor(endpoint, {timeout=5000, deadline=null, cancellation=null, maxFrame=1048576, server=null}={}) {
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
  async #call(frame, reply) {
    if (!(frame instanceof Uint8Array)||frame.byteLength>this.maxFrame)
      throw new FrameError(Status.invalidArgument,'frame must be bounded Uint8Array');
    const deadline=this.deadline??performance.now()+this.timeout;
    const left=deadline-performance.now();
    if (this.cancellation?.aborted) throw new FrameError(Status.cancelled,'waiting cancelled');
    if (left<=0) throw new FrameError(Status.timeout,'waiting budget exhausted');
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
    this.cancellation?.addEventListener('abort',abort,{once:true});
    // Abort can occur between the initial check and listener installation.
    if (this.cancellation?.aborted) abort();
    try {
      return await api.call(this.endpoint,frame,Math.min(0xffffffff,Math.max(0,Math.floor(deadline-performance.now()))),signal,this.maxFrame,reply,this.server);
    } catch (error) {
      const status=stopped==='timeout'&&error.status===Status.cancelled?Status.timeout:error.status;
      throw new FrameError(status??Status.internalError,error.message,error.transferred??0);
    } finally { clearTimeout(timer);this.cancellation?.removeEventListener('abort',abort); }
  }
  exchangeFrame(frame) { return this.#call(frame,true); }
  writeFrame(frame) { return this.#call(frame,false); }
}
