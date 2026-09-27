import {dlopen, ptr, read, toArrayBuffer} from 'bun:ffi';

const OK = 0, INTERNAL_ERROR = 6, PROOF_UNAVAILABLE = 9, FEATURE_XPC = 1;
const EXPECTATION_SIZE = 48;
const utf8 = new TextDecoder('utf-8', {fatal: true});

function optional(library, symbols) {
  try { return dlopen(library, symbols).symbols; } catch { return null; }
}

/* oa_ipc_server_expectation, version 1, on the 64-bit little-endian platforms
   Bun supports: four u32 fields, then pointer/length pairs for the principal and
   program byte spans. The spans stay referenced until the call returns. */
function expectation(server, keep) {
  const principal = new TextEncoder().encode(server.principal);
  const program = new TextEncoder().encode(server.program);
  const bytes = new Uint8Array(EXPECTATION_SIZE);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, EXPECTATION_SIZE, true);
  view.setUint32(4, 1, true);
  view.setUint32(8, server.principalKind, true);
  view.setUint32(12, 0, true);
  view.setBigUint64(16, BigInt(ptr(principal)), true);
  view.setBigUint64(24, BigInt(principal.byteLength), true);
  view.setBigUint64(32, BigInt(ptr(program)), true);
  view.setBigUint64(40, BigInt(program.byteLength), true);
  keep.push(principal, program, bytes);
  return bytes;
}

function call(request) {
  const keep = [];
  let library;
  let replyPointer = 0;
  try {
    if (request.endpoint.startsWith('xpc:')) {
      const features = optional(request.library, {oa_ipc_features: {args: [], returns: 'u32'}});
      if (!request.server || !features || (features.oa_ipc_features() & FEATURE_XPC) === 0) {
        return {status: PROOF_UNAVAILABLE, sent: 0,
          message: 'XPC endpoints require a server identity expectation and a library with XPC support'};
      }
    }
    library = dlopen(request.library, {
      oa_ipc_session_call: {args: ['ptr', 'u64', 'u32', 'ptr', 'ptr', 'ptr', 'u64', 'u32', 'u32', 'ptr', 'ptr'], returns: 'i32'},
      oa_ipc_reply_data: {args: ['ptr', 'ptr'], returns: 'ptr'},
      oa_ipc_reply_release: {args: ['ptr'], returns: 'void'},
    });
    const endpoint = new TextEncoder().encode(request.endpoint);
    const frame = new Uint8Array(request.frame);
    const server = request.server ? expectation(request.server, keep) : null;
    const reply = new BigUint64Array(1);
    const sent = new BigUint64Array(1);
    const status = library.symbols.oa_ipc_session_call(endpoint, BigInt(endpoint.byteLength), request.timeout,
      request.cancellation, server, frame, BigInt(frame.byteLength), request.maxFrame,
      request.reply ? 0 : 1, reply, sent);
    replyPointer = Number(reply[0]);
    let bytes = null;
    if (status === OK && request.reply) {
      const length = new BigUint64Array(1);
      const data = library.symbols.oa_ipc_reply_data(replyPointer, length);
      bytes = new Uint8Array(toArrayBuffer(data, 0, Number(length[0]))).slice();
    }
    keep.length = 0;
    return {status, sent: Number(sent[0]), reply: bytes};
  } finally {
    if (replyPointer) library?.symbols.oa_ipc_reply_release(replyPointer);
    library?.close();
  }
}

/* The installed runtime's identity, copied out of the native selection and
   released before answering. Validation matches the Node addon. */
function select(request) {
  const library = optional(request.library, {
    oa_ipc_select_runtime: {args: ['u32', 'ptr', 'ptr'], returns: 'i32'},
    oa_ipc_selected_server: {args: ['ptr'], returns: 'ptr'},
    oa_ipc_runtime_selection_release: {args: ['ptr'], returns: 'void'},
  });
  if (!library) return {status: PROOF_UNAVAILABLE, message: 'native runtime selection unavailable'};
  const handle = new BigUint64Array(1);
  const status = library.oa_ipc_select_runtime(request.timeout, request.cancellation, handle);
  if (status !== OK) return {status, message: 'installed runtime selection failed'};
  const selection = Number(handle[0]);
  if (!selection) return {status: INTERNAL_ERROR, message: 'native runtime selection absent'};
  try {
    const server = library.oa_ipc_selected_server(selection);
    if (!server) return {status: INTERNAL_ERROR, message: 'native runtime identity absent'};
    const principalLength = Number(read.u64(server, 24));
    const programLength = Number(read.u64(server, 40));
    const principal = read.ptr(server, 16);
    const program = read.ptr(server, 32);
    if (read.u32(server, 0) !== EXPECTATION_SIZE || read.u32(server, 4) !== 1 || read.u32(server, 12) !== 0 ||
        !principal || !program || !(principalLength > 0 && principalLength <= 65536) ||
        !(programLength > 0 && programLength <= 65536)) {
      return {status: INTERNAL_ERROR, message: 'invalid native runtime identity'};
    }
    return {status: OK, principalKind: read.u32(server, 8),
      principal: utf8.decode(new Uint8Array(toArrayBuffer(principal, 0, principalLength)).slice()),
      program: utf8.decode(new Uint8Array(toArrayBuffer(program, 0, programLength)).slice())};
  } finally {
    library.oa_ipc_runtime_selection_release(selection);
  }
}

self.onmessage = (event) => {
  const request = event.data;
  try {
    const result = request.op === 'select' ? select(request) : call(request);
    self.postMessage(result, result.reply ? [result.reply.buffer] : []);
  } catch (error) {
    self.postMessage({status: INTERNAL_ERROR, message: error instanceof Error ? error.message : String(error), sent: 0});
  }
};
