import {dlopen, toArrayBuffer} from 'bun:ffi';

self.onmessage = (event) => {
  const request = event.data;
  let library;
  let replyPointer = 0;
  try {
    library = dlopen(request.library, {
      oa_ipc_session_call: {args: ['ptr', 'u64', 'u32', 'ptr', 'ptr', 'ptr', 'u64', 'u32', 'u32', 'ptr', 'ptr'], returns: 'i32'},
      oa_ipc_reply_data: {args: ['ptr', 'ptr'], returns: 'ptr'},
      oa_ipc_reply_release: {args: ['ptr'], returns: 'void'},
    });
    const endpoint = new TextEncoder().encode(request.endpoint);
    const frame = new Uint8Array(request.frame);
    const reply = new BigUint64Array(1);
    const sent = new BigUint64Array(1);
    const status = library.symbols.oa_ipc_session_call(endpoint, BigInt(endpoint.byteLength), request.timeout,
      request.cancellation, 0, frame, BigInt(frame.byteLength), request.maxFrame,
      request.reply ? 0 : 1, reply, sent);
    replyPointer = Number(reply[0]);
    let bytes = null;
    if (status === 0 && request.reply) {
      const length = new BigUint64Array(1);
      const data = library.symbols.oa_ipc_reply_data(replyPointer, length);
      bytes = new Uint8Array(toArrayBuffer(data, 0, Number(length[0]))).slice();
    }
    self.postMessage({status, sent: Number(sent[0]), reply: bytes}, bytes ? [bytes.buffer] : []);
  } catch (error) {
    self.postMessage({status: 6, message: error instanceof Error ? error.message : String(error), sent: 0});
  } finally {
    if (replyPointer) library?.symbols.oa_ipc_reply_release(replyPointer);
    library?.close();
  }
};
