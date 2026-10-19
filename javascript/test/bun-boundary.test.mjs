import assert from 'node:assert/strict';
import test from 'node:test';
import {BunNativeConnector} from '../bun.js';
import {FrameError, Status} from '../index.js';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const expectation = {principalKind: 1, principal: 'fixture-user', program: '/fixture/runtime'};
const library = process.platform === 'win32' ? 'C:\\fixture\\libabstraction_ipc.dll' : '/fixture/libabstraction_ipc.so';

test('Bun worker refuses an old native feature set before loading the exchange entry point', () => {
  const source=readFileSync(new URL('../bun-worker.js',import.meta.url),'utf8').replace(/^import .*from 'bun:ffi';\s*/, '');
  for(const missing of [false,true]) {
    let answer,loads=0,closed=0;
    const context={TextDecoder,TextEncoder,Uint8Array,DataView,BigUint64Array,Int32Array,
      self:{postMessage:value=>{answer=value;}},
      dlopen:(_library,symbols)=>{loads++;assert.deepEqual(Object.keys(symbols),['oa_ipc_features']);if(missing)throw Error('old library');return {symbols:{oa_ipc_features:()=>0},close:()=>{closed++;}};}};
    vm.createContext(context);vm.runInContext(source,context);
    context.self.onmessage({data:{endpoint:'never-connect',library,sessions:false,frame:new Uint8Array(),reply:true}});
    assert.equal(answer.status,Status.ProofUnavailable);assert.equal(answer.sent,0);assert.equal(loads,1);
    assert.equal(closed,missing?0:1,'the feature-query handle closes before refusal');
  }
});

test('Bun opts into open proof only when advertised and preserves native zero-count failures', () => {
  const source=readFileSync(new URL('../bun-worker.js',import.meta.url),'utf8').replace(/^import .*from 'bun:ffi';\s*/, '');
  for(const [capabilities,sessions,want] of [[4,false,2],[4,true,0],[12,false,6],[12,true,4]]) {
    let answer,flags,closed=0;
    const context={TextDecoder,TextEncoder,Uint8Array,DataView,BigUint64Array,Int32Array,
      self:{postMessage:value=>{answer=value;}},
      dlopen:(_library,symbols)=>({close:()=>{closed++;},symbols:'oa_ipc_features' in symbols?{oa_ipc_features:()=>capabilities}:{
        oa_ipc_session_call:(...args)=>{flags=args[8];assert.equal(args[5],null);args[9][0]=0n;args[10][0]=0n;return 3;},
      }})};
    vm.createContext(context);vm.runInContext(source,context);
    context.self.onmessage({data:{endpoint:'never-connect',library,sessions,frame:new Uint8Array(),reply:true}});
    assert.equal(flags,want);assert.equal(answer.status,Status.IoError);assert.equal(answer.sent,0);assert.equal(closed,2);
  }
});

if(globalThis.Bun && process.env.OA_IPC_ACTIVATION_TEST_LIBRARY) {
  test('Bun reaches paired native activation validation before any installation selection', async()=>{
    const {dlopen,ptr}=await import('bun:ffi');
    const selected=process.env.OA_IPC_ACTIVATION_TEST_LIBRARY;
    const api=dlopen(selected,{
      oa_ipc_features:{args:[],returns:'u32'},
      oa_ipc_activate_runtime:{args:['ptr','u32','ptr','ptr'],returns:'i32'},
    });
    const principal=new TextEncoder().encode('fixture-user'),program=new TextEncoder().encode('relative');
    const expected=new Uint8Array(48),view=new DataView(expected.buffer);
    view.setUint32(0,48,true);view.setUint32(4,1,true);view.setUint32(8,process.platform==='win32'?1:2,true);
    view.setBigUint64(16,BigInt(ptr(principal)),true);view.setBigUint64(24,BigInt(principal.length),true);
    view.setBigUint64(32,BigInt(ptr(program)),true);view.setBigUint64(40,BigInt(program.length),true);
    const outcome=new Int32Array([123]);
    try {
      assert.ok(api.symbols.oa_ipc_features()&2);
      assert.equal(api.symbols.oa_ipc_activate_runtime(expected,100,0,outcome),Status.InvalidArgument);
      assert.equal(outcome[0],0);
    } finally {api.close();}
    const saved=process.env.ABSTRACTION_IPC_LIBRARY;
    try {
      process.env.ABSTRACTION_IPC_LIBRARY=selected;
      await assert.rejects(new BunNativeConnector().activateRuntime({principalKind:process.platform==='win32'?1:2,
        principal:'fixture-user',program:'relative'},{timeout:1000}),error=>error instanceof FrameError&&error.status===Status.InvalidArgument);
    } finally {
      if(saved===undefined)delete process.env.ABSTRACTION_IPC_LIBRARY;else process.env.ABSTRACTION_IPC_LIBRARY=saved;
    }
  });
}

test('Bun rejects XPC without a server expectation before loading the native transport', () => {
  assert.throws(() => new BunNativeConnector().connect('xpc:org.openabstractions.test'),
    (error) => error instanceof FrameError && error.status === Status.ProofUnavailable);
});

test('Bun connector binds a server expectation and refuses a malformed one', () => {
  const connector = new BunNativeConnector();
  const transport = connector.connect('fixture-endpoint', {server: expectation});
  assert.deepEqual(transport.server, expectation);
  assert.ok(Object.isFrozen(transport.server));
  assert.deepEqual(transport.callScope().server, expectation);
  assert.deepEqual(connector.connect('xpc:org.openabstractions.test', {server: expectation}).server, expectation);
  assert.throws(() => connector.connect('fixture-endpoint', {server: {principalKind: 1}}), TypeError);
  assert.throws(() => connector.connect('fixture-endpoint', {server: {...expectation, principal: 'a\0b'}}), TypeError);
});

test('Bun connector requires an absolute shared-library path before any native use', async () => {
  const saved = process.env.ABSTRACTION_IPC_LIBRARY;
  try {
    delete process.env.ABSTRACTION_IPC_LIBRARY;
    const connector = new BunNativeConnector();
    assert.throws(() => connector.runtimeEndpoint(), TypeError);
    await assert.rejects(connector.selectRuntime(), TypeError);
    process.env.ABSTRACTION_IPC_LIBRARY = 'relative/library';
    assert.throws(() => connector.runtimeEndpoint(), TypeError);
    await assert.rejects(connector.connect('fixture-endpoint', {server: expectation}).exchangeFrame(new Uint8Array(1)), TypeError);
  } finally {
    if (saved === undefined) delete process.env.ABSTRACTION_IPC_LIBRARY; else process.env.ABSTRACTION_IPC_LIBRARY = saved;
  }
});

test('Bun connector reports the Bun runtime as unavailable outside Bun instead of skipping verification', async () => {
  const saved = process.env.ABSTRACTION_IPC_LIBRARY;
  try {
    process.env.ABSTRACTION_IPC_LIBRARY = library;
    const connector = new BunNativeConnector();
    const outsideBun = (error) => error instanceof FrameError && error.status === Status.ProofUnavailable &&
      /Bun runtime/.test(error.message);
    assert.throws(() => connector.runtimeEndpoint(), outsideBun);
    await assert.rejects(connector.selectRuntime(), outsideBun);
    await assert.rejects(connector.activateRuntime(expectation), outsideBun);
    await assert.rejects(connector.activateRuntime({...expectation,program:''}), TypeError);
    await assert.rejects(connector.connect('fixture-endpoint', {server: expectation}).exchangeFrame(new Uint8Array(1)), outsideBun);
    await assert.rejects(connector.selectRuntime({timeout: -1}), TypeError);
  } finally {
    if (saved === undefined) delete process.env.ABSTRACTION_IPC_LIBRARY; else process.env.ABSTRACTION_IPC_LIBRARY = saved;
  }
});
