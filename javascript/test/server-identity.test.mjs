// PT-5a through the C ABI: the server image is matched by file identity.
// A child process started from a user-owned copy of the Node executable serves
// one local endpoint, so that copy is the server program and can be hard-linked
// (the installed node.exe under Program Files cannot). Another name for that
// file keeps the check; a different file at a name the expectation uses fails
// it. Runs where the native addon is built (ABSTRACTION_IPC_NODE or a source
// build).
import assert from 'node:assert/strict';
import {execFileSync, spawn} from 'node:child_process';
import {chmodSync, copyFileSync, linkSync, mkdtempSync, renameSync, rmSync} from 'node:fs';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import net from 'node:net';
import test from 'node:test';
import {addonPath, FrameError, FrameTransport, Status} from '../index.js';
import {BunFrameTransport} from '../bun.js';

function addonBuilt() {
  try { createRequire(new URL('../index.js', import.meta.url)).resolve(addonPath()); return true; }
  catch { return false; }
}
const supported = process.platform === 'win32' || process.platform === 'linux';
const enabled = supported && (globalThis.Bun ? !!process.env.ABSTRACTION_IPC_LIBRARY : addonBuilt());
const Transport = globalThis.Bun ? BunFrameTransport : FrameTransport;

function principal() {
  if (process.platform !== 'win32') return {principalKind: 2, principal: String(process.getuid())};
  const line = execFileSync('whoami', ['/user', '/fo', 'csv', '/nh'], {encoding: 'utf8'}).trim();
  return {principalKind: 1, principal: line.split(',').at(-1).replaceAll('"', '')};
}

const echo = `const net = require('node:net');
net.createServer((s) => s.on('data', (b) => s.write(b)).on('error', () => {}))
  .listen(process.argv[1], () => process.stdout.write('ready\\n'));`;

async function startServer(program, endpoint) {
  const child = spawn(program, ['-e', echo, endpoint], {stdio: ['ignore', 'pipe', 'inherit'], windowsHide: true});
  await new Promise((done, fail) => {
    child.once('error', fail);
    child.once('exit', (code) => fail(new Error(`echo server exited ${code}`)));
    child.stdout.on('data', (b) => { if (String(b).includes('ready')) done(); });
  });
  return child;
}

function call(endpoint, program) {
  return new Transport(endpoint, {timeout: 2000, server: {...principal(), program}})
    .exchangeFrame(new TextEncoder().encode('private'));
}

test('native binding: renaming the server image keeps the check; another file at the name fails it', {skip: !enabled}, async () => {
  const folder = mkdtempSync(join(tmpdir(), 'oa-node-identity-'));
  const ext = process.platform === 'win32' ? '.exe' : '';
  const image = join(folder, `server${ext}`);
  const link = join(folder, `linked${ext}`), moved = join(folder, `moved${ext}`);
  const endpoint = process.platform === 'win32'
    ? `\\\\.\\pipe\\oa-node-identity-${process.pid}-${process.hrtime.bigint()}`
    : join(folder, 'endpoint');
  let child;
  try {
    copyFileSync(process.execPath, image);
    chmodSync(image, 0o755);
    child = await startServer(image, endpoint);
    linkSync(image, link);
    assert.deepEqual(Buffer.from(await call(endpoint, link)), Buffer.from('private'));
    renameSync(link, moved);
    assert.deepEqual(Buffer.from(await call(endpoint, moved)), Buffer.from('private'));
    copyFileSync(image, link);
    await assert.rejects(call(endpoint, link), (e) => e instanceof FrameError && e.status === Status.Untrusted);
  } finally {
    if (child && child.exitCode === null) {
      const gone = new Promise((done) => child.once('exit', done));
      child.kill();
      await gone;
    }
    rmSync(folder, {recursive: true, force: true});
  }
});

test('native binding: fresh opaque calls, session opt-in, limits, EOF and cancellation', {skip: !enabled}, async () => {
  const folder = mkdtempSync(join(tmpdir(), 'oa-node-frames-'));
  const endpoint = process.platform === 'win32' ? `\\\\.\\pipe\\oa-node-frames-${process.pid}-${process.hrtime.bigint()}` : join(folder,'endpoint');
  const headers=[], sockets=new Set(); let mode='echo', connections=0;
  const server=net.createServer(socket=>{
    connections++;
    sockets.add(socket);socket.on('close',()=>sockets.delete(socket));socket.on('error',()=>{});
    let bytes=Buffer.alloc(0),size=null;
    socket.on('data',part=>{
      bytes=Buffer.concat([bytes,part]);
      if(size===null&&bytes.length>=4){size=bytes.readUInt32BE();headers.push(size);if(size>2**21){socket.destroy();return;}}
      if(size===null||bytes.length<4+size)return;
      if(mode==='stall')return;
      if(mode==='close'){socket.destroy();return;}
      if(mode==='oneway'){socket.end();return;}
      if(mode==='oversized'){socket.end(Buffer.from([0,0,0,9]));return;}
      if(mode==='truncated'){socket.end(Buffer.from([0,0,0,3,1]));return;}
      socket.end(bytes.subarray(0,4+size));
    });
  });
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(endpoint,resolve);});
  try {
    await assert.rejects(new Transport(endpoint+'-absent',{timeout:1000}).exchangeFrame(new Uint8Array()),
      e=>e.status===Status.OpenIoError&&e.transferred===0);
    const transport=new Transport(endpoint,{timeout:2000});
    assert.deepEqual(Buffer.from(await transport.exchangeFrame(new Uint8Array())),Buffer.alloc(0));
    const binary=Uint8Array.of(0,255,128,0,1),pending=transport.exchangeFrame(binary);binary.fill(17);
    assert.deepEqual(Buffer.from(await pending),Buffer.from([0,255,128,0,1]));
    assert.deepEqual(headers,[0,5],'ordinary calls start fresh with their opaque frame lengths');
    assert.equal(connections,2,'each ordinary call owns a fresh connection');
    await new Transport(endpoint,{timeout:2000,sessions:true}).exchangeFrame(Uint8Array.of(2));
    assert(headers.some(n=>n>2**21),'sessions=true retains native negotiation');
    const count=headers.length;
    await assert.rejects(new Transport(endpoint,{maxFrame:1}).exchangeFrame(Uint8Array.of(1,2)),e=>e.status===Status.InvalidArgument);
    assert.equal(headers.length,count,'request limit refuses before I/O');
    mode='oneway';await transport.writeFrame(new Uint8Array());
    mode='oversized';await assert.rejects(new Transport(endpoint,{maxFrame:4}).exchangeFrame(Uint8Array.of(1)),e=>e.status===Status.InvalidArgument);
    mode='truncated';await assert.rejects(transport.exchangeFrame(Uint8Array.of(1)),e=>e.status===Status.Disconnected);
    mode='close';await assert.rejects(transport.exchangeFrame(new Uint8Array()),e=>e.status===Status.Disconnected&&e.transferred===0);
    mode='stall';const cancellation=new AbortController();
    const cancelled=new Transport(endpoint,{timeout:2000,cancellation:cancellation.signal}).exchangeFrame(Uint8Array.of(1));
    const timer=setTimeout(()=>cancellation.abort(),30);
    try {await assert.rejects(cancelled,e=>e.status===Status.Cancelled);} finally {clearTimeout(timer);}
    await assert.rejects(new Transport(endpoint,{timeout:30}).exchangeFrame(Uint8Array.of(1)),e=>e.status===Status.Timeout);
  } finally {
    for(const socket of sockets)socket.destroy();
    await new Promise(resolve=>server.close(resolve));
    rmSync(folder,{recursive:true,force:true});
  }
});
