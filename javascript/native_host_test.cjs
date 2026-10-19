'use strict';
// Run with a selected existing Node host: host native_host_test.cjs ADDON ROOT.
// ROOT contains own-identity/sentinel.txt and an existing other-identity folder.
// This checks actual exported native identity; it makes no OA/runtime calls.
const path = require('node:path');
const report = {pid: process.pid, ppid: process.ppid, execPath: process.execPath,
  versions: process.versions, phase: 'entry'};
(async () => {
try {
  const [addonPath, root] = process.argv.slice(2);
  if (process.argv.length !== 4 || !path.isAbsolute(addonPath) || !path.isAbsolute(root)) {
    throw new Error('absolute addon and owned fixture root required');
  }
  const addon = require(addonPath);
  report.phase = 'addon_loaded';
  if(typeof addon.activateRuntime!=='function')throw new Error('paired native activation export absent');
  let invalidRefused=false;
  try { addon.activateRuntime({principalKind:0},0,null); } catch { invalidRefused=true; }
  if(!invalidRefused)throw new Error('invalid activation reached native work');
  report.invalidActivationRefused=true;
  // All wrapper shape checks accept this expectation. The native C entry
  // rejects its relative program in ServerGuard::valid_input before selection.
  const expected={principalKind:process.platform==='win32'?1:2,principal:'fixture-user',program:'relative'};
  const signal=addon.createCancellation();
  let nativeRefusal;
  try { await addon.activateRuntime(expected,1000,signal); } catch(error) { nativeRefusal=error; }
  if(nativeRefusal?.status!==4||nativeRefusal?.transferred!==0)throw new Error('native activation validation mismatch');
  report.nativeActivationStatus=nativeRefusal.status;
  process.env.ABSTRACTION_IPC_NODE=addonPath;
  const {activateRuntime,Status}=await import(require('node:url').pathToFileURL(path.join(__dirname,'index.js')).href);
  let wrapperRefusal;
  try { await activateRuntime(expected,{timeout:1000}); } catch(error) { wrapperRefusal=error; }
  if(wrapperRefusal?.status!==Status.InvalidArgument)throw new Error('activation wrapper lost native typed refusal');
  report.wrapperActivationStatus=wrapperRefusal.status;
  const file = path.join(root, 'own-identity', 'sentinel.txt');
  report.within = addon.withinPath(file, path.join(root, 'own-identity'));
  report.outside = addon.withinPath(file, path.join(root, 'other-identity'));
  if (report.within !== true || report.outside !== false) throw new Error('native identity mismatch');
  report.phase = 'PASS_OWN_FILE_NATIVE_IDENTITY';
} catch (error) {
  report.error = {name: error.name, code: error.code ?? null, message: error.message};
  process.exitCode = 1;
}
process.stdout.write(JSON.stringify(report) + '\n');
})();
