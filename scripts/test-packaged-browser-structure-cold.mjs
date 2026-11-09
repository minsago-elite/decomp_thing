import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { COLD_PROFILES, applyStructureProfile, makeChromeThrottlingCommands, summarizeColdSamples, runColdSamples } from './packaged-browser-structure-cold.mjs';

test('profiles configure CPU, RTT and asymmetric bandwidth; limits are profile specific', async () => {
  assert.equal(COLD_PROFILES.loopback.firstPageLimitMs, 500);
  assert.equal(COLD_PROFILES.constrained.firstPageLimitMs, 1000);
  assert.deepEqual(makeChromeThrottlingCommands(COLD_PROFILES.loopback), []);
  assert.deepEqual(makeChromeThrottlingCommands(COLD_PROFILES.constrained).map(x => x.params), [
    { rate: 4 }, { offline:false, latency:100, downloadThroughput:1_250_000, uploadThroughput:250_000, connectionType:'cellular3g' },
  ]);
  const calls = [];
  await applyStructureProfile({ call: async (...args) => calls.push(args) }, 'session', 'constrained');
  assert.deepEqual(calls, [
    ['Emulation.setCPUThrottlingRate', { rate: 4 }, 'session'],
    ['Network.emulateNetworkConditions', { offline:false, latency:100, downloadThroughput:1_250_000, uploadThroughput:250_000, connectionType:'cellular3g' }, 'session'],
  ]);
});

test('aggregation retains all twenty samples and uses nearest-rank p95 and median', () => {
  const samples = Array.from({length:20},(_,i)=>({status:'passed',firstPageMs:i === 19 ? 900 : i+1,rawFailedRequests:0}));
  const result = summarizeColdSamples(samples);
  assert.equal(result.sampleCount,20); assert.equal(result.nearestRankP95FirstPageMs,19);
  assert.equal(result.medianFirstPageMs,10.5); assert.equal(result.samples[19].firstPageMs,900);
});

test('failures and raw failed requests remain in outcomes and refuse pass', () => {
  const samples = Array.from({length:20},()=>({status:'passed',firstPageMs:1,rawFailedRequests:0}));
  samples[3] = {status:'failed',firstPageMs:1000,rawFailedRequests:0,error:'slow sample later failed a separate assertion'};
  samples[8] = {status:'passed',firstPageMs:900,rawFailedRequests:1};
  const r=summarizeColdSamples(samples); assert.equal(r.samples.length,20); assert.equal(r.failures,2); assert.equal(r.passed,false);
  assert.equal(r.timedSamples,20); assert.equal(r.nearestRankP95FirstPageMs,900);
  assert.throws(()=>summarizeColdSamples(samples.slice(1)),/exactly 20/);
});

test('runner refuses incorrect count', async () => {
  await assert.rejects(runColdSamples({driver:'unused',driverArgs:[],count:19}),/exactly 20/);
});

function fakeChild(code = 0, diagnostic = '') {
  const child = new EventEmitter();
  child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.pid = 12345;
  child.kill = () => true;
  queueMicrotask(() => { child.stdout.end('Report: /tmp/child/report.json\n'); child.stderr.end(diagnostic); child.emit('close', code); });
  return child;
}

test('runner executes twenty sequential fresh-child cold modes and retains the exact profile and evidence identity', async () => {
  let active = 0, maximumActive = 0, launches = 0;
  const result = await runColdSamples({ driver:'/repo/scripts/check-packaged-web-browser.mjs', driverArgs:['--archive','/pkg.zip'], profile:'loopback',
    spawnImpl: (_command, args) => {
      assert.ok(args.includes('--mode') && args.includes('structure-cold'));
      assert.ok(args.includes('--structure-profile') && args.includes('loopback'));
      launches++; active++; maximumActive = Math.max(maximumActive, active);
      const child = fakeChild(0, 'private diagnostic'); child.once('close', () => { active--; }); return child;
    },
    reportReader: async () => {
      const sample = launches;
      return { path:`/tmp/report-${sample}.json`, sha256:`${sample}`,
        report:{ status:'passed', driverCommit:'a'.repeat(40), archiveSha256:'b'.repeat(64), applicationJarSha256:'c'.repeat(64), shutdownConfirmed:true,
          testDirectory:`/tmp/run-${sample}`,browserProfileDirectory:`/tmp/run-${sample}/browser profile`,runtimeProcesses:{applicationPid:1000+sample,applicationStartTimeTicks:3000+sample,browserPid:2000+sample,browserStartTimeTicks:4000+sample},
          structureCold:{ passed:true, firstPageMs:sample === 20 ? 900 : sample, failedInventoryRequestCount:0, profileApplied:'loopback',
            browserHeapMemory:{sampledPeakBytes:1024}, jvmMemory:{incrementalPeakBytes:2048} } } };
    } });
  assert.equal(launches,20); assert.equal(maximumActive,1); assert.equal(result.sampleCount,20);
  assert.equal(result.successfulSamples,20); assert.equal(result.nearestRankP95FirstPageMs,19);
  assert.deepEqual(result.overBudgetSamples,[{index:20,firstPageMs:900}]);
  assert.equal(result.identityConsistent,true); assert.equal(result.passed,true);
  assert.ok(!JSON.stringify(result).includes('private diagnostic'));
  assert.equal(result.samples[0].diagnostic.byteLength, 'private diagnostic'.length);
});

test('runner fails closed on raw transport failures, missing source identities, or p95 over budget', async () => {
  let launches=0;
  const result = await runColdSamples({ driver:'/repo/driver.mjs', driverArgs:[], profile:'constrained', spawnImpl:()=>{launches++;return fakeChild();},
    reportReader:async()=>({path:`/tmp/${launches}.json`,sha256:'d'.repeat(64),report:{status:'passed',driverCommit:'a'.repeat(40),archiveSha256:launches===2?null:'b'.repeat(64),applicationJarSha256:'c'.repeat(64),shutdownConfirmed:true,
      testDirectory:`/tmp/run-${launches}`,browserProfileDirectory:`/tmp/run-${launches}/browser profile`,runtimeProcesses:{applicationPid:1000+launches,applicationStartTimeTicks:3000+launches,browserPid:2000+launches,browserStartTimeTicks:4000+launches},
      structureCold:{passed:true,firstPageMs:launches===20?1100:700,failedInventoryRequestCount:launches===1?1:0,profileApplied:'constrained',browserHeapMemory:{sampledPeakBytes:1},jvmMemory:{incrementalPeakBytes:1}}}}) });
  assert.equal(result.rawFailedRequests,1); assert.equal(result.successfulSamples,19); assert.equal(result.passed,false);
  const noIdentity = summarizeColdSamples(Array.from({length:20},(_,i)=>({status:'passed',firstPageMs:i+1,rawFailedRequests:0})));
  assert.equal(noIdentity.nearestRankP95FirstPageMs,19);
});

test('runner records the timeout state even when the child exits during termination grace', { skip: process.platform !== 'linux' }, async () => {
  let launches = 0;
  const result = await runColdSamples({ driver:'/repo/driver.mjs', driverArgs:[], profile:'loopback', timeoutMs:1000,
    spawnImpl:() => {
      const index = ++launches;
      const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.pid = 999999999;
      const close = () => { child.stdout.end('Report: /tmp/child/report.json\n'); child.stderr.end(); child.emit('close', 0); };
      setTimeout(close, index === 1 ? 1050 : 0);
      child.kill = () => true;
      return child;
    },
    reportReader: async () => ({ path:'/tmp/report.json', sha256:'a'.repeat(64),
      report:{ status:'passed', driverCommit:'b'.repeat(40), archiveSha256:'c'.repeat(64), applicationJarSha256:'d'.repeat(64),
        testDirectory:`/tmp/run-${launches}`, browserProfileDirectory:`/tmp/run-${launches}/profile`,
        runtimeProcesses:{ applicationPid:1000+launches, applicationStartTimeTicks:2000+launches,
          browserPid:3000+launches, browserStartTimeTicks:4000+launches },
        structureCold:{ passed:true, firstPageMs:10, failedInventoryRequestCount:0, profileApplied:'loopback' } } }) });
  assert.equal(result.samples[0].status, 'failed');
  assert.equal(result.samples[0].timedOut, true);
  assert.equal(result.samples[0].error, 'Cold sample timed out');
  assert.equal(result.passed, false);
});
