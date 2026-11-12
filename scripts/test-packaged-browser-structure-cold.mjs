import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { spawn } from 'node:child_process';
import { readFile, mkdtemp, mkdir, writeFile, rm, realpath } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { COLD_PROFILES, STRUCTURE_QUALIFICATION_SOURCE_FILES, applyStructureProfile, makeChromeThrottlingCommands, summarizeColdSamples, runColdSamples,
  verifyStructureQualificationSource, verifyStructureSourceRevision, verifyStructureBrowser } from './packaged-browser-structure-cold.mjs';

function gitBlob(bytes) { return createHash('sha1').update(`blob ${bytes.byteLength}\0`).update(bytes).digest('hex'); }
const approvedBrowserIdentity = Object.freeze({verified:true,product:'chrome',platform:'linux64',version:'149.0.7827.55',archiveSha256:'b'.repeat(64),
  executableSha256:'c'.repeat(64),lockSha256:'d'.repeat(64)});
const revisionBinding = (sourceCommit, headCommit, baseCommit) => ({verified:true,kind:headCommit ? 'pull-request-merge-commit' : 'commit-only',
  sourceCommit,headCommit:headCommit ?? null,baseCommit:baseCommit ?? null,parents:headCommit ? [baseCommit,headCommit] : []});
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');

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

test('qualification source identity matches committed Git blobs and refuses edited driver bytes', async () => {
  const commit = 'a'.repeat(40);
  const paths = ['.github/workflows/ci.yml', '.node-version', 'frontend/package.json',
    'scripts/check-packaged-web-browser.mjs', 'scripts/packaged-browser-structure-cold.mjs'];
  const committed = new Map(paths.map((path, i) => [path, Buffer.from(`committed source ${i}`)]));
  const working = new Map([...committed].map(([path, bytes]) => [path, Buffer.from(bytes)]));
  const runGit = (args, input) => {
    if (args[0] === 'rev-parse') {
      const path = args[1].slice(commit.length + 1);
      return gitBlob(committed.get(path));
    }
    assert.deepEqual(args, ['hash-object', '--stdin']);
    return gitBlob(input);
  };
  const identity = await verifyStructureQualificationSource('/repo', commit, {
    sourceFiles: paths, runGit, readFile: async path => working.get(path.slice('/repo/'.length)),
  });
  assert.equal(identity.verified, true);
  assert.equal(identity.commit, commit);
  assert.equal(identity.files.length, paths.length);
  assert.match(identity.sourceSha256, /^[0-9a-f]{64}$/);

  working.set(paths[1], Buffer.from('edited after source commit'));
  await assert.rejects(verifyStructureQualificationSource('/repo', commit, {
    sourceFiles: paths, runGit, readFile: async path => working.get(path.slice('/repo/'.length)),
  }), /qualification source differs from declared commit/);
});

test('source revision binding derives pull-request identity from the source commit graph', async () => {
  const base = '1'.repeat(40), head = '2'.repeat(40), merge = '3'.repeat(40), unrelated = '4'.repeat(40);
  const mergeRunGit = args => {
    if (args[0] === 'cat-file' && args[1] === '-p') return `tree ${'5'.repeat(40)}\nparent ${base}\nparent ${head}\n\nmerge candidate`;
    throw new Error(`unexpected git call: ${args.join(' ')}`);
  };
  const mergeBinding = await verifyStructureSourceRevision('/repo', merge, {expectedHeadCommit:head,expectedBaseCommit:base,eventPath:null,runGit:mergeRunGit});
  assert.deepEqual(mergeBinding,{verified:true,kind:'pull-request-merge-commit',sourceCommit:merge,headCommit:head,baseCommit:base,parents:[base,head]});
  await assert.rejects(verifyStructureSourceRevision('/repo', merge, {expectedHeadCommit:unrelated,expectedBaseCommit:base,eventPath:null,runGit:mergeRunGit}),/not the declared pull-request/);

  const headRunGit = args => {
    if (args[0] === 'cat-file' && args[1] === '-p') return `tree ${'6'.repeat(40)}\nparent ${unrelated}\n\nfeature head diverged before base advanced`;
    throw new Error(`unexpected git call: ${args.join(' ')}`);
  };
  assert.equal((await verifyStructureSourceRevision('/repo',head,{expectedHeadCommit:head,expectedBaseCommit:base,eventPath:null,runGit:headRunGit})).kind,'head-commit');
  const pushRunGit=args=>args[0]==='cat-file'&&args[1]==='-p'?`tree ${'7'.repeat(40)}\nparent ${base}\n\npush source`:null;
  const pushEvent=Buffer.from(JSON.stringify({after:head,ref:'refs/heads/master'}));
  assert.equal((await verifyStructureSourceRevision('/repo',head,{expectedHeadCommit:head,expectedBaseCommit:null,eventPath:'/event',
    readFile:async()=>pushEvent,runGit:pushRunGit})).kind,'push-commit');
  await assert.rejects(verifyStructureSourceRevision('/repo',merge,{expectedHeadCommit:head,expectedBaseCommit:null,eventPath:null,runGit:mergeRunGit}),/push source revision/);
});

test('source revision binding refuses environment values that contradict the GitHub event', async () => {
  const base='1'.repeat(40),head='2'.repeat(40),merge='3'.repeat(40);
  const runGit=args=>args[0]==='cat-file'&&args[1]==='-p'?`tree ${'5'.repeat(40)}\nparent ${base}\nparent ${head}\n\nmerge candidate`:null;
  const event=Buffer.from(JSON.stringify({pull_request:{head:{sha:head},base:{sha:base}}}));
  assert.equal((await verifyStructureSourceRevision('/repo',merge,{expectedHeadCommit:head,expectedBaseCommit:base,eventPath:'/event',
    readFile:async()=>event,runGit})).verified,true);
  await assert.rejects(verifyStructureSourceRevision('/repo',merge,{expectedHeadCommit:'4'.repeat(40),expectedBaseCommit:base,eventPath:'/event',
    readFile:async()=>event,runGit}),/do not match the GitHub event payload/);
});

test('source revision binding honors an ambient GitHub event path when one is present', async () => {
  const base='1'.repeat(40),head='2'.repeat(40),merge='3'.repeat(40);
  const runGit=args=>args[0]==='cat-file'&&args[1]==='-p'?`tree ${'5'.repeat(40)}\nparent ${base}\nparent ${head}\n\nshallow merge candidate`:null;
  const event=Buffer.from(JSON.stringify({pull_request:{head:{sha:head},base:{sha:base}}}));
  const previous=process.env.GITHUB_EVENT_PATH;
  process.env.GITHUB_EVENT_PATH='/ambient-event';
  try {
    const binding=await verifyStructureSourceRevision('/repo',merge,{expectedHeadCommit:head,expectedBaseCommit:base,
      readFile:async path=>{assert.equal(path,'/ambient-event');return event;},runGit});
    assert.equal(binding.kind,'pull-request-merge-commit');
  } finally {
    if(previous===undefined) delete process.env.GITHUB_EVENT_PATH;
    else process.env.GITHUB_EVENT_PATH=previous;
  }
});

test('browser identity requires the reviewed installed lock, binary hash, and exact version', async () => {
  const root=await mkdtemp(resolve(repoRoot,'build/structure-browser-pin-test-'));
  try {
    const install=resolve(root,'web-test-browser'); await mkdir(install);
    const chrome=resolve(install,'chrome'); const bytes=Buffer.from('pinned test browser executable');
    const lock={schemaVersion:1,product:'chrome',platform:'linux64',version:'149.0.7827.55',revision:'1625079',sha256:'a'.repeat(64),chromeSha256:createHash('sha256').update(bytes).digest('hex')};
    await writeFile(resolve(root,'web-test-browser.json'),JSON.stringify(lock));
    await writeFile(resolve(install,'decomp-browser-lock.json'),JSON.stringify(lock)); await writeFile(chrome,bytes);
    const options={repoRoot:root,chromePath:chrome,sourceLockPath:'web-test-browser.json',readFile,realpath,hashFile:async path=>createHash('sha256').update(await readFile(path)).digest('hex'),
      runVersion:()=>`Google Chrome for Testing ${lock.version}`};
    const identity=await verifyStructureBrowser(options);
    assert.equal(identity.verified,true); assert.equal(identity.executableSha256,lock.chromeSha256); assert.equal(identity.version,lock.version);
    await writeFile(chrome,'substituted browser');
    await assert.rejects(verifyStructureBrowser(options),/differs from the reviewed binary/);
    await writeFile(chrome,bytes);
    await assert.rejects(verifyStructureBrowser({...options,runVersion:()=>`Chromium 148.0.0.0`}),/version output/);
    await writeFile(resolve(install,'decomp-browser-lock.json'),JSON.stringify({...lock,version:'148.0.0.0'}));
    await assert.rejects(verifyStructureBrowser(options),/installed browser lock differs/);
  } finally { await rm(root,{recursive:true,force:true}); }
});

test('source identity includes the Node and browser qualification toolchain pins', () => {
  for (const path of ['.node-version', 'frontend/package.json', 'scripts/install-frontend-node.sh',
    'scripts/frontend-node-sha256.txt', 'scripts/install-web-test-browser.py', 'scripts/web-test-browser.json',
    'scripts/test-packaged-browser-install.py', 'scripts/test-packaged-browser-structure.mjs',
    'scripts/test-packaged-browser-structure-cold.mjs']) {
    assert.ok(STRUCTURE_QUALIFICATION_SOURCE_FILES.includes(path), `qualification source identity is missing ${path}`);
  }
});

test('source identity covers the complete relative import graph of the browser driver', async () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const pending = ['scripts/check-packaged-web-browser.mjs'];
  const visited = new Set();
  while (pending.length) {
    const source = pending.pop();
    if (visited.has(source)) continue;
    visited.add(source);
    assert.ok(STRUCTURE_QUALIFICATION_SOURCE_FILES.includes(source), `qualification source identity is missing imported module ${source}`);
    const contents = await readFile(resolve(root, source), 'utf8');
    const specifiers = [
      ...contents.matchAll(/\bfrom\s*(['"])(\.{1,2}\/[^'"]+)\1/g),
      ...contents.matchAll(/\bimport\s*\(\s*(['"])(\.{1,2}\/[^'"]+)\1\s*\)/g),
      ...contents.matchAll(/\bimport\s*(['"])(\.{1,2}\/[^'"]+)\1/g),
    ].map(match => match[2]);
    for (const specifier of specifiers) {
      const target = resolve(dirname(resolve(root, source)), specifier);
      const relativeTarget = relative(root, target);
      assert.ok(relativeTarget && !relativeTarget.startsWith('..'), `relative module escapes qualification root: ${specifier}`);
      pending.push(relativeTarget);
    }
  }
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
    expectedHeadCommit:'d'.repeat(40), expectedBaseCommit:'f'.repeat(40),
    spawnImpl: (_command, args) => {
      assert.ok(args.includes('--mode') && args.includes('structure-cold'));
      assert.ok(args.includes('--structure-profile') && args.includes('loopback'));
      launches++; active++; maximumActive = Math.max(maximumActive, active);
      const child = fakeChild(0, 'private diagnostic'); child.once('close', () => { active--; }); return child;
    },
    reportReader: async () => {
      const sample = launches;
      return { path:`/tmp/report-${sample}.json`, sha256:`${sample}`,
        report:{ status:'passed', driverCommit:'a'.repeat(40), driverPullRequestHeadCommit:'d'.repeat(40), driverPullRequestBaseCommit:'f'.repeat(40),
          sourceIdentity:{ verified:true, commit:'a'.repeat(40), sourceSha256:'e'.repeat(64), files:[{path:'scripts/web-test-browser.json',sha256:'d'.repeat(64)}],
            revisionBinding:revisionBinding('a'.repeat(40),'d'.repeat(40),'f'.repeat(40)) },browserIdentity:approvedBrowserIdentity,tools:{chromeSha256:'c'.repeat(64)},
          archiveSha256:'b'.repeat(64), applicationJarSha256:'c'.repeat(64), shutdownConfirmed:true,
          testDirectory:`/tmp/run-${sample}`,browserProfileDirectory:`/tmp/run-${sample}/browser profile`,runtimeProcesses:{applicationPid:1000+sample,applicationStartTimeTicks:3000+sample,browserPid:2000+sample,browserStartTimeTicks:4000+sample},
          structureCold:{ passed:true, firstPageMs:sample === 20 ? 900 : sample, failedInventoryRequestCount:0, profileApplied:'loopback',
            failedInventoryRequests:[{sequence:2,requestIdHash:'1'.repeat(64),urlHash:'2'.repeat(64),
              pathTemplate:'/nested/api/v1/jobs/{id}/runs/{id}/revisions/{id}/functions',method:'GET',status:200,
              failure:{error:'net::ERR_ABORTED',canceled:true},lateFailedAfterFinished:false,contentLength:12,dataLength:12,
              classification:'canceled-after-consumption',rawUrl:'https://private.example/secret?token=secret',body:'private body'}],
            failedInventoryRequestEvidenceComplete:true,provenCanceledAfterConsumptionCount:1,unprovenFailedInventoryRequestCount:0,
            browserHeapMemory:{sampledPeakBytes:1024}, jvmMemory:{incrementalPeakBytes:2048} },
          structureServerTiming:{timings:[{phase:'first-page',elapsedNanos:123456},{phase:'other',elapsedNanos:-1},
            {phase:'private phase',elapsedNanos:999}],limit:512,overflow:0} } };
    } });
  assert.equal(launches,20); assert.equal(maximumActive,1); assert.equal(result.sampleCount,20);
  assert.equal(result.successfulSamples,20); assert.equal(result.nearestRankP95FirstPageMs,19);
  assert.deepEqual(result.overBudgetSamples,[{index:20,firstPageMs:900}]);
  assert.equal(result.identityConsistent,true); assert.equal(result.passed,true);
  assert.equal(result.expectedHeadCommit,'d'.repeat(40));
  assert.equal(result.expectedBaseCommit,'f'.repeat(40));
  assert.equal(result.samples[0].driverPullRequestHeadCommit,'d'.repeat(40));
  assert.deepEqual(result.samples[0].structureServerTiming,{timings:[{phase:'first-page',elapsedNanos:123456}],limit:512,overflow:0,invalidOrDropped:2});
  assert.deepEqual(result.samples[0].failedInventoryRequests,[{sequence:2,requestIdHash:'1'.repeat(64),urlHash:'2'.repeat(64),
    pathTemplate:'/nested/api/v1/jobs/{id}/runs/{id}/revisions/{id}/functions',method:'GET',status:200,
    failure:{error:'net::ERR_ABORTED',canceled:true},lateFailedAfterFinished:false,contentLength:12,dataLength:12,
    classification:'canceled-after-consumption'}]);
  assert.equal(result.samples[0].failedInventoryRequestEvidenceComplete,true);
  assert.equal(result.samples[0].provenCanceledAfterConsumptionCount,1);
  assert.equal(result.samples[0].unprovenFailedInventoryRequestCount,0);
  assert.ok(!JSON.stringify(result).includes('private diagnostic'));
  assert.ok(!JSON.stringify(result).includes('private.example'));
  assert.ok(!JSON.stringify(result).includes('private body'));
  assert.equal(result.samples[0].diagnostic.byteLength, 'private diagnostic'.length);
});

test('cold aggregation refuses individually pinned but inconsistent browser builds', async () => {
  let launches=0;
  const result=await runColdSamples({driver:'/repo/driver.mjs',driverArgs:[],profile:'loopback',expectedHeadCommit:null,expectedBaseCommit:null,
    spawnImpl:()=>{launches++;return fakeChild();},
    reportReader:async()=>({path:`/tmp/browser-${launches}.json`,sha256:String(launches),report:{status:'passed',driverCommit:'a'.repeat(40),
      sourceIdentity:{verified:true,commit:'a'.repeat(40),sourceSha256:'e'.repeat(64),revisionBinding:revisionBinding('a'.repeat(40)),files:[{path:'scripts/web-test-browser.json',sha256:'d'.repeat(64)}]},
      browserIdentity:launches===9?{...approvedBrowserIdentity,version:'150.0.0.0'}:approvedBrowserIdentity,tools:{chromeSha256:'c'.repeat(64)},
      archiveSha256:'b'.repeat(64),applicationJarSha256:'c'.repeat(64),testDirectory:`/tmp/browser-run-${launches}`,
      browserProfileDirectory:`/tmp/browser-run-${launches}/profile`,runtimeProcesses:{applicationPid:1000+launches,applicationStartTimeTicks:2000+launches,
        browserPid:3000+launches,browserStartTimeTicks:4000+launches},structureCold:{passed:true,firstPageMs:10,failedInventoryRequestCount:0,
        profileApplied:'loopback',browserHeapMemory:{sampledPeakBytes:1},jvmMemory:{incrementalPeakBytes:1}}}})});
  assert.equal(result.successfulSamples,20);
  assert.equal(result.identityConsistent,false);
  assert.equal(result.passed,false);
});

test('runner fails closed on raw transport failures, missing source identities, or p95 over budget', async () => {
  let launches=0;
  const result = await runColdSamples({ driver:'/repo/driver.mjs', driverArgs:[], profile:'constrained', expectedHeadCommit:null, expectedBaseCommit:null,
    spawnImpl:()=>{launches++;return fakeChild();},
    reportReader:async()=>({path:`/tmp/${launches}.json`,sha256:'d'.repeat(64),report:{status:'passed',driverCommit:'a'.repeat(40),
      sourceIdentity:{verified:launches!==3,commit:'a'.repeat(40),sourceSha256:'e'.repeat(64),files:[{path:'scripts/web-test-browser.json',sha256:'d'.repeat(64)}],revisionBinding:revisionBinding('a'.repeat(40))},
      browserIdentity:approvedBrowserIdentity,tools:{chromeSha256:'c'.repeat(64)},
      archiveSha256:launches===2?null:'b'.repeat(64),applicationJarSha256:'c'.repeat(64),shutdownConfirmed:true,
      testDirectory:`/tmp/run-${launches}`,browserProfileDirectory:`/tmp/run-${launches}/browser profile`,runtimeProcesses:{applicationPid:1000+launches,applicationStartTimeTicks:3000+launches,browserPid:2000+launches,browserStartTimeTicks:4000+launches},
      structureCold:{passed:true,firstPageMs:launches===20?1100:700,failedInventoryRequestCount:launches===1?1:0,profileApplied:'constrained',browserHeapMemory:{sampledPeakBytes:1},jvmMemory:{incrementalPeakBytes:1}}}}) });
  assert.equal(result.rawFailedRequests,1); assert.equal(result.successfulSamples,18); assert.equal(result.identityConsistent,false); assert.equal(result.passed,false);
  const noIdentity = summarizeColdSamples(Array.from({length:20},(_,i)=>({status:'passed',firstPageMs:i+1,rawFailedRequests:0})));
  assert.equal(noIdentity.nearestRankP95FirstPageMs,19);
});

test('runner refuses a child report attributed to a different pull-request head or base', async () => {
  let launches = 0;
  const result = await runColdSamples({ driver:'/repo/driver.mjs', driverArgs:[], profile:'loopback',
    expectedHeadCommit:'d'.repeat(40), expectedBaseCommit:'f'.repeat(40), spawnImpl:()=>{launches++;return fakeChild();},
    reportReader:async()=>({path:`/tmp/${launches}.json`,sha256:'a'.repeat(64),report:{status:'passed',driverCommit:'b'.repeat(40),
      driverPullRequestHeadCommit:'c'.repeat(40),driverPullRequestBaseCommit:'e'.repeat(40),
      sourceIdentity:{verified:true,commit:'b'.repeat(40),sourceSha256:'1'.repeat(64),files:[{path:'scripts/web-test-browser.json',sha256:'d'.repeat(64)}],revisionBinding:revisionBinding('b'.repeat(40),'c'.repeat(40),'e'.repeat(40))},
      browserIdentity:approvedBrowserIdentity,archiveSha256:'2'.repeat(64),
      applicationJarSha256:'3'.repeat(64),testDirectory:`/tmp/run-${launches}`,browserProfileDirectory:`/tmp/run-${launches}/profile`,
      runtimeProcesses:{applicationPid:10_000+launches,applicationStartTimeTicks:20_000+launches,browserPid:30_000+launches,browserStartTimeTicks:40_000+launches},
      structureCold:{passed:true,firstPageMs:10,failedInventoryRequestCount:0,profileApplied:'loopback'}}})});
  assert.equal(result.successfulSamples,0);
  assert.equal(result.identityConsistent,false);
  assert.match(result.samples[0].error,/declared pull-request head SHA/);
  assert.equal(result.passed,false);

  launches = 0;
  const baseMismatch = await runColdSamples({ driver:'/repo/driver.mjs', driverArgs:[], profile:'loopback',
    expectedHeadCommit:'d'.repeat(40), expectedBaseCommit:'f'.repeat(40), spawnImpl:()=>{launches++;return fakeChild();},
    reportReader:async()=>({path:`/tmp/base-${launches}.json`,sha256:'b'.repeat(64),report:{status:'passed',driverCommit:'a'.repeat(40),
      driverPullRequestHeadCommit:'d'.repeat(40),driverPullRequestBaseCommit:'e'.repeat(40),
      sourceIdentity:{verified:true,commit:'a'.repeat(40),sourceSha256:'1'.repeat(64),files:[{path:'scripts/web-test-browser.json',sha256:'d'.repeat(64)}],revisionBinding:revisionBinding('a'.repeat(40),'d'.repeat(40),'e'.repeat(40))},
      browserIdentity:approvedBrowserIdentity,archiveSha256:'2'.repeat(64),
      applicationJarSha256:'3'.repeat(64),testDirectory:`/tmp/base-run-${launches}`,browserProfileDirectory:`/tmp/base-run-${launches}/profile`,
      runtimeProcesses:{applicationPid:20_000+launches,applicationStartTimeTicks:30_000+launches,browserPid:40_000+launches,browserStartTimeTicks:50_000+launches},
      structureCold:{passed:true,firstPageMs:10,failedInventoryRequestCount:0,profileApplied:'loopback'}}})});
  assert.equal(baseMismatch.successfulSamples,0);
  assert.match(baseMismatch.samples[0].error,/declared pull-request base SHA/);
});

test('runner classifies an absent child report separately from a pull-request identity mismatch', async () => {
  const result = await runColdSamples({ driver:'/repo/driver.mjs', driverArgs:[], profile:'loopback',
    expectedHeadCommit:'d'.repeat(40), expectedBaseCommit:'f'.repeat(40), spawnImpl:()=>fakeChild(),
    reportReader:async()=>null });
  assert.equal(result.successfulSamples,0);
  assert.equal(result.identityConsistent,false);
  assert.equal(result.samples.length,20);
  assert.ok(result.samples.every(sample => sample.error === 'Child report was not produced or could not be read'));
  assert.ok(result.samples.every(sample => sample.childReportPresent === false));
  assert.ok(result.samples.every(sample => sample.driverPullRequestHeadCommit === null));

  const unreadable = await runColdSamples({ driver:'/repo/driver.mjs', driverArgs:[], profile:'loopback',
    expectedHeadCommit:'d'.repeat(40), expectedBaseCommit:'f'.repeat(40), spawnImpl:()=>fakeChild(),
    reportReader:async()=>{ throw Object.assign(new Error('/secret/private/report.json'),{code:'ENOENT'}); } });
  assert.ok(unreadable.samples.every(sample => sample.error === 'Child report was not produced or could not be read'));
  assert.ok(!JSON.stringify(unreadable).includes('/secret/private'));
});

test('runner records the timeout state even when the child exits during termination grace', { skip: process.platform !== 'linux' }, async () => {
  let launches = 0;
  const result = await runColdSamples({ driver:'/repo/driver.mjs', driverArgs:[], profile:'loopback', timeoutMs:1000,
    expectedHeadCommit:null, expectedBaseCommit:null,
    spawnImpl:() => {
      const index = ++launches;
      const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.pid = 999999999;
      const close = () => { child.stdout.end('Report: /tmp/child/report.json\n'); child.stderr.end(); child.emit('close', 0); };
      setTimeout(close, index === 1 ? 1050 : 0);
      child.kill = () => true;
      return child;
    },
    reportReader: async () => ({ path:'/tmp/report.json', sha256:'a'.repeat(64),
      report:{ status:'passed', driverCommit:'b'.repeat(40), sourceIdentity:{ verified:true, commit:'b'.repeat(40), sourceSha256:'e'.repeat(64), files:[{path:'scripts/web-test-browser.json',sha256:'d'.repeat(64)}],revisionBinding:revisionBinding('b'.repeat(40)) },browserIdentity:approvedBrowserIdentity,
        archiveSha256:'c'.repeat(64), applicationJarSha256:'d'.repeat(64),
        testDirectory:`/tmp/run-${launches}`, browserProfileDirectory:`/tmp/run-${launches}/profile`,
        runtimeProcesses:{ applicationPid:1000+launches, applicationStartTimeTicks:2000+launches,
          browserPid:3000+launches, browserStartTimeTicks:4000+launches },
        structureCold:{ passed:true, firstPageMs:10, failedInventoryRequestCount:0, profileApplied:'loopback' } } }) });
  assert.equal(result.samples[0].status, 'failed');
  assert.equal(result.samples[0].timedOut, true);
  assert.equal(result.samples[0].error, 'Cold sample timed out');
  assert.equal(result.passed, false);
});

test('runner confirms real process groups and escalates when a surviving descendant ignores termination', { skip: process.platform !== 'linux' }, async () => {
  let launches = 0;
  const descendantPids = [];
  const result = await runColdSamples({ driver:'/unused/driver.mjs', driverArgs:[], profile:'loopback', processGroupGraceMs:150,
    expectedHeadCommit:null, expectedBaseCommit:null,
    spawnImpl:(command, _args, options) => {
      const index = ++launches;
      const descendant = index === 1 ? `process.on('SIGTERM',()=>{}); setInterval(()=>{},1000);`
        : index === 2 ? `setTimeout(()=>process.exit(0),30);`
          : null;
      const launch = descendant === null
        ? `process.stdout.write('Report: /tmp/child/report.json\\n',()=>process.exit(0));`
        : `const {spawn}=require('node:child_process'); const child=spawn(process.execPath,['-e',${JSON.stringify(descendant)}],{stdio:'ignore'}); child.unref(); process.stdout.write('descendant-pid='+child.pid+'\\nReport: /tmp/child/report.json\\n',()=>process.exit(0));`;
      return spawn(command, ['-e', launch], options);
    },
    reportReader:async stdout => {
      const pid = Number(stdout.match(/descendant-pid=(\d+)/)?.[1]);
      if (pid) {
        assert.doesNotThrow(() => process.kill(pid, 0), 'the runner should observe the live descendant before cleanup');
        descendantPids.push(pid);
      }
      const sample = launches;
      return {path:`/tmp/report-${sample}.json`,sha256:String(sample),report:{status:'passed',driverCommit:'a'.repeat(40),
        sourceIdentity:{verified:true,commit:'a'.repeat(40),sourceSha256:'e'.repeat(64),files:[{path:'scripts/web-test-browser.json',sha256:'d'.repeat(64)}],revisionBinding:revisionBinding('a'.repeat(40))},browserIdentity:approvedBrowserIdentity,archiveSha256:'b'.repeat(64),
        applicationJarSha256:'c'.repeat(64),testDirectory:`/tmp/run-${sample}`,browserProfileDirectory:`/tmp/run-${sample}/profile`,
        runtimeProcesses:{applicationPid:10_000+sample,applicationStartTimeTicks:20_000+sample,browserPid:30_000+sample,browserStartTimeTicks:40_000+sample},
        structureCold:{passed:true,firstPageMs:10,failedInventoryRequestCount:0,profileApplied:'loopback'}}};
    }});
  assert.equal(launches,20);
  assert.equal(result.samples[0].processTreeForced,true,JSON.stringify(result.samples[0]));
  assert.equal(result.samples[0].shutdownConfirmed,true);
  assert.equal(result.samples[0].status,'failed','forced cleanup must be reported as a failed cold sample');
  assert.equal(result.samples[1].processTreeForced,false,'a descendant that exits during the grace window needs no escalation');
  assert.equal(result.samples[1].shutdownConfirmed,true);
  assert.equal(descendantPids.length,2);
  for (const pid of descendantPids) {
    const stat = await readFile(`/proc/${pid}/stat`, 'utf8').catch(error => error?.code === 'ENOENT' ? null : Promise.reject(error));
    const state = stat === null ? null : stat.slice(stat.lastIndexOf(') ') + 2, stat.lastIndexOf(') ') + 3);
    assert.ok(stat === null || state === 'Z', `owned descendant ${pid} should be gone or reaped after the sample closes`);
  }
});

test('timeout sends SIGTERM then SIGKILL to a real launcher and descendant that both ignore termination', { skip: process.platform !== 'linux' }, async () => {
  let launches = 0;
  let descendantPid = null;
  const result = await runColdSamples({ driver:'/unused/driver.mjs', driverArgs:[], profile:'loopback', timeoutMs:1000,
    expectedHeadCommit:null, expectedBaseCommit:null,
    terminationGraceMs:150, processGroupGraceMs:150,
    spawnImpl:(command, _args, options) => {
      const index = ++launches;
      const launch = index === 1
        ? `const {spawn}=require('node:child_process'); const child=spawn(process.execPath,['-e',${JSON.stringify("process.on('SIGTERM',()=>{});setInterval(()=>{},1000);")}],{stdio:'ignore'}); child.unref(); process.on('SIGTERM',()=>{}); process.stdout.write('descendant-pid='+child.pid+'\\nReport: /tmp/child/report.json\\n'); setInterval(()=>{},1000);`
        : `process.stdout.write('Report: /tmp/child/report.json\\n',()=>process.exit(0));`;
      const child = spawn(command, ['-e', launch], options);
      child.stdout.on('data', chunk => {
        const pid = Number(chunk.toString('utf8').match(/descendant-pid=(\d+)/)?.[1]);
        if (pid) descendantPid = pid;
      });
      return child;
    },
    reportReader:async stdout => {
      const sample = launches;
      return {path:`/tmp/report-${sample}.json`,sha256:String(sample),report:{status:'passed',driverCommit:'a'.repeat(40),
        sourceIdentity:{verified:true,commit:'a'.repeat(40),sourceSha256:'e'.repeat(64),files:[{path:'scripts/web-test-browser.json',sha256:'d'.repeat(64)}],revisionBinding:revisionBinding('a'.repeat(40))},browserIdentity:approvedBrowserIdentity,archiveSha256:'b'.repeat(64),
        applicationJarSha256:'c'.repeat(64),testDirectory:`/tmp/run-${sample}`,browserProfileDirectory:`/tmp/run-${sample}/profile`,
        runtimeProcesses:{applicationPid:50_000+sample,applicationStartTimeTicks:60_000+sample,browserPid:70_000+sample,browserStartTimeTicks:80_000+sample},
        structureCold:{passed:true,firstPageMs:10,failedInventoryRequestCount:0,profileApplied:'loopback'}}};
    }});
  assert.equal(launches,20);
  assert.equal(result.samples[0].timedOut,true);
  assert.equal(result.samples[0].processTreeForced,true,JSON.stringify(result.samples[0]));
  assert.equal(result.samples[0].shutdownConfirmed,true);
  assert.equal(result.samples[0].status,'failed');
  assert.ok(descendantPid > 0);
  const stat = await readFile(`/proc/${descendantPid}/stat`, 'utf8').catch(error => error?.code === 'ENOENT' ? null : Promise.reject(error));
  const state = stat === null ? null : stat.slice(stat.lastIndexOf(') ') + 2, stat.lastIndexOf(') ') + 3);
  assert.ok(stat === null || state === 'Z', 'the real descendant must be gone or reaped after timeout escalation');
});
