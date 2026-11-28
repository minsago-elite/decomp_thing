import { execFileSync, spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { basename, dirname, join, resolve } from 'node:path';
import { createReadStream } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { MAX_REPORT_BYTES, MAX_REPORT_PARTS, REPORT_PART_BYTES } from './packaged-browser-restart.mjs';

export const COLD_SAMPLE_COUNT = 20;
export const COLD_SAMPLE_TIMEOUT_MS = 45_000;
export const STRUCTURE_QUALIFICATION_SOURCE_FILES = Object.freeze([
  '.github/workflows/ci.yml',
  '.node-version',
  'frontend/package.json',
  'scripts/check-packaged-web-browser.mjs',
  'scripts/packaged-browser-structure.mjs',
  'scripts/packaged-browser-structure-cold.mjs',
  'scripts/packaged-browser-structure-profile.json',
  'scripts/frontend-node-sha256.txt',
  'scripts/install-frontend-node.sh',
  'scripts/install-web-test-browser.py',
  'scripts/web-test-browser.json',
  'scripts/packaged-browser-install.py',
  'scripts/test-packaged-browser-install.py',
  'scripts/packaged-browser-upload.mjs',
  'scripts/packaged-browser-scale.mjs',
  'scripts/packaged-browser-contrast.mjs',
  'scripts/packaged-browser-live.mjs',
  'scripts/packaged-browser-lifecycle.mjs',
  'scripts/packaged-browser-history.mjs',
  'scripts/packaged-browser-legacy.mjs',
  'scripts/packaged-browser-restart.mjs',
  'scripts/packaged-browser-upgrade.mjs',
  'scripts/packaged-browser-audit.mjs',
  'scripts/packaged-browser-cdp-diagnostics.mjs',
  'scripts/packaged-browser-target-lifecycle.mjs',
  'scripts/packaged-browser-temp-parent.mjs',
  'scripts/packaged-browser-log-server-phases.mjs',
  'scripts/packaged-browser-logs.mjs',
  'scripts/packaged-browser-log-projection-evidence.mjs',
  'scripts/packaged-browser-sources.mjs',
  'scripts/packaged-browser-native-download.mjs',
  'scripts/test-packaged-browser-structure.mjs',
  'scripts/test-packaged-browser-structure-cold.mjs',
]);
export const COLD_PROFILES = Object.freeze({
  loopback: Object.freeze({ name: 'loopback', firstPageLimitMs: 500, cpuRate: 1, latencyMs: 0, downloadBytesPerSecond: 0, uploadBytesPerSecond: 0 }),
  constrained: Object.freeze({ name: 'constrained', firstPageLimitMs: 1000, cpuRate: 4, latencyMs: 100, downloadBytesPerSecond: 1_250_000, uploadBytesPerSecond: 250_000 }),
});

export function structureProfile(name = 'loopback') {
  const profile = COLD_PROFILES[name];
  if (!profile) throw new TypeError(`unknown structure profile: ${name}`);
  return profile;
}

export async function verifyStructureQualificationSource(repoRoot, commit, {
  sourceFiles = STRUCTURE_QUALIFICATION_SOURCE_FILES,
  readFile = fs.readFile,
  runGit = (args, input) => execFileSync('git', ['-C', repoRoot, ...args], {
    encoding: input === undefined ? 'utf8' : undefined,
    input,
    stdio: ['pipe', 'pipe', 'pipe'],
  }).toString().trim(),
} = {}) {
  if (typeof commit !== 'string' || !/^[0-9a-f]{40,64}$/.test(commit)) throw new TypeError('qualification source commit must be a full Git object ID');
  if (!Array.isArray(sourceFiles) || sourceFiles.length === 0 || new Set(sourceFiles).size !== sourceFiles.length) {
    throw new TypeError('qualification source file list must be non-empty and unique');
  }
  const files = [];
  for (const path of sourceFiles) {
    const approvedSourcePath = typeof path === 'string' && (path.startsWith('scripts/')
      || path === '.github/workflows/ci.yml' || path === '.node-version' || path === 'frontend/package.json');
    if (!approvedSourcePath || path.startsWith('/') || path.split('/').includes('..')) {
      throw new TypeError(`invalid qualification source path: ${String(path)}`);
    }
    const committedBlob = runGit(['rev-parse', `${commit}:${path}`]);
    const bytes = await readFile(`${repoRoot}/${path}`);
    const executedBlob = runGit(['hash-object', '--stdin'], bytes);
    if (!/^[0-9a-f]{40,64}$/.test(committedBlob) || !/^[0-9a-f]{40,64}$/.test(executedBlob)) {
      throw new Error(`Git returned an invalid blob identity for qualification source ${path}`);
    }
    if (executedBlob !== committedBlob) throw new Error(`qualification source differs from declared commit: ${path}`);
    files.push({ path, gitBlob: committedBlob, sha256: createHash('sha256').update(bytes).digest('hex'), byteLength: bytes.byteLength });
  }
  const sourceSha256 = createHash('sha256').update(JSON.stringify({ commit, files })).digest('hex');
  return { verified: true, commit, sourceSha256, files };
}

export async function verifyStructureSourceRevision(repoRoot, sourceCommit, {
  expectedHeadCommit = process.env.PACKAGED_WEB_SOURCE_HEAD_SHA || null,
  expectedBaseCommit = process.env.PACKAGED_WEB_SOURCE_BASE_SHA || null,
  eventPath = process.env.GITHUB_EVENT_PATH || null,
  readFile = fs.readFile,
  runGit = args => execFileSync('git', ['-C', repoRoot, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim(),
} = {}) {
  const fullObjectId = value => typeof value === 'string' && /^[0-9a-f]{40,64}$/.test(value);
  if (!fullObjectId(sourceCommit)) throw new TypeError('qualification source commit must be a full Git object ID');
  // Read the commit object itself: `rev-list --parents` hides parents at a
  // shallow boundary, which is exactly how checkout@v* provisions CI builds.
  const commitObject = runGit(['cat-file', '-p', sourceCommit]);
  const header = commitObject.split('\n\n', 1)[0];
  const headerLines = header.split('\n');
  if (!headerLines.some(line => /^tree [0-9a-f]{40,64}$/.test(line))) {
    throw new Error('qualification source commit object is malformed');
  }
  const parents = headerLines.filter(line => line.startsWith('parent ')).map(line => line.slice('parent '.length));
  if (parents.some(parent => !fullObjectId(parent)) || new Set(parents).size !== parents.length) {
    throw new Error('qualification source commit parent list is invalid');
  }
  if (expectedHeadCommit === null && expectedBaseCommit === null) {
    return { verified: true, kind: 'commit-only', sourceCommit, headCommit: null, baseCommit: null, parents };
  }
  if (!fullObjectId(expectedHeadCommit) || (expectedBaseCommit !== null && !fullObjectId(expectedBaseCommit))) {
    throw new TypeError('declared source head/base must be full Git object IDs');
  }
  let event = null;
  if (eventPath) event = JSON.parse(await readFile(eventPath, 'utf8'));
  let kind;
  if (expectedBaseCommit === null) {
    const branchPushMismatch = event?.ref?.startsWith('refs/heads/') && event?.after !== expectedHeadCommit;
    if (event?.pull_request || sourceCommit !== expectedHeadCommit || branchPushMismatch) {
      throw new Error('declared push source revision does not match the checked-out commit and event payload');
    }
    kind = 'push-commit';
  } else if (event) {
    const eventHead = event?.pull_request?.head?.sha;
    const eventBase = event?.pull_request?.base?.sha;
    if (eventHead !== expectedHeadCommit || eventBase !== expectedBaseCommit) {
      throw new Error('declared pull-request revisions do not match the GitHub event payload');
    }
  }
  if (kind === 'push-commit') {
    // A push event binds the exact checked-out source commit.
  } else if (sourceCommit === expectedHeadCommit) {
    // Exact head identity plus the event's base/head pair is sufficient. A
    // feature head need not contain a base that advanced after it diverged.
    kind = 'head-commit';
  } else if (parents.length === 2 && parents[0] === expectedBaseCommit && parents[1] === expectedHeadCommit) {
    kind = 'pull-request-merge-commit';
  } else {
    throw new Error('qualification source commit is not the declared pull-request head or its base/head merge');
  }
  return { verified: true, kind, sourceCommit, headCommit: expectedHeadCommit, baseCommit: expectedBaseCommit, parents };
}

export async function verifyStructureBrowser({ repoRoot, chromePath, sourceLockPath = 'scripts/web-test-browser.json',
  readFile = fs.readFile, realpath = fs.realpath, hashFile = async path => {
    const digest = createHash('sha256');
    for await (const chunk of createReadStream(path)) digest.update(chunk);
    return digest.digest('hex');
  }, runVersion = path => execFileSync(path, ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 5000 }).trim() }) {
  const sourceLockBytes = await readFile(resolve(repoRoot, sourceLockPath));
  const sourceLock = JSON.parse(sourceLockBytes.toString('utf8'));
  if (sourceLock?.schemaVersion !== 1 || sourceLock?.product !== 'chrome' || sourceLock?.platform !== 'linux64'
      || typeof sourceLock?.version !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(sourceLock.version)
      || typeof sourceLock?.chromeSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(sourceLock.chromeSha256)) {
    throw new Error('reviewed browser lock does not contain a valid Chrome binary identity');
  }
  const executable = await realpath(chromePath);
  if (basename(executable) !== 'chrome') throw new Error('Chrome executable is not the reviewed installation entry point');
  const installationRoot = dirname(executable);
  if (await realpath(dirname(chromePath)) !== installationRoot) throw new Error('Chrome executable is not directly inside its reviewed installation');
  const installedLockBytes = await readFile(resolve(installationRoot, 'decomp-browser-lock.json'));
  const installedLock = JSON.parse(installedLockBytes.toString('utf8'));
  const canonical = value => JSON.stringify(value, Object.keys(value).sort());
  if (canonical(installedLock) !== canonical(sourceLock)) throw new Error('installed browser lock differs from the reviewed source lock');
  const executableSha256 = await hashFile(executable);
  if (executableSha256 !== sourceLock.chromeSha256) throw new Error('Chrome executable differs from the reviewed binary SHA-256');
  const versionOutput = runVersion(executable);
  const escapedVersion = sourceLock.version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (!new RegExp(`(?:^|\\s)${escapedVersion}(?:\\s|$)`).test(versionOutput)) {
    throw new Error('Chrome version output differs from the reviewed browser version');
  }
  return { verified: true, product: sourceLock.product, platform: sourceLock.platform, version: sourceLock.version,
    revision: sourceLock.revision, archiveSha256: sourceLock.sha256, executableSha256, lockSha256: createHash('sha256').update(sourceLockBytes).digest('hex') };
}

/**
 * Live (not zombie or dead) members of a Linux process group, read from /proc. Returns null when absence cannot be
 * established: an unreadable /proc, an unreadable entry other than one that exited meanwhile, or a malformed record.
 */
export async function liveProcessGroupMembers(processGroupId, { readdir = fs.readdir, readFile = fs.readFile } = {}) {
  let names;
  try { names = await readdir('/proc'); }
  catch { return null; }
  const pids = names.filter(name => /^[1-9][0-9]{0,9}$/.test(name));
  const live = [];
  for (let start = 0; start < pids.length; start += 64) {
    const batch = await Promise.all(pids.slice(start, start + 64).map(name => Promise.resolve().then(() => readFile(`/proc/${name}/stat`, 'utf8'))
      .then(stat => ({ name, stat }), error => ({ name, error }))));
    for (const { name, stat, error } of batch) {
      if (error) {
        if (error?.code === 'ENOENT' || error?.code === 'ESRCH') continue; // Exited after the listing.
        return null;
      }
      const member = liveMember(stat, processGroupId);
      if (member === null) return null; // A malformed record cannot prove absence.
      if (member) live.push(Number(name));
    }
  }
  return live;
}

/** True for a live member of the group, false for another group or a zombie or dead member, null when malformed. */
function liveMember(stat, processGroupId) {
  const commandEnd = typeof stat === 'string' ? stat.lastIndexOf(') ') : -1;
  const fields = commandEnd < 0 ? [] : stat.slice(commandEnd + 2).trim().split(/\s+/);
  const state = fields[0];
  const group = Number(fields[2]);
  if (!/^[A-Za-z]$/.test(state ?? '') || !Number.isSafeInteger(group)) return null;
  return group === processGroupId && !['Z', 'X', 'x'].includes(state);
}

/**
 * Confirms that no live member of the process group remains. kill(-group, 0) still succeeds while the group holds only
 * zombies that a non-reaping PID 1 never collects (R4), so those are read from /proc: two zombie-only observations one
 * poll apart mean no member can still run or fork. Anything that cannot be established stays unconfirmed.
 */
export async function waitForProcessGroupExit(pid, timeoutMs, { members = liveProcessGroupMembers, pollMs = 100 } = {}) {
  if (process.platform !== 'linux' || !Number.isSafeInteger(pid) || pid <= 0) return false;
  const deadline = Date.now() + timeoutMs;
  let zombieOnlyObservations = 0;
  for (;;) {
    try { process.kill(-pid, 0); }
    catch (error) { return error?.code === 'ESRCH'; }
    const live = await members(pid);
    zombieOnlyObservations = Array.isArray(live) && live.length === 0 ? zombieOnlyObservations + 1 : 0;
    if (zombieOnlyObservations >= 2) return true;
    // A zombie-only observation at the deadline gets exactly one more poll to complete its pair.
    if (Date.now() >= deadline && zombieOnlyObservations === 0) return false;
    await new Promise(resolve => setTimeout(resolve, pollMs));
  }
}

async function forceStopProcessGroup(pid, timeoutMs = 10_000) {
  if (process.platform !== 'linux' || !Number.isSafeInteger(pid) || pid <= 0) return false;
  try { process.kill(-pid, 'SIGKILL'); }
  catch (error) { if (error?.code === 'ESRCH') return true; }
  return waitForProcessGroupExit(pid, timeoutMs);
}

export function summarizeColdSamples(samples, expected = COLD_SAMPLE_COUNT) {
  if (!Number.isSafeInteger(expected) || expected < 1) throw new TypeError('expected sample count must be positive');
  if (!Array.isArray(samples) || samples.length !== expected) throw new RangeError(`expected exactly ${expected} samples; received ${samples?.length ?? 'invalid'}`);
  const validRawCount = sample => Number.isSafeInteger(sample?.rawFailedRequests) && sample.rawFailedRequests >= 0;
  const successful = samples.filter(s => s?.status === 'passed' && validRawCount(s) && s.rawFailedRequests === 0
    && Number.isFinite(s.firstPageMs) && s.firstPageMs >= 0);
  // Failed runs remain failures, but any timing they produced still belongs in
  // the latency distribution; otherwise a slow failed request could disappear
  // from p95 simply because a separate assertion also failed.
  const values = samples.filter(s => Number.isFinite(s?.firstPageMs) && s.firstPageMs >= 0)
    .map(s => s.firstPageMs).sort((a,b) => a-b);
  const failures = samples.reduce((n,s) => n + (s?.status === 'passed' ? 0 : 1)
    + (validRawCount(s) ? s.rawFailedRequests : 1), 0);
  const p95 = values.length ? values[Math.ceil(values.length * .95)-1] : null;
  const median = values.length ? (values.length % 2 ? values[(values.length-1)/2] : (values[values.length/2-1]+values[values.length/2])/2) : null;
  return { expectedSamples: expected, sampleCount: samples.length, timedSamples: values.length, samples, successfulSamples: successful.length,
    medianFirstPageMs: median, nearestRankP95FirstPageMs: p95,
    rawFailedRequests: samples.reduce((n,s)=>n+(validRawCount(s) ? s.rawFailedRequests : 0),0), invalidRawCountSamples: samples.filter(s=>!validRawCount(s)).length, failures,
    passed: samples.length === expected && successful.length === expected && failures === 0 };
}

export function makeChromeThrottlingCommands(profile) {
  if (!Object.values(COLD_PROFILES).includes(profile)) throw new TypeError('unknown cold profile');
  if (profile.name === 'loopback') return [];
  return [
    { method: 'Emulation.setCPUThrottlingRate', params: { rate: profile.cpuRate } },
    { method: 'Network.emulateNetworkConditions', params: { offline: false, latency: profile.latencyMs,
      downloadThroughput: profile.downloadBytesPerSecond, uploadThroughput: profile.uploadBytesPerSecond, connectionType: 'cellular3g' } },
  ];
}

export async function applyStructureProfile(cdp, sessionId, name = 'loopback') {
  const profile = typeof name === 'string' ? structureProfile(name) : name;
  for (const command of makeChromeThrottlingCommands(profile)) await cdp.call(command.method, command.params, sessionId);
  return profile;
}

export async function runColdSamples({ driver, driverArgs, count = COLD_SAMPLE_COUNT, profile = 'loopback', spawnImpl = spawn,
  timeoutMs = COLD_SAMPLE_TIMEOUT_MS, terminationGraceMs = 10_000, processGroupGraceMs = 10_000,
  expectedHeadCommit = process.env.PACKAGED_WEB_SOURCE_HEAD_SHA || null,
  expectedBaseCommit = process.env.PACKAGED_WEB_SOURCE_BASE_SHA || null, reportReader = readChildReport }) {
  if (count !== COLD_SAMPLE_COUNT) throw new RangeError(`cold structure run requires exactly ${COLD_SAMPLE_COUNT} samples`);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30 * 60_000) throw new RangeError('cold sample timeout is outside its allowed bound');
  if (!Number.isSafeInteger(terminationGraceMs) || terminationGraceMs < 100 || terminationGraceMs > 30_000) {
    throw new RangeError('termination grace is outside its allowed bound');
  }
  if (!Number.isSafeInteger(processGroupGraceMs) || processGroupGraceMs < 100 || processGroupGraceMs > 30_000) {
    throw new RangeError('process group grace is outside its allowed bound');
  }
  for (const [label, commit] of [['pull request head', expectedHeadCommit], ['pull request base', expectedBaseCommit]]) {
    if (commit !== null && (typeof commit !== 'string' || !/^[0-9a-f]{40,64}$/.test(commit))) {
      throw new TypeError(`declared ${label} commit must be a full Git object ID`);
    }
  }
  if (expectedHeadCommit === null && expectedBaseCommit !== null) {
    throw new TypeError('a declared pull-request base cannot be supplied without its head commit');
  }
  profile = structureProfile(typeof profile === 'string' ? profile : profile?.name);
  const samples = [];
  let activeChild = null, interrupted = null;
  const interrupt = signal => {
    interrupted = signal;
    if (!activeChild?.pid) return;
    try {
      if (process.platform === 'linux') process.kill(-activeChild.pid, 'SIGTERM');
      else activeChild.kill('SIGTERM');
    } catch {}
  };
  process.once('SIGTERM', interrupt);
  process.once('SIGINT', interrupt);
  try {
  for (let index = 0; index < count; index++) {
    if (interrupted) break;
    let stdout = '', stderr = '', exitCode = null, timedOut = false, childClosed = false, processTreeConfirmed = false, processGroupId = null;
    try {
      const child = spawnImpl(process.execPath, [driver, ...driverArgs, '--mode', 'structure-cold', '--structure-profile', profile.name],
        { stdio: ['ignore','pipe','pipe'], detached: process.platform === 'linux' });
      activeChild = child;
      processGroupId = child.pid;
      const retain = (current, chunk) => (current + chunk.toString('utf8')).slice(-1_048_576);
      const outcome = await new Promise(resolveOutcome => {
        let settled = false;
        const settle = result => { if (!settled) { settled = true; resolveOutcome(result); } };
        child.stdout.on('data', b => { stdout = retain(stdout, b); });
        child.stderr.on('data', b => { stderr = retain(stderr, b); });
        child.once('error', error => { if (!timedOut) settle({ error }); });
        child.once('close', code => { childClosed = true; if (!timedOut) settle({ code }); });
        const timer = setTimeout(async () => {
          timedOut = true;
          try {
            if (process.platform === 'linux' && child.pid) process.kill(-child.pid, 'SIGTERM');
            else child.kill('SIGTERM');
          } catch {}
          const childClosedInGrace = childClosed || await Promise.race([new Promise(resolve => child.once('close', () => resolve(true))), new Promise(resolve => setTimeout(() => resolve(false), terminationGraceMs))]);
          let shutdownConfirmed = childClosedInGrace && await waitForProcessGroupExit(processGroupId, terminationGraceMs);
          let processTreeForced = false;
          if (!shutdownConfirmed) {
            processTreeForced = true;
            try {
              if (process.platform === 'linux' && child.pid) process.kill(-child.pid, 'SIGKILL');
              else child.kill('SIGKILL');
            } catch {}
            const childClosedAfterKill = childClosed || await Promise.race([new Promise(resolve => child.once('close', () => resolve(true))),
              new Promise(resolve => setTimeout(() => resolve(false), terminationGraceMs))]);
            shutdownConfirmed = childClosedAfterKill && await waitForProcessGroupExit(processGroupId, terminationGraceMs);
          }
          // A closed launcher process is not proof that Chrome or the JVM exited.
          // Only the process-group probe confirms that no owned descendant remains.
          settle({ timeout: true, shutdownConfirmed, processTreeForced });
        }, timeoutMs);
        timer.unref?.();
        child.once('close', () => clearTimeout(timer));
      });
      exitCode = outcome.code ?? null;
      const childReport = await reportReader(stdout);
      const report = childReport?.report ?? null;
      const evidence = report?.structureCold;
      const rawFailedRequests = Number.isSafeInteger(evidence?.failedInventoryRequestCount) && evidence.failedInventoryRequestCount >= 0
        ? evidence.failedInventoryRequestCount : null;
      const firstPageMs = Number.isFinite(evidence?.firstPageMs) && evidence.firstPageMs >= 0 ? evidence.firstPageMs : null;
      const sourceHeadMatches = !expectedHeadCommit || report?.driverPullRequestHeadCommit === expectedHeadCommit;
      const sourceBaseMatches = !expectedBaseCommit || report?.driverPullRequestBaseCommit === expectedBaseCommit;
      const revisionBinding = report?.sourceIdentity?.revisionBinding;
      const revisionBindingMatches = revisionBinding?.verified === true && revisionBinding.sourceCommit === report?.driverCommit
        && revisionBinding.headCommit === (expectedHeadCommit ?? null) && revisionBinding.baseCommit === (expectedBaseCommit ?? null);
      const browserIdentity = report?.browserIdentity;
      const sourceBrowserLock = report?.sourceIdentity?.files?.find(file => file.path === 'scripts/web-test-browser.json');
      const browserIdentityVerified = browserIdentity?.verified === true && browserIdentity.product === 'chrome'
        && browserIdentity.platform === 'linux64' && /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(browserIdentity.version ?? '')
        && /^[0-9a-f]{64}$/.test(browserIdentity.archiveSha256 ?? '') && /^[0-9a-f]{64}$/.test(browserIdentity.executableSha256 ?? '')
        && /^[0-9a-f]{64}$/.test(browserIdentity.lockSha256 ?? '')
        && sourceBrowserLock?.sha256 === browserIdentity.lockSha256
        && report?.tools?.chromeSha256 === browserIdentity.executableSha256;
      processTreeConfirmed = outcome.shutdownConfirmed ?? (childClosed && processGroupId
        ? await waitForProcessGroupExit(processGroupId, processGroupGraceMs) : false);
      let processTreeForced = outcome.processTreeForced ?? false;
      if (!processTreeConfirmed && childClosed && processGroupId) {
        const forcedCleanupConfirmed = await forceStopProcessGroup(processGroupId, processGroupGraceMs);
        processTreeForced ||= forcedCleanupConfirmed;
        processTreeConfirmed ||= forcedCleanupConfirmed;
      }
      const shutdownConfirmed = processTreeConfirmed;
      const diagnostic = stderr.length ? { byteLength: Buffer.byteLength(stderr), sha256: createHash('sha256').update(stderr).digest('hex') } : null;
      const passed = sourceHeadMatches && sourceBaseMatches && revisionBindingMatches && browserIdentityVerified
        && !interrupted && !timedOut && !processTreeForced
        && exitCode === 0 && report?.status === 'passed' && evidence?.passed === true
        && evidence?.profileApplied === profile.name && rawFailedRequests === 0 && firstPageMs !== null && shutdownConfirmed
        && report?.sourceIdentity?.verified === true && report.sourceIdentity.commit === report.driverCommit;
      samples.push({ index: index + 1, status: passed ? 'passed' : 'failed', profile: profile.name, exitCode, firstPageMs, rawFailedRequests,
        browserHeapBytes: evidence?.browserHeapMemory?.sampledPeakBytes ?? null,
        jvmRssIncrementBytes: evidence?.jvmMemory?.incrementalPeakBytes ?? null,
        profileApplied: evidence?.profileApplied ?? null,
        reportPath: childReport?.path ?? null, reportSha256: childReport?.sha256 ?? null, reportFullSha256: childReport?.fullSha256 ?? null, driverCommit: report?.driverCommit ?? null,
        driverPullRequestHeadCommit: report?.driverPullRequestHeadCommit ?? null,
        driverPullRequestBaseCommit: report?.driverPullRequestBaseCommit ?? null,
        sourceIdentity: report?.sourceIdentity ?? null,
        browserIdentity: browserIdentity ?? null,
        archiveSha256: report?.archiveSha256 ?? null, applicationJarSha256: report?.applicationJarSha256 ?? null,
        testDirectory: report?.testDirectory ?? null, browserProfileDirectory: report?.browserProfileDirectory ?? null,
        runtimeProcesses: report?.runtimeProcesses ?? null,
        shutdownConfirmed, processTreeForced, timedOut, error: outcome.timeout ? 'Cold sample timed out'
          : outcome.error ? String(outcome.error.message).slice(0, 512)
          : !report ? `Child exited with code ${exitCode ?? 'unknown'} without a retained report; primary failure unavailable`
          // A #1882 publication failure leaves a bounded failure record whose facts are scrubbed previews.
          : report.reportPublication?.status === 'failed'
            ? `Child report publication failed; primary failure: ${firstDiagnosticLine(report.error?.preview) ?? 'unavailable'}`
          : !sourceHeadMatches ? 'Child report did not match the declared pull-request head SHA'
          : !sourceBaseMatches ? 'Child report did not match the declared pull-request base SHA'
          : !revisionBindingMatches ? 'Child report did not bind the source commit to the declared pull-request revisions'
          : !browserIdentityVerified ? 'Child report did not verify the reviewed browser installation'
          : evidence?.failures?.[0] ?? (report.status !== 'passed' ? firstDiagnosticLine(report.error) : null) ?? (processTreeForced ? 'Forced process-group kill was required after the packaged driver exited'
            : evidence?.profileApplied !== profile.name ? 'Child report did not confirm the requested profile' : null),
        failureClass: passed ? null : outcome.timeout ? 'timeout' : outcome.error ? 'launch' : !report ? 'report-unavailable'
          : report.reportPublication?.status === 'failed' ? 'report-publication' : 'reported',
        diagnostic });
      if (!shutdownConfirmed) break; // Never overlap another run with an unconfirmed child process tree.
      if (interrupted) break;
    } catch (error) {
      let catchTreeForced = false;
      if (!processTreeConfirmed && processGroupId) {
        processTreeConfirmed = await waitForProcessGroupExit(processGroupId, 10_000).catch(() => false);
        if (!processTreeConfirmed) {
          catchTreeForced = await forceStopProcessGroup(processGroupId).catch(() => false);
          processTreeConfirmed = catchTreeForced;
        }
      }
      samples.push({ index: index + 1, status: 'failed', profile: profile.name, exitCode, firstPageMs: null,
        rawFailedRequests: null, shutdownConfirmed: processTreeConfirmed, timedOut, error: String(error.message).slice(0, 512),
        processTreeForced: catchTreeForced,
        diagnostic: stderr.length ? { byteLength: Buffer.byteLength(stderr), sha256: createHash('sha256').update(stderr).digest('hex') } : null });
      if (!processTreeConfirmed) break;
    } finally { activeChild = null; }
  }
  } finally {
    process.removeListener('SIGTERM', interrupt);
    process.removeListener('SIGINT', interrupt);
  }
  if (samples.length < count) {
    for (let index = samples.length; index < count; index++) samples.push({ index: index + 1, status: 'not-run', profile: profile.name,
      exitCode: null, firstPageMs: null, rawFailedRequests: null, shutdownConfirmed: false,
      error: interrupted ? `Cold sample run interrupted by ${interrupted}` : 'Prior sample process tree shutdown was unconfirmed' });
  }
  const summary = summarizeColdSamples(samples);
  const identities = samples.filter(sample => sample.status === 'passed')
    .map(sample => [sample.driverCommit, sample.driverPullRequestHeadCommit ?? sample.driverCommit,
      sample.driverPullRequestBaseCommit ?? 'unspecified', sample.sourceIdentity?.sourceSha256,
      sample.browserIdentity?.version, sample.browserIdentity?.archiveSha256, sample.browserIdentity?.executableSha256,
      sample.browserIdentity?.lockSha256, sample.archiveSha256, sample.applicationJarSha256]);
  const identityConsistent = identities.length === count && identities.every(identity => identity.every(Boolean)
    && identity.every((value, index) => value === identities[0][index]));
  const directories = samples.map(sample => sample.testDirectory);
  const runDirectoriesUnique = directories.every(Boolean) && new Set(directories).size === count;
  const processIdentities = samples.map(sample => sample.runtimeProcesses).filter(Boolean)
    .map(value => `${value.applicationPid}:${value.applicationStartTimeTicks}:${value.browserPid}:${value.browserStartTimeTicks}`);
  const processIdentitiesPresent = samples.every(sample => Number.isSafeInteger(sample.runtimeProcesses?.applicationPid)
    && sample.runtimeProcesses.applicationPid > 0 && Number.isSafeInteger(sample.runtimeProcesses?.applicationStartTimeTicks)
    && sample.runtimeProcesses.applicationStartTimeTicks > 0 && Number.isSafeInteger(sample.runtimeProcesses?.browserPid)
    && sample.runtimeProcesses.browserPid > 0 && Number.isSafeInteger(sample.runtimeProcesses?.browserStartTimeTicks)
    && sample.runtimeProcesses.browserStartTimeTicks > 0
    && sample.browserProfileDirectory && sample.testDirectory && sample.browserProfileDirectory.startsWith(sample.testDirectory + '/'));
  const processIdentitiesUnique = processIdentities.length === count && new Set(processIdentities).size === count;
  return { profile: profile.name, firstPageLimitMs: profile.firstPageLimitMs, expectedHeadCommit, expectedBaseCommit, ...summary, identityConsistent,
    runDirectoriesUnique, processIdentitiesPresent, processIdentitiesUnique,
    overBudgetSamples: samples.filter(sample => Number.isFinite(sample.firstPageMs) && sample.firstPageMs > profile.firstPageLimitMs)
      .map(sample => ({ index: sample.index, firstPageMs: sample.firstPageMs })),
    passed: summary.successfulSamples === count && summary.rawFailedRequests === 0 && identityConsistent && runDirectoriesUnique
      && processIdentitiesPresent && processIdentitiesUnique
      && Number.isFinite(summary.nearestRankP95FirstPageMs) && summary.nearestRankP95FirstPageMs <= profile.firstPageLimitMs };
}

function firstDiagnosticLine(value) {
  if (typeof value !== 'string') return null;
  const line = value.slice(0, 1024).split('\n').find(part => part.trim());
  return line ? line.trim().slice(0, 512) : null;
}

const reportDigest = bytes => createHash('sha256').update(bytes).digest('hex');

/**
 * Reads a child's report. When #1882 publication moved facts out of report.json into digest references, the full
 * scrubbed report is rebuilt from its parts and bound back to report.json, so aggregation never reads structureCold or
 * any other field from a reference (R5). Every inconsistency throws, which fails that sample.
 */
export async function readChildReport(stdout, { readFile = fs.readFile } = {}) {
  const match = stdout.match(/Report: (.+\/report\.json)\s*$/m);
  if (!match) return null;
  const path = resolve(match[1]);
  const bytes = await readFile(path);
  if (bytes.length > MAX_REPORT_BYTES) throw new Error('Child report.json exceeds its published byte bound');
  const primary = JSON.parse(bytes.toString('utf8'));
  if (!primary || typeof primary !== 'object' || Array.isArray(primary)) throw new Error('Child report.json is not a report object');
  if (!Object.hasOwn(primary, 'reportEvidence')) return { path, report: primary, sha256: reportDigest(bytes) };
  const { report, fullSha256 } = await reconstructChildReport(dirname(path), primary, readFile);
  return { path, report, sha256: reportDigest(bytes), fullSha256 };
}

async function reconstructChildReport(directory, primary, readFile) {
  const fail = (message) => { throw new Error(`Child report parts are inconsistent: ${message}`); };
  const evidence = primary.reportEvidence;
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) fail('reportEvidence is not an object');
  const { parts, bytes: fullLength, sha256: fullSha256, referencedKeys } = evidence;
  if (evidence.partBytes !== REPORT_PART_BYTES || evidence.maxParts !== MAX_REPORT_PARTS || evidence.primaryMaxBytes !== MAX_REPORT_BYTES) {
    fail('unexpected publication limits');
  }
  if (!Number.isSafeInteger(fullLength) || fullLength <= MAX_REPORT_BYTES || fullLength > REPORT_PART_BYTES * MAX_REPORT_PARTS) fail('full size');
  if (!/^[0-9a-f]{64}$/.test(fullSha256 ?? '')) fail('full digest');
  if (!Array.isArray(parts) || parts.length !== Math.ceil(fullLength / REPORT_PART_BYTES)) fail('part count');
  const chunks = [];
  let offset = 0;
  for (const [index, part] of parts.entries()) {
    // Names are checked before any read, so a part can never name a path outside the report directory.
    if (part?.file !== `report.full.part-${String(index).padStart(3, '0')}`) fail(`part ${index} name`);
    if (part.bytes !== Math.min(REPORT_PART_BYTES, fullLength - offset) || !/^[0-9a-f]{64}$/.test(part.sha256 ?? '')) fail(`part ${index} size`);
    const data = await readFile(join(directory, part.file));
    if (data.length !== part.bytes || reportDigest(data) !== part.sha256) fail(`part ${index} bytes`);
    chunks.push(data);
    offset += data.length;
  }
  const fullBytes = Buffer.concat(chunks);
  if (fullBytes.length !== fullLength || reportDigest(fullBytes) !== fullSha256) fail('reassembled bytes');
  const report = JSON.parse(fullBytes.toString('utf8'));
  if (!report || typeof report !== 'object' || Array.isArray(report) || Object.hasOwn(report, 'reportEvidence')) fail('full report shape');
  // report.json must be exactly the full report with only its listed keys replaced by their digest references.
  const keys = Object.keys(primary).filter(key => key !== 'reportEvidence');
  if (JSON.stringify(keys) !== JSON.stringify(Object.keys(report))) fail('top-level keys');
  if (!Array.isArray(referencedKeys) || new Set(referencedKeys).size !== referencedKeys.length
    || referencedKeys.some(key => key === 'status' || !keys.includes(key))) fail('referenced keys');
  for (const key of keys) {
    const valueBytes = Buffer.from(JSON.stringify(report[key]), 'utf8');
    if (referencedKeys.includes(key)) {
      const reference = primary[key];
      if (reference?.reportEvidence !== key || reference.bytes !== valueBytes.length || reference.sha256 !== reportDigest(valueBytes)
        || Object.keys(reference).length !== 3) fail(`reference ${key}`);
    } else if (JSON.stringify(primary[key]) !== JSON.stringify(report[key])) fail(`inline ${key}`);
  }
  return { report, fullSha256 };
}

export async function writeColdAggregate(path, result) {
  const bytes = Buffer.from(JSON.stringify(result, null, 2) + '\n');
  await fs.writeFile(path, bytes, { flag: 'wx', mode: 0o600 });
  return createHash('sha256').update(bytes).digest('hex');
}

async function main() {
  const args = process.argv.slice(2);
  if (args[0] !== '--run') return;
  const profile = args[1];
  const separator = args.indexOf('--');
  if (separator < 0 || separator + 1 >= args.length) throw new Error('Usage: run-packaged-browser-structure-cold.mjs --run loopback|constrained -- <driver args>');
  const driver = resolve(args[separator + 1]);
  const driverArgs = args.slice(separator + 2);
  const result = await runColdSamples({ driver, driverArgs, profile });
  const root = resolve(process.env.STRUCTURE_COLD_REPORT_DIR ?? 'build');
  await fs.mkdir(root, { recursive: true });
  const path = resolve(root, `program-structure-cold-${profile}-${Date.now()}-${randomUUID()}.json`);
  result.aggregateReport = basename(path);
  result.aggregateSha256 = await writeColdAggregate(path, result);
  console.log(JSON.stringify({ ...result, aggregatePath: path }, null, 2));
  if (!result.passed) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => { console.error(String(error?.stack ?? error).slice(0, 4096)); process.exitCode = 1; });
}

// The caller supplies the retained stderr tail. IDs stay decimal strings across the JVM/JS boundary.
export function structureServerTimingSummary(output) {
  const limit = 512;
  const timings = [], manifestStages = [], terminals = [];
  let overflow = 0, manifestOverflow = 0, terminalOverflow = 0;
  const phases = /^web-structure-timing phase=([a-z0-9-]{1,64}) elapsedNanos=(\d{1,19})(?: invocationId=([1-9]\d{0,18}))?\r?$/gm;
  for (const [,phase,duration,invocationId] of output.matchAll(phases)) {
    const elapsedNanos = Number(duration);
    if (timings.length === limit || !Number.isSafeInteger(elapsedNanos)) { overflow++; continue; }
    timings.push(invocationId ? { phase, elapsedNanos, invocationId } : { phase, elapsedNanos });
  }
  const stages = /^web-structure-manifest-timing stage=(manifest-(?:root|file-fields|file-evidence-init|path-order|construct|profile-policy)) elapsedNanos=(\d{1,19}) segments=([1-9]\d{0,18}) invocationId=([1-9]\d{0,18})\r?$/gm;
  for (const [,stage,duration,count,invocationId] of output.matchAll(stages)) {
    const elapsedNanos = Number(duration), segments = Number(count);
    if (manifestStages.length === limit || !Number.isSafeInteger(elapsedNanos) || !Number.isSafeInteger(segments)) {
      manifestOverflow++;
      continue;
    }
    manifestStages.push({ stage, elapsedNanos, segments, invocationId });
  }
  const outcomes = /^web-structure-timing-terminal invocationId=([1-9]\d{0,18}) status=(ok|failed|refused|interrupted|cancelled)\r?$/gm;
  for (const [,invocationId,status] of output.matchAll(outcomes)) {
    if (terminals.length === limit) { terminalOverflow++; continue; }
    terminals.push({ invocationId, status });
  }
  return { timings, limit, overflow, manifestStages, manifestLimit: limit, manifestOverflow,
    terminals, terminalLimit: limit, terminalOverflow };
}
