import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { promises as fs, readFileSync, createReadStream } from 'node:fs';
import { join, basename, dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { createServer as createHttpServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { qualifyUpload, qualifyUploadFailures, qualifyMeasuredUpload } from './packaged-browser-upload.mjs';
import { seedScale, qualifyScale, dashboardFiltersWithSnapshot } from './packaged-browser-scale.mjs';
import { seedSourceTreeFixture } from './packaged-source-tree-fixture.mjs';
import { qualifySourceTree, qualifySourceTreeColdPage } from './packaged-browser-source-tree.mjs';
import { SOURCE_TREE_COLD_SAMPLE_COUNT, summarizeSourceTreeColdSamples } from './packaged-browser-source-tree-cold.mjs';
import { seedLive, qualifyLive } from './packaged-browser-live.mjs';
import { seedHistory, qualifyHistory } from './packaged-browser-history.mjs';
import { seedLegacy, qualifyLegacy } from './packaged-browser-legacy.mjs';
import { qualifyRestart, assertGracefulShutdown, scrubTokens, boundReport } from './packaged-browser-restart.mjs';
import { qualifyUpgrade, qualifyUpgradeCache } from './packaged-browser-upgrade.mjs';
import { qualifyAudit, assertAudit } from './packaged-browser-audit.mjs';
import { PackagedBrowserCdpDiagnostics } from './packaged-browser-cdp-diagnostics.mjs';

// Test driver only: the application is launched with a separate Node-free PATH.
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { values } = parseArgs({ options: {
  archive: { type: 'string' },
  'previous-archive': { type: 'string' },
  mode: { type: 'string', default: 'public' },
  profile: { type: 'string', default: 'loopback' },
  'work-parent': { type: 'string', default: join(repo, 'build') },
  'keep-workdir': { type: 'boolean', default: false },
  chrome: { type: 'string' },
  'java-home': { type: 'string' },
  python: { type: 'string', default: '/usr/bin/python3' },
  'no-sandbox': { type: 'boolean', default: false },
  'cold-report': { type: 'string' },
  help: { type: 'boolean', default: false },
} });
if (values.help) {
  console.log('Usage: node scripts/check-packaged-web-browser.mjs --archive /absolute/distribution.zip --chrome /absolute/chrome --java-home /absolute/jdk [--mode public|session|upload|metadata|history|restart|scale|source-tree|live|proxy|upgrade|legacy|audit] [--profile loopback|constrained] [--previous-archive /absolute/previous.zip] [--work-parent /absolute/scratch] [--keep-workdir] [--python /absolute/python3] [--no-sandbox]');
  console.log('restart: seeded history on one JVM, graceful SIGTERM-only restart on the same installation/data/port, fresh bootstrap and serverInstanceId, then two tabs with a progress-pin stale If-Match 412. No live worker, no restart-while-running, one Chromium only.');
  console.log('public: packaged home/Runtime/recovery; session: public plus local session journey; upload: session plus inert upload and lost-response retry; history: session plus preseeded inert multi-page attempts; scale: session plus 10,000 persisted jobs and keyboard pagination; proxy: real Vite HMR and session journey against packaged JVM; upgrade: previous JVM to current JVM on one origin with an old tab.');
  console.log('legacy: inert legacy HTML/polling with explicit test-owned state edits; no workflow execution.');
  console.log('audit: every route at 1440x900, 390x844, 320px and 200%/400% zoom in light/dark themes with contract-fixture API reads fulfilled in DevTools; measures reflow, text/focus contrast, target size, reduced motion, every packaged asset under CSP and navigation timing budgets.');
  console.log('metadata: session plus one inert header upload/retry, real packaged job metadata, maximum uint64 address, and simulated malformed-response recovery; no workflow execution or upload quota/scale measurement.');
  console.log('live: session plus authored inert job changes and real background listing reads; preserves focused row order and applies new jobs on explicit refresh.');
  console.log('upgrade requires --previous-archive and distinct manifest builds with the old Runtime chunk absent from --archive. Its previous extraction is always removed before the current extraction, even with --keep-workdir.');
  console.log('Reports/screenshots stay in build/. Owned extraction/profile/socket directories are removed after confirmed shutdown unless --keep-workdir is set. Proxy requires npm ci --ignore-scripts under the pinned Node beforehand.');
  process.exit(0);
}
const nodeVersion = process.versions.node;
const expectedNode = readFileSync(join(repo, '.node-version'), 'utf8').trim();
assert.equal(nodeVersion, expectedNode, `Use the pinned test-driver Node ${expectedNode}`);
for (const option of ['archive', 'chrome', 'java-home', 'python']) {
  assert.ok(values[option] && isAbsolute(values[option]), `--${option} must name an absolute existing path; see --help`);
  await fs.access(values[option]);
}
assert.ok(['public', 'session', 'upload', 'metadata', 'history', 'restart', 'scale', 'source-tree', 'source-tree-cold-worker', 'live', 'proxy', 'upgrade', 'legacy', 'audit'].includes(values.mode), '--mode must be a supported packaged browser mode');
if (values.mode === 'source-tree' || values.mode === 'source-tree-cold-worker') assert.ok(['loopback', 'constrained'].includes(values.profile), '--profile must be loopback or constrained for source-tree mode');
if (values.mode === 'source-tree') {
  assert.equal(process.env.DECOMP_PACKAGED_SOURCE_TREE_SUPERVISED, '1',
    'Use run-packaged-browser-source-tree-supervised.mjs so the complete cold and warm process tree is owned');
}
if (values['cold-report']) assert.ok(isAbsolute(values['cold-report']), '--cold-report must be an absolute path');
if (values.mode === 'source-tree-cold-worker') assert.ok(values['cold-report'], 'cold worker mode is internal and requires --cold-report');
if (values.mode === 'upgrade') {
  assert.ok(values['previous-archive'] && isAbsolute(values['previous-archive']), 'upgrade requires --previous-archive as an absolute existing ZIP path');
  await fs.access(values['previous-archive']);
} else assert.equal(values['previous-archive'], undefined, '--previous-archive is only supported with --mode upgrade');
assert.ok(isAbsolute(values['work-parent']), '--work-parent must be an absolute directory');
const archive = values.archive;
const javaHome = values['java-home'];
const chromeBinary = values.chrome;
await fs.mkdir(join(repo, 'build'), { recursive: true });
const buildRoot = await fs.realpath(join(repo, 'build'));
const buildRootRelative = relative(repo, buildRoot);
assert.ok(buildRootRelative !== '..' && !buildRootRelative.startsWith(`..${sep}`) && !isAbsolute(buildRootRelative),
  'Repository build directory must resolve inside the repository');
assert.ok((await fs.stat(values['work-parent'])).isDirectory(), '--work-parent must already exist');
if (values.mode === 'proxy') await fs.access(join(repo, 'frontend/node_modules/vite/bin/vite.js'));
const sensitiveValues = [];
const safeDiagnostic = (value) => {
  let safe = String(value).replaceAll(/#bootstrap=[A-Za-z0-9_-]+/g, '#bootstrap=[redacted]');
  for (const sensitive of sensitiveValues) if (sensitive) safe = safe.replaceAll(sensitive, '[redacted]');
  return safe;
};
const safeEvidence = (value) => {
  if (Array.isArray(value)) return value.map(safeEvidence);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, safeEvidence(item)]));
  return typeof value === 'string' ? safeDiagnostic(value) : value;
};
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function fileHash(path) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest('hex');
}
async function javaRuntimeHashes(home) {
  return {
    javaSha256: await fileHash(join(home, 'bin/java')),
    javaModulesSha256: await fileHash(join(home, 'lib/modules')),
    javaReleaseSha256: await fileHash(join(home, 'release')),
  };
}
const root = await fs.mkdtemp(join(values['work-parent'], 'packaged-browser-'));
let application;
let browser;
let browserStartupMs = null;
let vite;
let work;
let browserTmp;
let lastTarget;
const targets = [];
const cdpDiagnostics = new PackagedBrowserCdpDiagnostics();
const profile = join(root, 'browser profile');
const ownerToken = randomUUID();
const installHelper = join(repo, 'scripts/packaged-browser-install.py');
const sourceTreeDriverFiles = [
  'scripts/check-packaged-web-browser.mjs',
  'scripts/packaged-browser-upload.mjs',
  'scripts/packaged-browser-scale.mjs',
  'scripts/packaged-browser-contrast.mjs',
  'scripts/packaged-source-tree-fixture.mjs',
  'scripts/packaged-browser-source-tree.mjs',
  'scripts/packaged-browser-source-tree-cold.mjs',
  'scripts/packaged-browser-live.mjs',
  'scripts/packaged-browser-history.mjs',
  'scripts/packaged-browser-legacy.mjs',
  'scripts/packaged-browser-restart.mjs',
  'scripts/packaged-browser-upgrade.mjs',
  'scripts/packaged-browser-audit.mjs',
  'scripts/packaged-browser-cdp-diagnostics.mjs',
  'scripts/packaged-browser-process-supervisor.py',
  'scripts/run-packaged-browser-source-tree-supervised.mjs',
  'scripts/packaged-browser-install.py',
];
let sourceTreeColdSummary = null;
let checkoutCommit = null;
let checkoutParents = null;
let sourceTreeWorktreeClean = null;
try {
  const checkoutRoot = resolve(execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd: repo, encoding: 'utf8', maxBuffer: 1024 }).trim());
  if (checkoutRoot === repo) {
    checkoutCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8', maxBuffer: 1024 }).trim();
    const commit = execFileSync('git', ['cat-file', '-p', checkoutCommit], { cwd: repo, encoding: 'utf8', maxBuffer: 1024 * 1024 });
    checkoutParents = commit.split('\n').filter(line => line.startsWith('parent ')).map(line => line.slice('parent '.length));
    sourceTreeWorktreeClean = execFileSync('git', ['status', '--porcelain', '--untracked-files=all'],
      { cwd: repo, encoding: 'utf8', maxBuffer: 1024 * 1024 }).trim() === '';
  }
} catch { /* An extracted source archive has no Git metadata; retain the driver hashes below. */ }
if (!checkoutCommit && process.env.GITHUB_SHA && /^[0-9a-f]{40}$/i.test(process.env.GITHUB_SHA)) checkoutCommit = process.env.GITHUB_SHA;
if (checkoutCommit && process.env.GITHUB_SHA && /^[0-9a-f]{40}$/i.test(process.env.GITHUB_SHA)) {
  assert.equal(checkoutCommit, process.env.GITHUB_SHA, 'Checked-out source commit differs from the workflow commit');
  assert.equal(sourceTreeWorktreeClean, true, 'Packaged browser qualification requires the workflow checkout to be clean');
}
let pullRequestIdentity = null;
try {
  if (process.env.GITHUB_EVENT_PATH) {
    const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
    const pullRequest = event.pull_request;
    if (pullRequest?.head?.sha && pullRequest?.base?.sha) pullRequestIdentity = {
      headSha: pullRequest.head.sha, baseSha: pullRequest.base.sha,
      mergeSha: process.env.GITHUB_SHA ?? null,
    };
  }
} catch { /* Workflow payload attribution is optional outside GitHub Actions. */ }
let cdp;
let applicationError = '';
let applicationOutput = '';
let applicationStartupMs = null;
let browserError = '';
let viteError = '';
const report = { status: 'running', mode: values.mode, ...(['source-tree', 'source-tree-cold-worker'].includes(values.mode) ? { profile: values.profile } : {}), testDirectory: root, driverNode: nodeVersion,
  driverCommit: checkoutCommit, checkoutParents, workflowSha: process.env.GITHUB_SHA ?? null,
  pullRequestIdentity, sourceTreeWorktreeClean,
  ...(['source-tree', 'source-tree-cold-worker'].includes(values.mode) ? { sourceTreeDriverSha256: Object.fromEntries(sourceTreeDriverFiles.map(path =>
    [path, createHash('sha256').update(readFileSync(join(repo, path))).digest('hex')])) } : {}),
  tools: { node: process.execPath, chrome: chromeBinary, javaHome, python: values.python }, requests: {} };
const launchErrors = new WeakMap();
console.log(`Evidence directory: ${root}`);
let activeColdSupervisor = null;
let externalCancellation = null;
let finalReportWritten = false;
const coldSampleRecords = [];
let coldSupervisorLaunched = false;
let coldSupervisorCleanupConfirmed = true;
let sourceTreeRequestEvidencePromise = null;
async function externalizeSourceTreeRequestEvidence() {
  if (sourceTreeRequestEvidencePromise) return sourceTreeRequestEvidencePromise;
  const routeRequests = report.sourceTreeScale?.requests;
  if (report.mode !== 'source-tree' || !routeRequests || typeof routeRequests !== 'object') return null;
  sourceTreeRequestEvidencePromise = (async () => {
    const file = 'source-tree-scale-evidence.json';
    const coldSummary = report.sourceTreeColdSamples;
    if (!coldSummary || !Array.isArray(coldSummary.samples)) {
      const counts = Object.fromEntries(Object.entries(routeRequests).map(([route, entries]) =>
        [route, Array.isArray(entries) ? entries.length : null]));
      report.status = 'failed';
      report.sourceTreeScale.requests = { counts, artifact: null };
      report.sourceTreeEvidenceRetention = { confirmed: false, reason: 'cold-sample-records-missing',
        routeCounts: counts, completeSamplesRetained: false };
      process.exitCode = 1;
      return null;
    }
    const evidence = {
      schema: 'decompengine.packaged-source-tree-scale-evidence.v1',
      driverCommit: report.driverCommit,
      workflowSha: report.workflowSha,
      profile: report.profile,
      fixture: report.sourceTreeScale.fixture,
      runtime: {
        archiveSha256: report.archiveSha256, applicationJarSha256: report.applicationJarSha256,
        buildId: report.buildId, browserProduct: report.browser?.product ?? null,
        chromeSha256: report.tools.chromeSha256, javaSha256: report.tools.javaSha256,
        javaModulesSha256: report.tools.javaModulesSha256, javaReleaseSha256: report.tools.javaReleaseSha256,
        checkoutParents: report.checkoutParents, pullRequestIdentity: report.pullRequestIdentity,
        sourceTreeDriverSha256: report.sourceTreeDriverSha256,
      },
      requests: routeRequests,
      coldSamples: coldSummary.samples,
    };
    const safeEvidence = scrubTokens(evidence, sensitiveValues);
    const bytes = Buffer.from(`${JSON.stringify(safeEvidence, null, 2)}\n`, 'utf8');
    const counts = Object.fromEntries(Object.entries(routeRequests).map(([route, entries]) =>
      [route, Array.isArray(entries) ? entries.length : null]));
    const coldFailures = coldSummary.samples.filter(sample => sample.status !== 'passed').map(sample => ({
      index: sample.index, status: sample.status,
      cleanup: sample.cleanup?.cleanup ?? 'unavailable',
      cleanupScanIncomplete: sample.cleanup?.cleanupScanIncomplete ?? true,
      survivors: sample.cleanup?.survivors ?? null,
      outerSupervisor: sample.outerSupervisor ? {
        timeout: sample.outerSupervisor.timeout, supervisorExited: sample.outerSupervisor.supervisorExited,
        cleanupConfirmed: sample.outerSupervisor.cleanupConfirmed,
        exitCode: sample.outerSupervisor.exitCode, signal: sample.outerSupervisor.signal,
        error: sample.outerSupervisor.error ?? null,
      } : null,
      worker: sample.worker ? { status: sample.worker.status, error: sample.worker.error ?? null } : null,
    }));
    const maximumBytes = 8 * 1024 * 1024;
    const retainFailureSummary = (reason, error = null) => {
      report.status = 'failed';
      report.sourceTreeEvidenceRetention = { confirmed: false, reason,
        observedBytes: bytes.length, maximumBytes, routeCounts: counts,
        ...(error ? { error: safeDiagnostic(error?.message ?? String(error)) } : {}),
        completeSamplesRetained: false, sampleCount: coldSummary.samples.length };
      report.sourceTreeScale.requests = { counts, artifact: null };
      report.sourceTreeColdSamples = {
        profile: coldSummary.profile, definition: coldSummary.definition,
        filesystemState: coldSummary.filesystemState, sampleCount: coldSummary.sampleCount,
        medianMs: coldSummary.medianMs, nearestRankP95Ms: coldSummary.nearestRankP95Ms,
        gate: { ...coldSummary.gate, passed: false }, failedAttempts: coldFailures,
        samplesArtifact: null,
      };
      process.exitCode = 1;
      return null;
    };
    if (bytes.length > maximumBytes) {
      return retainFailureSummary('evidence-artifact-exceeded-byte-bound');
    }
    const path = join(root, file);
    try { await fs.writeFile(path, bytes, { flag: 'wx', mode: 0o600 }); }
    catch (error) { return retainFailureSummary('evidence-artifact-write-failed', error); }
    const reference = { file, bytes: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex'), counts,
      schema: evidence.schema, retention: 'complete-request-and-cold-sample-records-in-separate-byte-bounded-artifact' };
    report.sourceTreeScale.requests = { artifact: file, bytes: reference.bytes, sha256: reference.sha256, counts };
    report.sourceTreeScale.requestEvidence = reference;
    report.sourceTreeColdSamples = {
      profile: coldSummary.profile, definition: coldSummary.definition,
      filesystemState: coldSummary.filesystemState, sampleCount: coldSummary.sampleCount,
      medianMs: coldSummary.medianMs, nearestRankP95Ms: coldSummary.nearestRankP95Ms,
      gate: coldSummary.gate, failedAttempts: coldFailures,
      samplesArtifact: { file, bytes: reference.bytes, sha256: reference.sha256,
        sampleCount: coldSummary.samples.length, completeRawSamples: true },
    };
    return reference;
  })();
  return sourceTreeRequestEvidencePromise;
}
async function writeCancelledReport() {
  await externalizeSourceTreeRequestEvidence().catch(() => null);
  const cancelledReport = scrubTokens(boundReport(report), sensitiveValues);
  const writes = [fs.writeFile(join(root, 'report.json'), JSON.stringify(cancelledReport, null, 2) + '\n')];
  if (values['cold-report']) writes.push(fs.writeFile(values['cold-report'], JSON.stringify(cancelledReport, null, 2) + '\n'));
  await Promise.all(writes).catch(() => { process.exitCode = 1; });
}
function onSourceTreeCancellation(signal) {
  if (values.mode !== 'source-tree' || externalCancellation) return;
  externalCancellation = signal;
  report.status = 'failed';
  report.externalCancellation = signal;
  process.exitCode = 1;
  if (finalReportWritten) void writeCancelledReport();
  if (activeColdSupervisor) {
    activeColdSupervisor.kill(signal);
    return;
  }
  for (const child of [browser, application, vite]) {
    if (child && child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
  }
  try { cdp?.socket.close(); } catch { /* The main finally path records bounded cleanup. */ }
}
if (values.mode === 'source-tree') {
  process.on('SIGTERM', () => onSourceTreeCancellation('SIGTERM'));
  process.on('SIGINT', () => onSourceTreeCancellation('SIGINT'));
}

function startOwned(command, args, options) {
  const child = spawn(command, args, options);
  child.on('error', (error) => launchErrors.set(child, error));
  return child;
}

async function processIdentity(pid) {
  const stat = await fs.readFile(`/proc/${pid}/stat`);
  const close = stat.lastIndexOf(0x29);
  assert.ok(close >= 0, 'Could not read process start identity');
  const fields = stat.subarray(close + 2).toString('ascii').trim().split(/\s+/u);
  assert.ok(fields.length > 19, 'Process identity record was truncated');
  const startTicks = Number(fields[19]);
  assert.ok(Number.isSafeInteger(startTicks) && startTicks >= 0, 'Process start identity was invalid');
  const processName = stat.subarray(1, close).toString('utf8');
  const executable = basename(await fs.readlink(`/proc/${pid}/exe`));
  return { pid, startTicks, processName, executable };
}

async function javaProcessIdentity(launcherPid) {
  const entries = (await fs.readdir('/proc')).filter(name => /^[1-9][0-9]*$/u.test(name)).map(Number);
  const parents = new Map();
  const names = new Map();
  await Promise.all(entries.map(async pid => {
    try {
      const stat = await fs.readFile(`/proc/${pid}/stat`);
      const close = stat.lastIndexOf(0x29);
      if (close < 0) return;
      const fields = stat.subarray(close + 2).toString('ascii').trim().split(/\s+/u);
      if (fields.length > 19) { parents.set(pid, Number(fields[1])); names.set(pid, stat.subarray(1, close).toString('utf8')); }
    } catch { /* Processes can exit while the observation snapshot is collected. */ }
  }));
  const descendants = new Set([launcherPid]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [pid, parent] of parents) if (descendants.has(parent) && !descendants.has(pid)) {
      descendants.add(pid);
      changed = true;
    }
  }
  const candidates = [];
  for (const pid of descendants) {
    try {
      const executable = basename(await fs.readlink(`/proc/${pid}/exe`));
      if (names.get(pid) === 'java' || /^java(?:[0-9.]*)?$/iu.test(executable)) candidates.push(await processIdentity(pid));
    } catch { /* A transient exit is not a JVM identity. */ }
  }
  assert.equal(candidates.length, 1, 'The packaged launcher must own exactly one identifiable Java process');
  return candidates[0];
}

async function waitFor(check, label, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    for (const child of [application, browser, vite]) {
      if (child && launchErrors.has(child)) throw launchErrors.get(child);
    }
    const value = await check();
    if (value) return value;
    await delay(75);
  }
  throw new Error(`Timed out waiting for ${label}`);
}

async function runSourceTreeColdSamples(expected) {
  const samples = coldSampleRecords;
  const sampleRoot = join(root, 'source-tree-cold-samples');
  await fs.mkdir(sampleRoot);
  let abortReason = null;
  try {
  for (let index = 0; index < SOURCE_TREE_COLD_SAMPLE_COUNT; index++) {
    if (externalCancellation) { abortReason ??= 'cancelled-before-next-sample'; break; }
    const sampleDirectory = join(sampleRoot, `sample-${String(index + 1).padStart(2, '0')}`);
    await fs.mkdir(sampleDirectory);
    const workerWorkParent = join(sampleDirectory, 'worker-owned-files');
    await fs.mkdir(workerWorkParent);
    const workerReport = join(sampleDirectory, 'worker-report.json');
    const receiptPath = join(sampleDirectory, 'supervisor-receipt.json');
    const supervisorDiagnosticPath = join(sampleDirectory, 'supervisor-diagnostic.log');
    const driverPath = fileURLToPath(import.meta.url);
    const supervisorPath = join(repo, 'scripts/packaged-browser-process-supervisor.py');
    const workerArgs = [driverPath, '--archive', archive, '--chrome', chromeBinary, '--java-home', javaHome,
      '--python', values.python, '--work-parent', workerWorkParent, '--mode', 'source-tree-cold-worker',
      '--profile', values.profile, '--cold-report', workerReport, '--keep-workdir'];
    if (values['no-sandbox']) workerArgs.push('--no-sandbox');
    const commandArgs = [supervisorPath, '--receipt', receiptPath, '--execution-timeout-seconds', '180', '--', process.execPath, ...workerArgs];
    let diagnosticHandle;
    let child;
    let diagnosticCloseError = null;
    try {
      diagnosticHandle = await fs.open(supervisorDiagnosticPath, 'wx', 0o600);
      child = spawn(values.python, commandArgs, { cwd: repo, env: process.env,
        stdio: ['ignore', 'ignore', diagnosticHandle.fd] });
    } catch (error) {
      await diagnosticHandle?.close().catch(() => {});
      samples.push({ index: index + 1, status: 'failed', result: null,
        cleanup: { cleanup: 'not-started', cleanupScanIncomplete: false, survivors: [] },
        identityMatchesOuterRun: false,
        outerSupervisor: { timeout: false, supervisorExited: true, cleanupConfirmed: true,
          retainedAsCleanupOwner: false, exitCode: null, signal: null,
          error: safeDiagnostic(error.message), diagnostic: null },
        worker: { status: null, exitCode: null, signal: null,
          error: safeDiagnostic(error.message), report: basename(workerReport) } });
      report.sourceTreeColdSamples = summarizeSourceTreeColdSamples(samples, values.profile);
      abortReason = `cold-sample-${index + 1}-supervisor-launch-failed`;
      break;
    }
    activeColdSupervisor = child;
    coldSupervisorLaunched = true;
    coldSupervisorCleanupConfirmed = false;
    if (externalCancellation) child.kill(externalCancellation);
    const closed = new Promise(resolve => {
      child.once('error', error => resolve({ code: null, signal: null, error: safeDiagnostic(error.message) }));
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
    try { await diagnosticHandle.close(); }
    catch (error) { diagnosticCloseError = safeDiagnostic(error.message); }
    const waitForClose = milliseconds => new Promise(resolve => {
      const timer = setTimeout(() => resolve(null), milliseconds);
      closed.then(value => { clearTimeout(timer); resolve(value); });
    });
    let exit = await waitForClose(225_000); // 180-second worker deadline plus cleanup/report allowance.
    let outerTimedOut = false;
    if (!exit) {
      outerTimedOut = true;
      child.kill('SIGTERM');
      exit = await waitForClose(40_000);
    }
    if (!exit) {
      let escalationReceipt = null;
      try { escalationReceipt = JSON.parse(await fs.readFile(receiptPath, 'utf8')); } catch { /* No proof means keep the only cleanup owner alive. */ }
      const descendantsConfirmedGone = escalationReceipt && !escalationReceipt.cleanupScanIncomplete
        && (escalationReceipt.survivors?.length ?? 0) === 0
        && ['clean', 'terminated-leaked'].includes(escalationReceipt.cleanup);
      if (descendantsConfirmedGone) {
        child.kill('SIGKILL');
        exit = await waitForClose(5_000);
      }
    }
    const outerCleanupConfirmed = !!exit;
    if (!outerCleanupConfirmed) child.unref(); // It remains the live subreaper/cleanup owner; never orphan its descendants.
    exit ??= { code: null, signal: null, error: 'supervisor-did-not-exit-after-outer-escalation' };
    if (outerCleanupConfirmed) activeColdSupervisor = null;
    let receipt = null;
    let worker = null;
    try { receipt = JSON.parse(await fs.readFile(receiptPath, 'utf8')); } catch { /* Retain a missing/malformed receipt as a failed attempt. */ }
    try { worker = JSON.parse(await fs.readFile(workerReport, 'utf8')); } catch { /* Retain a missing/malformed report as a failed attempt. */ }
    let supervisorDiagnostic = null;
    try {
      const info = await fs.stat(supervisorDiagnosticPath);
      const handle = await fs.open(supervisorDiagnosticPath, 'r');
      try {
        const length = Math.min(info.size, 65_536);
        const buffer = Buffer.alloc(length);
        await handle.read(buffer, 0, length, Math.max(0, info.size - length));
        supervisorDiagnostic = safeDiagnostic(buffer.toString('utf8'));
      } finally { await handle.close(); }
    } catch { /* Missing diagnostics do not erase the retained worker and receipt evidence. */ }
    const cleanup = receipt ?? { cleanup: 'unavailable', cleanupScanIncomplete: true, supervisorExitCode: exit.code };
    const result = worker?.coldSampleResult ?? null;
    const expectedIdentity = { archiveSha256: expected.archiveSha256, applicationJarSha256: expected.applicationJarSha256,
      buildId: expected.buildId, chromeSha256: expected.chromeSha256,
      javaSha256: expected.javaSha256, javaModulesSha256: expected.javaModulesSha256,
      javaReleaseSha256: expected.javaReleaseSha256,
      workflowSha: expected.workflowSha, driverCommit: expected.driverCommit,
      checkoutParents: expected.checkoutParents, pullRequestIdentity: expected.pullRequestIdentity,
      sourceTreeWorktreeClean: expected.sourceTreeWorktreeClean,
      sourceTreeDriverSha256: expected.sourceTreeDriverSha256, fixture: expected.fixture };
    const observedIdentity = result && { archiveSha256: result.archiveSha256,
      applicationJarSha256: result.applicationJarSha256, buildId: result.buildId,
      chromeSha256: result.chromeSha256, javaSha256: result.javaSha256,
      javaModulesSha256: result.javaModulesSha256, javaReleaseSha256: result.javaReleaseSha256,
      workflowSha: result.workflowSha, driverCommit: result.driverCommit,
      checkoutParents: result.checkoutParents, pullRequestIdentity: result.pullRequestIdentity,
      sourceTreeWorktreeClean: result.sourceTreeWorktreeClean,
      sourceTreeDriverSha256: result.sourceTreeDriverSha256, fixture: result.fixture };
    const identityMatchesOuterRun = !!result && JSON.stringify(observedIdentity) === JSON.stringify(expectedIdentity);
    const cleanupConfirmed = receipt && !receipt.cleanupScanIncomplete && (receipt.survivors?.length ?? 0) === 0
      && ['clean', 'terminated-leaked'].includes(receipt.cleanup);
    coldSupervisorCleanupConfirmed = outerCleanupConfirmed && !!cleanupConfirmed;
    const status = !diagnosticCloseError && !outerTimedOut && outerCleanupConfirmed && exit.code === 0
      && worker?.status === 'passed' && cleanupConfirmed && cleanup.cleanup === 'clean'
      && cleanup.status === 'passed' && result
      && identityMatchesOuterRun ? 'passed' : 'failed';
    samples.push({ index: index + 1, status, result, cleanup, identityMatchesOuterRun: !!identityMatchesOuterRun,
      outerSupervisor: { timeout: outerTimedOut, supervisorExited: outerCleanupConfirmed,
        cleanupConfirmed: outerCleanupConfirmed && !!cleanupConfirmed,
        retainedAsCleanupOwner: !outerCleanupConfirmed,
        exitCode: exit.code, signal: exit.signal ?? null,
        error: exit.error ?? diagnosticCloseError,
        diagnostic: supervisorDiagnostic },
      worker: { status: worker?.status ?? null, exitCode: exit.code, signal: exit.signal ?? null,
        error: worker?.error ?? exit.error ?? supervisorDiagnostic, report: basename(workerReport) } });
    report.sourceTreeColdSamples = summarizeSourceTreeColdSamples(samples, values.profile);
    await fs.writeFile(join(sampleDirectory, 'sample-summary.json'), JSON.stringify(samples.at(-1), null, 2) + '\n');
    console.log(`Source-tree cold sample ${index + 1}/${SOURCE_TREE_COLD_SAMPLE_COUNT}: ${status}`);
    if (!cleanupConfirmed || !outerCleanupConfirmed) {
      abortReason = `cold-sample-${index + 1}-teardown-unconfirmed`;
      break;
    }
    // The worker retained all process-owned files. Remove them only after its
    // subreaper receipt proves that every owned descendant has exited.
    const workerBrowserTmp = resolve(worker?.browserTempDirectory ?? '');
    assert.equal(await fs.realpath(dirname(workerBrowserTmp)), buildRoot, 'Cold worker temp directory escaped the short owned build path');
    assert.match(basename(workerBrowserTmp), /^\.ct-[A-Za-z0-9]+$/u, 'Cold worker temp directory is not an owned Chromium socket directory');
    await fs.rm(workerBrowserTmp, { recursive: true, force: true });
    await fs.rm(workerWorkParent, { recursive: true, force: true });
    samples.at(-1).cleanup = { ...samples.at(-1).cleanup,
      browserTempRemovedAfterConfirmedTeardown: true, workerFilesRemovedAfterConfirmedTeardown: true };
    await fs.writeFile(join(sampleDirectory, 'sample-summary.json'), JSON.stringify(samples.at(-1), null, 2) + '\n');
    if (outerTimedOut) {
      abortReason = `cold-sample-${index + 1}-outer-timeout`;
      break;
    }
    if (cleanup.executionTimedOut) {
      abortReason = `cold-sample-${index + 1}-execution-timeout`;
      break;
    }
    if (externalCancellation) { abortReason ??= 'cancelled-during-cold-sample'; break; }
  }
  return { ...summarizeSourceTreeColdSamples(samples, values.profile),
    ...(abortReason || externalCancellation ? { interrupted: { signal: externalCancellation, reason: abortReason } } : {}) };
  } finally {
    if (activeColdSupervisor?.exitCode !== null || activeColdSupervisor?.signalCode !== null) activeColdSupervisor = null;
  }
}

class Protocol {
  constructor(socket) {
    this.socket = socket;
    this.sequence = 0;
    this.pending = new Map();
    this.listeners = new Map();
    socket.addEventListener('message', ({ data }) => {
      let message;
      try { message = JSON.parse(data); }
      catch (error) {
        const failure = new Error('Chrome DevTools returned invalid JSON', { cause: error });
        for (const pending of this.pending.values()) { clearTimeout(pending.timer); pending.reject(failure); }
        this.pending.clear();
        socket.close();
        return;
      }
      if (message.id) {
        const pending = this.pending.get(message.id);
        if (!pending) return;
        clearTimeout(pending.timer);
        this.pending.delete(message.id);
        if (message.error) pending.reject(new Error(message.error.message));
        else pending.resolve(message.result);
      } else {
        for (const listener of this.listeners.get(`${message.sessionId ?? ''}:${message.method}`) ?? []) listener(message.params);
      }
    });
    socket.addEventListener('close', () => {
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(new Error('DevTools connection closed'));
      }
      this.pending.clear();
    });
  }
  call(method, params = {}, sessionId) {
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`DevTools deadline: ${method}`)); }, 15000);
      this.pending.set(id, { resolve, reject, timer });
      this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  on(method, listener, sessionId) {
    const key = `${sessionId ?? ''}:${method}`;
    if (!this.listeners.has(key)) this.listeners.set(key, []);
    this.listeners.get(key).push(listener);
  }
}

async function snapshot(directory, relative = '') {
  const result = {};
  for (const entry of await fs.readdir(join(directory, relative), { withFileTypes: true })) {
    const name = join(relative, entry.name);
    assert.ok(!entry.isSymbolicLink(), `Unexpected installation symlink: ${name}`);
    const stat = await fs.stat(join(directory, name));
    assert.equal(stat.mode & 0o222, 0, `Installation entry is writable: ${name}`);
    if (entry.isDirectory()) Object.assign(result, await snapshot(directory, name));
    else result[name] = await fileHash(join(directory, name));
  }
  return result;
}

const forcedKill = new WeakSet();
async function stop(process) {
  if (!process || process.exitCode !== null || process.signalCode !== null) return;
  if (!process.pid && launchErrors.has(process)) return; // Spawn failed before any process existed.
  process.kill('SIGTERM');
  const deadline = Date.now() + 5000;
  while (process.exitCode === null && process.signalCode === null && Date.now() < deadline) await delay(50);
  if (process.exitCode === null && process.signalCode === null) {
    forcedKill.add(process);
    process.kill('SIGKILL');
    const killDeadline = Date.now() + 5000;
    while (process.exitCode === null && process.signalCode === null && Date.now() < killDeadline) await delay(50);
  }
  if (process.exitCode === null && process.signalCode === null) throw new Error('Owned process shutdown could not be confirmed.');
}

async function connectDevTools(url, timeoutMs = 15000) {
  const socket = new WebSocket(url);
  try {
    await new Promise((resolve, reject) => {
      const finish = (error) => {
        clearTimeout(timer);
        socket.removeEventListener('open', opened);
        socket.removeEventListener('error', failed);
        if (error) reject(error);
        else resolve();
      };
      const opened = () => finish();
      const failed = () => finish(new Error('Chrome DevTools connection failed'));
      const timer = setTimeout(() => finish(new Error('Chrome DevTools connection deadline exceeded')), timeoutMs);
      socket.addEventListener('open', opened, { once: true });
      socket.addEventListener('error', failed, { once: true });
    });
    return socket;
  } catch (error) {
    try { socket.close(); } catch { /* Preserve the handshake failure. */ }
    throw error;
  }
}

function responseHeader(response, name) {
  const value = Object.entries(response.headers ?? {}).find(([candidate]) => candidate.toLowerCase() === name)?.[1];
  return value === undefined ? null : String(value);
}

function urlPath(value) {
  try { return new URL(value).pathname; }
  catch { return null; }
}

function responseSummary(response, source) {
  return { responseRoute: urlPath(response.url.split('#')[0].split('?')[0]),
    status: response.status, contentSecurityPolicy: responseHeader(response, 'content-security-policy'), source };
}

function correlateDocumentResponse(state, requestId, response, source) {
  const request = state.pendingDocumentRequests.get(requestId);
  const summary = responseSummary(response, source);
  if (!request) {
    state.orphanDocumentResponses.push(summary);
    return;
  }
  Object.assign(request, summary);
  state.pendingDocumentRequests.delete(requestId);
}

async function makeTarget({ cspProbe = false, cacheEnabled = false, newWindow = false } = {}) {
  assert.equal(typeof cacheEnabled, 'boolean', 'Browser cache policy must be explicit');
  const initialization = cdpDiagnostics.beginTarget();
  const { targetId } = await cdpDiagnostics.command(initialization, 'Target.createTarget', () =>
    cdp.call('Target.createTarget', { url: 'about:blank', ...(newWindow ? { newWindow: true } : {}) }));
  cdpDiagnostics.setTargetIds(initialization, targetId);
  const { sessionId } = await cdpDiagnostics.command(initialization, 'Target.attachToTarget', () =>
    cdp.call('Target.attachToTarget', { targetId, flatten: true }));
  cdpDiagnostics.setTargetIds(initialization, targetId, sessionId);
  const state = { targetId, sessionId, cspProbe, cacheEnabled, requests: [], responses: [], exceptions: [], requestUrls: new Map(),
    initializationComplete: false,
    cacheRequests: [], cacheResponses: [], cacheRequestIds: new Set(),
    documentRequests: [], pendingDocumentRequests: new Map(), orphanDocumentResponses: [],
    cspViolations: [], cspLogEntries: [], cspBlockedRequests: [], cspIssues: [] };
  targets.push(state);
  if (!cspProbe) lastTarget = state;
  cdp.on('Network.requestWillBeSent', (event) => {
    const priorDocument = state.pendingDocumentRequests.has(event.requestId);
    if (event.redirectResponse && (event.type === 'Document' || priorDocument)) {
      correlateDocumentResponse(state, event.requestId, event.redirectResponse, 'requestWillBeSent.redirectResponse');
    }
    const type = event.type ?? (priorDocument ? 'Document' : undefined);
    const url = event.request.url.split('#')[0].split('?')[0];
    state.requestUrls.set(event.requestId, url);
    state.requests.push({ requestId: event.requestId, method: event.request.method, url, type });
    if (cacheEnabled) state.cacheRequests.push({ requestId: event.requestId, method: event.request.method, url, type });
    if (type === 'Document') {
      const request = { requestId: event.requestId, sequence: state.documentRequests.length,
        route: urlPath(url), method: event.request.method, status: null,
        contentSecurityPolicy: null, source: null, failure: null };
      state.documentRequests.push(request);
      state.pendingDocumentRequests.set(event.requestId, request);
    }
  }, sessionId);
  cdp.on('Network.requestServedFromCache', (event) => {
    if (cacheEnabled) state.cacheRequestIds.add(event.requestId);
  }, sessionId);
  cdp.on('Network.responseReceived', (event) => {
    const response = { requestId: event.requestId, url: event.response.url.split('#')[0].split('?')[0], status: event.response.status, type: event.type };
    if (cacheEnabled) state.cacheResponses.push({ requestId: event.requestId, ...response,
      fromDiskCache: event.response.fromDiskCache ?? null, fromServiceWorker: event.response.fromServiceWorker ?? null });
    if (event.type === 'Document' || state.pendingDocumentRequests.has(event.requestId)) {
      response.contentSecurityPolicy = responseHeader(event.response, 'content-security-policy');
      correlateDocumentResponse(state, event.requestId, event.response, 'responseReceived');
    }
    state.responses.push(response);
  }, sessionId);
  cdp.on('Network.loadingFailed', (event) => {
    if (event.type === 'Document') {
      const request = state.pendingDocumentRequests.get(event.requestId);
      if (request) request.failure = { errorText: event.errorText, blockedReason: event.blockedReason ?? null };
    }
    if (event.blockedReason === 'csp') state.cspBlockedRequests.push({ requestId: event.requestId,
      url: state.requestUrls.get(event.requestId) ?? null, errorText: event.errorText,
      blockedReason: event.blockedReason, type: event.type });
  }, sessionId);
  cdp.on('Runtime.exceptionThrown', (event) => state.exceptions.push(event.exceptionDetails.text), sessionId);
  cdp.on('Runtime.bindingCalled', (event) => {
    if (event.name !== '__decompRecordCspViolation') return;
    try { state.cspViolations.push(JSON.parse(event.payload)); }
    catch { state.cspViolations.push({ malformedPayload: String(event.payload) }); }
  }, sessionId);
  cdp.on('Log.entryAdded', ({ entry }) => {
    if (/content[- ]security[- ]policy|refused to (?:load|execute|apply|connect|frame)|blocked by[^.]*\bcsp\b/i.test(entry.text)) {
      state.cspLogEntries.push({ source: entry.source, level: entry.level, text: entry.text, url: entry.url ?? null, lineNumber: entry.lineNumber ?? null });
    }
  }, sessionId);
  cdp.on('Audits.issueAdded', ({ issue }) => {
    if (issue.code === 'ContentSecurityPolicyIssue') state.cspIssues.push(issue.details?.contentSecurityPolicyIssueDetails ?? issue);
  }, sessionId);
  const initialize = (method, params = {}) => cdpDiagnostics.command(initialization, method,
    () => cdp.call(method, params, sessionId));
  await initialize('Page.enable');
  await initialize('Runtime.enable');
  await initialize('Network.enable');
  await initialize('Log.enable');
  await initialize('Audits.enable');
  await initialize('Runtime.addBinding', { name: '__decompRecordCspViolation' });
  await initialize('Page.addScriptToEvaluateOnNewDocument', { source: `addEventListener('securitypolicyviolation', event => {
    globalThis.__decompRecordCspViolation(JSON.stringify({
      blockedURI: event.blockedURI, columnNumber: event.columnNumber, disposition: event.disposition,
      documentURI: event.documentURI, effectiveDirective: event.effectiveDirective,
      lineNumber: event.lineNumber, originalPolicy: event.originalPolicy,
      sourceFile: event.sourceFile, statusCode: event.statusCode, violatedDirective: event.violatedDirective,
    }));
  });` });
  await initialize('Network.setCacheDisabled', { cacheDisabled: !cacheEnabled });
  await initialize('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  state.initializationComplete = true;
  return state;
}

function targetCspViolationCount(target) {
  return target.cspViolations.length + target.cspLogEntries.length + target.cspBlockedRequests.length + target.cspIssues.length;
}

function cspEvidence() {
  const productTargets = targets.filter((target) => !target.cspProbe);
  const inspectedTargets = productTargets.map((target) => {
    const documentRequests = target.documentRequests.map(({ requestId: _requestId, ...request }) => request);
    return {
      documentRoutes: [...new Set(documentRequests.map((request) => request.route))],
      documentRequests,
      documentPolicies: documentRequests.filter((request) => request.source !== null),
      unresolvedDocumentRequests: documentRequests.filter((request) => request.source === null),
      orphanDocumentResponses: target.orphanDocumentResponses,
      violationEvents: target.cspViolations,
      securityLogEntries: target.cspLogEntries,
      blockedRequests: target.cspBlockedRequests,
      auditIssues: target.cspIssues,
    };
  });
  const documentRequests = inspectedTargets.flatMap((target) => target.documentRequests);
  const documentPolicies = inspectedTargets.flatMap((target) => target.documentPolicies);
  const unresolvedDocumentRequests = inspectedTargets.flatMap((target, targetIndex) =>
    target.unresolvedDocumentRequests.map((request) => ({ targetIndex, ...request })));
  const orphanDocumentResponses = inspectedTargets.flatMap((target, targetIndex) =>
    target.orphanDocumentResponses.map((response) => ({ targetIndex, ...response })));
  const invalidDocumentUrls = [
    ...documentRequests.filter((request) => request.route === null || request.responseRoute === null)
      .map(({ sequence, route, responseRoute }) => ({ sequence, route, responseRoute })),
    ...orphanDocumentResponses.filter((response) => response.responseRoute === null)
      .map(({ targetIndex, responseRoute }) => ({ targetIndex, responseRoute })),
  ];
  return safeEvidence({
    inspectedTargets,
    attachedTargetCount: inspectedTargets.length,
    inspectedTargetCount: inspectedTargets.filter((target) => target.documentRoutes.length > 0).length,
    documentRequestCount: documentRequests.length,
    documentResponseCount: documentPolicies.length,
    unresolvedDocumentRequestCount: unresolvedDocumentRequests.length,
    unresolvedDocumentRequests,
    orphanDocumentResponseCount: orphanDocumentResponses.length,
    orphanDocumentResponses,
    invalidDocumentUrls,
    missingPolicyDocuments: documentPolicies.filter((response) => !response.contentSecurityPolicy),
    unsafePolicyDocuments: documentPolicies.filter((response) => /'unsafe-(?:inline|eval)'/.test(response.contentSecurityPolicy ?? '')),
    violationCount: productTargets.reduce((count, target) => count + targetCspViolationCount(target), 0),
    signals: ['SecurityPolicyViolationEvent', 'Log.entryAdded', 'Network.loadingFailed', 'Audits.issueAdded'],
  });
}

async function qualifyCspDetector() {
  const probe = await makeTarget({ cspProbe: true });
  const blockedImage = 'http://127.0.0.1/__csp_probe_blocked_image';
  const html = `<!doctype html><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; img-src 'none'"><p id="probe-ready">ready</p><script>globalThis.__cspProbeExecuted=true</script><img src="${blockedImage}">`;
  await cdp.call('Page.navigate', { url: `data:text/html;charset=utf-8,${encodeURIComponent(html)}` }, probe.sessionId);
  await ready(probe, `document.querySelector('#probe-ready')?.textContent === 'ready'`, 'CSP detector positive control');
  await waitFor(() => probe.cspViolations.length > 0 && probe.cspLogEntries.length > 0 &&
    probe.cspBlockedRequests.length > 0 && probe.cspIssues.length > 0, 'all four CSP detector signals');
  assert.ok(await evaluate(probe, `typeof globalThis.__cspProbeExecuted === 'undefined'`), 'CSP detector probe script executed');
  assert.ok(probe.cspBlockedRequests.some((request) => request.url === blockedImage),
    'CSP did not block the positive-control external image');
  return { blockedInlineScript: true, blockedExternalImage: true, observedSignalCount: targetCspViolationCount(probe),
    signals: { violationEvents: probe.cspViolations.length, securityLogEntries: probe.cspLogEntries.length,
      blockedRequests: probe.cspBlockedRequests.length, auditIssues: probe.cspIssues.length } };
}

async function evaluate(target, expression) {
  const result = await cdp.call('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, target.sessionId);
  if (result.exceptionDetails) {
    const exception = result.exceptionDetails.exception;
    const detail = exception?.description ?? exception?.value ?? result.exceptionDetails.text;
    throw new Error(`Browser expression failed: ${result.exceptionDetails.text}: ${detail}`);
  }
  return result.result.value;
}

async function ready(target, expression, label) {
  return waitFor(async () => {
    try { return await evaluate(target, `document.body !== null && (${expression})`); }
    catch (error) {
      if (/context|navigat|Cannot find/i.test(error.message)) return false;
      throw error;
    }
  }, label);
}

async function capture(target, name) {
  const { data } = await cdp.call('Page.captureScreenshot', { format: 'png' }, target.sessionId);
  await fs.writeFile(join(root, name), Buffer.from(data, 'base64'));
}

async function prepareArchive(archivePath) {
  assert.equal(work, undefined, 'Remove the previous owned extraction before preparing another archive');
  const archiveSha256 = await fileHash(archivePath);
  work = await fs.mkdtemp(join(values['work-parent'], 'packaged-browser-work-'));
  report.workDirectory = work;
  let setup;
  try {
    setup = JSON.parse(execFileSync(values.python, [installHelper, 'prepare', '--archive', archivePath,
      '--work', work, '--owner-token', ownerToken], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }));
  } catch (error) {
    throw new Error('Packaged archive preparation failed or returned invalid JSON', { cause: error });
  }
  const before = await snapshot(setup.app);
  const bins = join(work, 'launcher tools');
  const working = join(work, 'unrelated working directory');
  await fs.mkdir(bins);
  await fs.mkdir(working);
  for (const name of ['uname', 'ls', 'xargs', 'sed', 'tr']) {
    const executable = execFileSync('/bin/sh', ['-c', `command -v ${name}`], { encoding: 'utf8' }).trim();
    await fs.symlink(executable, join(bins, name));
  }
  // Gradle uses xargs with its default external echo command while parsing JVM options.
  await fs.symlink('/usr/bin/echo', join(bins, 'echo'));
  const environment = { PATH: bins, JAVA_HOME: javaHome, LANG: 'C.UTF-8' };
  for (const name of ['node', 'npm']) assert.notEqual(spawnSync('/bin/sh', ['-c', `command -v ${name}`], { env: environment }).status, 0);
  const data = join(working, 'untouched jobs');
  return { ...setup, archivePath, archiveSha256, work, before, working, environment, data };
}

function installationIdentity(installation) {
  return { archive: basename(installation.archivePath), archivePath: installation.archivePath,
    archiveSha256: installation.archiveSha256, applicationJar: installation.jar,
    applicationJarSha256: installation.jarSha256, buildId: installation.manifest.buildId,
    applicationVersion: installation.manifest.applicationVersion, resourceBudget: installation.resourceBudget };
}

function recordInstallation(installation) {
  Object.assign(report, installationIdentity(installation), {
    workDirectory: installation.work, unrelatedWorkingDirectory: installation.working,
    basePath: values.mode === 'legacy' ? '/' : '/nested/', nodeOnApplicationPath: false, npmOnApplicationPath: false, readOnlyInstallation: true,
  });
}

async function launchApplication(installation, port = '0', frontendOrigin) {
  const startupStarted = performance.now();
  applicationOutput = '';
  applicationError = '';
  application = startOwned(join(installation.app, 'bin/llm_bin_patch'), ['web', '--ui', values.mode === 'legacy' ? 'legacy' : 'spa', '--host', '127.0.0.1', '--port', port,
    '--base-path', values.mode === 'legacy' ? '/' : '/nested/', '--data-dir', installation.data, ...(frontendOrigin ? ['--dev-frontend-origin', frontendOrigin] : [])], {
    cwd: installation.working, env: installation.environment, stdio: ['ignore', 'pipe', 'pipe'],
  });
  application.stdout.on('data', (chunk) => { applicationOutput = (applicationOutput + chunk).slice(-1048576); });
  application.stderr.on('data', (chunk) => { applicationError = (applicationError + chunk).slice(-1048576); });
  const origin = await waitFor(() => {
    if (application.exitCode !== null || application.signalCode !== null) throw new Error(`Packaged application exited: ${applicationError}`);
    return applicationOutput.match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
  }, 'packaged application listener');
  applicationStartupMs = Math.round((performance.now() - startupStarted) * 100) / 100;
  console.log(`Packaged application ready: ${origin}${values.mode === 'legacy' ? '/' : '/nested/'}`);
  return origin;
}

async function removeOwnedWork() {
  if (!work) return;
  if (await fs.stat(join(work, '.packaged-browser-owned')).then(() => true, () => false)) {
    execFileSync(values.python, [installHelper, 'cleanup', '--work', work, '--owner-token', ownerToken]);
  } else await fs.rmdir(work); // Only an empty directory if preparation never initialized it.
  work = undefined;
}

try {
  report.tools.chromeSha256 = await fileHash(chromeBinary);
  if (['source-tree', 'source-tree-cold-worker'].includes(values.mode)) {
    Object.assign(report.tools, await javaRuntimeHashes(javaHome));
  }
  let installation = await prepareArchive(values.mode === 'upgrade' ? values['previous-archive'] : archive);
  recordInstallation(installation);
  const { manifest, data } = installation;
  const legacyFixture = values.mode === 'legacy' ? await seedLegacy(data) : null;
  const historyFixture = values.mode === 'history' ? await seedHistory(data) : null;
  const restartFixture = values.mode === 'restart' ? await seedHistory(data) : null;
  const scaleFixture = values.mode === 'scale' ? await seedScale(data) : null;
  const sourceTreeFixture = ['source-tree', 'source-tree-cold-worker'].includes(values.mode) ? await seedSourceTreeFixture(data) : null;
  const liveFixture = values.mode === 'live' ? await seedLive(data) : null;
  const populated = !!(historyFixture || restartFixture || scaleFixture || sourceTreeFixture || liveFixture);
  const libraryText = historyFixture || restartFixture ? 'synthetic-history.elf' : scaleFixture ? 'synthetic-project-09999.elf'
    : sourceTreeFixture ? 'synthetic-source-tree.elf'
    : liveFixture ? 'live-dashboard-2.elf' : 'No uploaded jobs yet.';
  let developmentPort;
  let browserOrigin;
  if (values.mode === 'source-tree') {
    sourceTreeColdSummary = await runSourceTreeColdSamples({ archiveSha256: installation.archiveSha256,
      applicationJarSha256: installation.jarSha256, buildId: installation.manifest.buildId,
      chromeSha256: report.tools.chromeSha256, javaSha256: report.tools.javaSha256,
      javaModulesSha256: report.tools.javaModulesSha256, javaReleaseSha256: report.tools.javaReleaseSha256,
      workflowSha: report.workflowSha,
      driverCommit: report.driverCommit, checkoutParents: report.checkoutParents,
      pullRequestIdentity: report.pullRequestIdentity, sourceTreeWorktreeClean: report.sourceTreeWorktreeClean,
      sourceTreeDriverSha256: report.sourceTreeDriverSha256,
      fixture: { jobId: sourceTreeFixture.jobId, runId: sourceTreeFixture.runId,
        revisionId: sourceTreeFixture.revisionId, fileCount: sourceTreeFixture.fileCount,
        binarySha256: sourceTreeFixture.binarySha256, sourceSha256: sourceTreeFixture.sourceSha256,
        profileId: sourceTreeFixture.profileId, profileSha256: sourceTreeFixture.profileSha256 } });
    report.sourceTreeColdSamples = sourceTreeColdSummary;
    if (sourceTreeColdSummary.interrupted) throw new Error(`Cold sampling stopped: ${JSON.stringify(sourceTreeColdSummary.interrupted)}`);
    assert.equal(await fileHash(archive), installation.archiveSha256,
      'The packaged archive changed during cold sampling');
  }
  if (values.mode === 'proxy') {
    const reservation = createHttpServer();
    await new Promise((resolve, reject) => {
      reservation.once('error', reject);
      reservation.listen(0, '127.0.0.1', resolve);
    });
    developmentPort = reservation.address().port;
    await new Promise((resolve, reject) => reservation.close((error) => error ? reject(error) : resolve()));
    browserOrigin = `http://127.0.0.1:${developmentPort}`;
  }
  const origin = await launchApplication(installation, '0', values.mode === 'proxy' ? browserOrigin : undefined);
  report.origin = origin;
  browserOrigin ??= origin;
  const observeNativeVisibility = values.mode === 'restart';
  if (observeNativeVisibility && !process.env.DISPLAY) {
    throw new Error('restart mode requires a real X display; run it under xvfb-run rather than emulating visibility');
  }
  report.browserDisplayMode = observeNativeVisibility ? 'headful-x11' : 'headless';

  // Chrome places SingletonSocket under TMPDIR. Keep it short enough even on hosted
  // runners whose checkout path is /home/runner/work/<repo>/<repo>.
  browserTmp = await fs.mkdtemp(join(repo, 'build/.ct-'));
  report.browserTempDirectory = browserTmp;
  report.browserProfileDirectory = profile;
  await fs.mkdir(profile);
  const browserStartupStarted = performance.now();
  browser = startOwned(chromeBinary, [...(observeNativeVisibility ? [] : ['--headless=new']), '--disable-gpu', ...(values['no-sandbox'] ? ['--no-sandbox'] : []), '--no-first-run', '--no-default-browser-check', '--disable-background-networking', '--disable-extensions', '--disable-default-apps', '--disable-sync', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', `--user-data-dir=${profile}`, 'about:blank'], {
    cwd: repo, env: { ...process.env, TMPDIR: relative(repo, browserTmp) }, stdio: ['ignore', 'ignore', 'pipe'],
  });
  browser.stderr.on('data', (chunk) => { browserError = (browserError + chunk).slice(-1048576); });
  const portFile = await waitFor(async () => {
    if (browser.exitCode !== null || browser.signalCode !== null) throw new Error(`Browser exited: ${browserError}`);
    try { return await fs.readFile(join(profile, 'DevToolsActivePort'), 'utf8'); } catch { return false; }
  }, 'Chrome DevTools listener');
  browserStartupMs = Math.round((performance.now() - browserStartupStarted) * 100) / 100;
  const [port, socketPath] = portFile.trim().split('\n');
  const socket = await connectDevTools(`ws://127.0.0.1:${port}${socketPath}`);
  cdp = new Protocol(socket);
  cdp.on('Target.targetCreated', ({ targetInfo }) => cdpDiagnostics.targetEvent('target-created', {
    targetId: targetInfo?.targetId, targetType: targetInfo?.type, attached: targetInfo?.attached,
  }));
  cdp.on('Target.targetDestroyed', ({ targetId }) => cdpDiagnostics.targetEvent('target-destroyed', { targetId }));
  cdp.on('Target.attachedToTarget', ({ sessionId, targetInfo }) => cdpDiagnostics.targetEvent('target-attached', {
    targetId: targetInfo?.targetId, sessionId, targetType: targetInfo?.type, attached: targetInfo?.attached,
  }));
  cdp.on('Target.detachedFromTarget', ({ sessionId, targetId }) => cdpDiagnostics.targetEvent('target-detached', { targetId, sessionId }));
  const discoveryStarted = performance.now();
  try {
    await cdp.call('Target.setDiscoverTargets', { discover: true });
    report.targetDiscoveryMonitoring = { outcome: 'success', elapsedMs: Math.max(0, Math.round(performance.now() - discoveryStarted)) };
  } catch (error) {
    report.targetDiscoveryMonitoring = { outcome: error?.message === 'DevTools deadline: Target.setDiscoverTargets' ? 'deadline' : 'protocol-error',
      elapsedMs: Math.max(0, Math.round(performance.now() - discoveryStarted)) };
    throw error;
  }
  report.browser = await cdp.call('Browser.getVersion');
  report.browserSandboxDisabled = values['no-sandbox'];
  if (values.mode === 'source-tree-cold-worker') {
    const bootstrapUrl = await waitFor(() => applicationOutput.split(/\s+/).find(part => part.startsWith(origin + '/nested/#bootstrap=')), 'fresh JVM bootstrap handoff');
    const token = new URL(bootstrapUrl).hash.slice('#bootstrap='.length);
    sensitiveValues.push(token);
    const coldTab = await makeTarget();
    const authenticationStarted = performance.now();
    const exchange = await fetch(`${origin}/nested/api/v1/session`, {
      method: 'POST',
      headers: { accept: 'application/json', 'content-type': 'application/json', origin },
      body: JSON.stringify({ token }),
      redirect: 'manual',
    });
    assert.equal(exchange.status, 200, 'Fresh bootstrap exchange did not create a session');
    const exchangeBody = await exchange.json();
    assert.ok(exchangeBody.data?.csrfToken && exchangeBody.data?.expiresAt, 'Session response omitted credential metadata');
    const setCookie = exchange.headers.get('set-cookie');
    assert.ok(setCookie, 'Session exchange omitted its HttpOnly cookie');
    const cookiePair = setCookie.split(';', 1)[0];
    const separator = cookiePair.indexOf('=');
    assert.ok(separator > 0 && cookiePair.length - separator > 1, 'Session cookie was malformed');
    const cookieName = cookiePair.slice(0, separator);
    const cookieValue = cookiePair.slice(separator + 1);
    sensitiveValues.push(cookieValue);
    const cookieResult = await cdp.call('Network.setCookie', { url: `${origin}/nested/`, name: cookieName,
      value: cookieValue, path: '/nested/', httpOnly: true, sameSite: 'Strict', secure: false }, coldTab.sessionId);
    assert.equal(cookieResult.success, true, 'Could not install the real session cookie in the empty browser profile');
    const installedCookies = (await cdp.call('Network.getCookies', { urls: [`${origin}/nested/`] }, coldTab.sessionId)).cookies;
    assert.equal(installedCookies.length, 1, 'Cold profile contained storage beyond its one required session cookie');
    assert.equal(installedCookies[0].name, cookieName);
    assert.equal(installedCookies[0].path, '/nested/');
    assert.equal(installedCookies[0].httpOnly, true);
    assert.equal(installedCookies[0].sameSite, 'Strict');
    const authenticationMs = Math.round((performance.now() - authenticationStarted) * 100) / 100;
    const result = await qualifySourceTreeColdPage({ fixture: sourceTreeFixture, target: coldTab, cdp, evaluate, ready,
      browserOrigin, profile: values.profile });
    assert.equal(await evaluate(coldTab, 'location.hash'), '', 'The browser document must not contain a bootstrap fragment');
    assert.equal(await evaluate(coldTab, 'localStorage.length + sessionStorage.length'), 0,
      'Cold browser authentication must not add local or session storage');
    report.coldSampleResult = { ...result, browserPid: browser.pid, jvmPid: application.pid,
      profileId: createHash('sha256').update(profile).digest('hex'), jvmStartupMs: applicationStartupMs,
      browserStartupMs, authenticationMs,
      browserProcessIdentity: await processIdentity(browser.pid), jvmProcessIdentity: await javaProcessIdentity(application.pid),
      archiveSha256: installation.archiveSha256, applicationJarSha256: installation.jarSha256,
      buildId: manifest.buildId, chromeSha256: report.tools.chromeSha256,
      javaSha256: report.tools.javaSha256,
      javaModulesSha256: report.tools.javaModulesSha256, javaReleaseSha256: report.tools.javaReleaseSha256,
      browserProduct: report.browser.product, workflowSha: report.workflowSha, driverCommit: report.driverCommit,
      checkoutParents: report.checkoutParents, pullRequestIdentity: report.pullRequestIdentity,
      sourceTreeWorktreeClean: report.sourceTreeWorktreeClean,
      sourceTreeDriverSha256: report.sourceTreeDriverSha256,
      fixture: { jobId: sourceTreeFixture.jobId, runId: sourceTreeFixture.runId,
        revisionId: sourceTreeFixture.revisionId, fileCount: sourceTreeFixture.fileCount,
        binarySha256: sourceTreeFixture.binarySha256, sourceSha256: sourceTreeFixture.sourceSha256,
        profileId: sourceTreeFixture.profileId, profileSha256: sourceTreeFixture.profileSha256 },
      applicationCacheBoundary: 'new packaged JVM; source fixture seeded before launch; no source API read before direct measured navigation; source catalog cache is process-local',
      sessionBoundary: 'fresh bootstrap POST performed by the driver; exactly one HttpOnly session cookie installed before the first browser document; no bootstrap fragment, local storage, session storage, or prior session reused' };
    report.sourceTreeScale = { coldFirstDataPage: { durationMs: result.durationMs } };
    report.browserColdProfileId = report.coldSampleResult.profileId;
  } else {
  report.cspDetectorProbe = await qualifyCspDetector();
  if (legacyFixture) {
    const tab = await makeTarget();
    const bootstrapUrl = await waitFor(() => applicationOutput.split(/\s+/).find(part => part.startsWith(origin + '/login#bootstrap=')), 'legacy local bootstrap handoff');
    sensitiveValues.push(new URL(bootstrapUrl).hash.slice('#bootstrap='.length));
    report.legacy = await qualifyLegacy({ fixture: legacyFixture, origin, bootstrapUrl, tab, cdp, evaluate, ready, makeTarget });
    report.requests.legacy = tab.requests;
  }
  if (values.mode === 'upgrade') {
    const previous = installation;
    report.upgrade = { previous: installationIdentity(previous), phase: 'previous-home', requestInterception: false };
    const previousRuntime = previous.manifest.files.find((entry) => /^assets\/Runtime-.+\.js$/.test(entry.path));
    assert.ok(previousRuntime, 'Previous package must contain a Runtime lazy chunk');
    const previousRuntimeUrl = `${origin}/nested/assets/ui/${previousRuntime.path}`;
    const tab = await makeTarget({ cacheEnabled: true });
    await cdp.call('Page.navigate', { url: `${origin}/nested/` }, tab.sessionId);
    await ready(tab, `document.querySelector('h1')?.textContent === 'Your work, with its evidence'`, 'previous packaged home');
    assert.equal(await evaluate(tab, `document.querySelector('meta[name="decomp-ui-build"]')?.content`), previous.manifest.buildId);
    assert.equal(await evaluate(tab, `document.querySelector('meta[name="decomp-application-version"]')?.content`), previous.manifest.applicationVersion);
    assert.equal(tab.requests.filter((entry) => entry.url === previousRuntimeUrl).length, 0, 'Previous Runtime chunk was loaded before replacement');
    // A second target uses the same owned browser profile and real HTTP cache.
    // Keep the original old tab alive with its lazy Runtime still unrequested.
    const cacheProbe = await makeTarget({ cacheEnabled: true });
    await cdp.call('Page.navigate', { url: `${origin}/nested/` }, cacheProbe.sessionId);
    await ready(cacheProbe, `document.querySelector('h1')?.textContent === 'Your work, with its evidence'`, 'cached previous packaged home');
    assert.equal(await evaluate(cacheProbe, `document.querySelector('meta[name="decomp-ui-build"]')?.content`), previous.manifest.buildId);
    await delay(100); // Drain already-produced DevTools resource/cache events.
    report.upgrade.cachedBootstrap = qualifyUpgradeCache(previous.manifest, `${origin}/nested/assets/ui/`, {
      cacheEnabled: cacheProbe.cacheEnabled, coldResponses: tab.cacheResponses,
      requests: cacheProbe.cacheRequests, responses: cacheProbe.cacheResponses,
      cacheRequestIds: [...cacheProbe.cacheRequestIds],
    });
    assert.equal(cacheProbe.requests.filter((entry) => entry.url === previousRuntimeUrl).length, 0, 'Cache warm-up loaded the old lazy Runtime');
    await cdp.call('Page.bringToFront', {}, tab.sessionId);
    lastTarget = tab;
    await capture(tab, 'upgrade-previous-home.png');

    // The tab and its old entry module remain alive. Only the owned JVM and its
    // extracted install are replaced; no browser request is intercepted.
    await stop(application);
    report.upgrade.previousShutdownConfirmed = true;
    assert.deepEqual(await snapshot(previous.app), previous.before, 'Previous installation bytes changed');
    assert.equal(await fs.stat(previous.data).then(() => true, () => false), false, 'Previous public browsing created job data');
    report.upgrade.previousInstallationUnchanged = true;
    await removeOwnedWork();
    report.upgrade.previousWorkCleanupConfirmed = true;
    report.upgrade.phase = 'prepare-current';
    installation = await prepareArchive(archive);
    recordInstallation(installation);
    report.upgrade.current = installationIdentity(installation);
    const pair = qualifyUpgrade(previous.manifest, installation.manifest);
    assert.equal(pair.previousRuntime.path, previousRuntime.path);
    report.upgrade.previousLazyChunk = pair.previousRuntime.path;
    report.upgrade.currentLazyChunk = pair.currentRuntime.path;
    const replacementOrigin = await launchApplication(installation, new URL(origin).port);
    assert.equal(replacementOrigin, origin, 'Replacement JVM did not preserve the previous origin');
    report.upgrade.phase = 'old-tab-current-server';
    assert.equal(await evaluate(tab, `document.querySelector('meta[name="decomp-ui-build"]')?.content`), previous.manifest.buildId);
    assert.equal(tab.requests.filter((entry) => entry.type === 'Document').length, 1, 'Old tab reloaded during server replacement');
    assert.equal(tab.requests.filter((entry) => entry.url === previousRuntimeUrl).length, 0, 'Old lazy chunk was requested before navigation');
    await evaluate(tab, `document.querySelector('a[href="/nested/runtime"]').click()`);
    await ready(tab, `document.querySelector('h1')?.textContent === 'This view is unavailable' && document.querySelector('#asset-notice-title')?.textContent === 'The application may have updated'`, 'actual old-tab version notice');
    await delay(5000);
    const warning = await evaluate(tab, `(() => {
      const visibleInViewport = element => {
        if (!element || element.getClientRects().length === 0) return false;
        for (let ancestor = element; ancestor; ancestor = ancestor.parentElement) {
          const style = getComputedStyle(ancestor);
          if (style.display === 'none' || style.visibility !== 'visible' || Number(style.opacity) <= 0) return false;
        }
        const bounds = element.getBoundingClientRect();
        if (bounds.width <= 0 || bounds.height <= 0 || bounds.left < 0 || bounds.top < 0 ||
          bounds.right > document.documentElement.clientWidth || bounds.bottom > window.innerHeight) return false;
        const hit = document.elementFromPoint(bounds.left + bounds.width / 2, bounds.top + bounds.height / 2);
        return hit !== null && element.contains(hit);
      };
      const reload = [...document.querySelectorAll('button')].find(button => button.textContent === 'Reload application');
      return { notices: document.querySelectorAll('[role="alert"]').length, text: document.body.innerText,
        reloadEnabled: !!reload && !reload.matches(':disabled'),
        noticeTitleWithinViewport: visibleInViewport(document.querySelector('#asset-notice-title')),
        reloadControlWithinViewport: visibleInViewport(reload) };
    })()`);
    assert.equal(warning.notices, 1);
    assert.equal(warning.reloadEnabled, true);
    assert.equal(warning.noticeTitleWithinViewport, true);
    assert.equal(warning.reloadControlWithinViewport, true);
    assert.ok(warning.text.includes(previous.manifest.buildId), 'Version notice lost the old tab build identity');
    assert.equal(tab.requests.filter((entry) => entry.url === previousRuntimeUrl).length, 1, 'Old lazy chunk was automatically retried');
    assert.ok(tab.responses.some((entry) => entry.url === previousRuntimeUrl && entry.status === 404), 'Replacement JVM did not return the real missing-asset 404');
    assert.equal(tab.requests.filter((entry) => entry.type === 'Document').length, 1, 'Old tab automatically reloaded');
    assert.ok(tab.requests.every((entry) => ['GET', 'HEAD'].includes(entry.method)), 'Upgrade recovery sent a mutation');
    assert.deepEqual(tab.exceptions, []);
    await capture(tab, 'upgrade-version-notice.png');
    try {
      await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Reload application').click()`);
    } catch (error) {
      if (!/context|navigat/i.test(error.message)) throw error;
    }
    const current = installation.manifest;
    await ready(tab, `document.querySelector('h1')?.textContent === 'Runtime status' && document.body.innerText.includes(${JSON.stringify(current.buildId)}) && document.querySelectorAll('[role="alert"]').length === 0`, 'explicit reload into current packaged Runtime');
    await delay(1000);
    assert.equal(await evaluate(tab, `document.querySelector('meta[name="decomp-ui-build"]')?.content`), current.buildId);
    assert.equal(await evaluate(tab, `document.querySelector('meta[name="decomp-application-version"]')?.content`), current.applicationVersion);
    assert.equal(await evaluate(tab, 'location.pathname'), '/nested/runtime');
    assert.ok(await evaluate(tab, `document.body.innerText.includes(${JSON.stringify(current.applicationVersion)})`));
    assert.equal(tab.requests.filter((entry) => entry.type === 'Document').length, 2, 'Explicit upgrade reload was not exactly one document request');
    assert.equal(tab.requests.filter((entry) => entry.url === previousRuntimeUrl).length, 1, 'Reload repeated the stale lazy import');
    assert.ok(tab.responses.some((entry) => entry.url === `${origin}/nested/assets/ui/${pair.currentRuntime.path}` && entry.status === 200), 'Current Runtime chunk did not load successfully');
    assert.ok(tab.requests.every((entry) => ['GET', 'HEAD'].includes(entry.method)), 'Explicit reload sent a mutation');
    assert.ok(tab.requests.every((entry) => entry.url.startsWith(origin + '/')), 'Upgrade fetched an external dependency');
    assert.ok(cacheProbe.requests.every((entry) => ['GET', 'HEAD'].includes(entry.method)), 'Cache warm-up tab sent a later mutation');
    assert.ok(cacheProbe.requests.every((entry) => entry.url.startsWith(origin + '/')), 'Cache warm-up tab fetched an external dependency');
    assert.deepEqual(cacheProbe.exceptions, []);
    assert.deepEqual(tab.exceptions, []);
    assert.equal(await fs.stat(installation.data).then(() => true, () => false), false, 'Current public browsing created job data');
    await capture(tab, 'upgrade-current-runtime.png');
    Object.assign(report.upgrade, { phase: 'recovered-current', sameOrigin: origin, basePath: '/nested/',
      sameTabPreserved: true, oldLazyResponseStatus: 404, warningCount: 1, observationSeconds: 5,
      automaticReloads: 0, automaticChunkRetries: 0, explicitReloadDocumentRequests: 1,
      recoveredCurrentBuild: true, mutationRequests: 0, noticeTitleWithinViewport: true, reloadControlWithinViewport: true });
    report.requests.upgrade = tab.requests;
    report.requests.upgradeCacheWarm = cacheProbe.requests;
    report.jobDataCreated = false;
  }
  if (restartFixture) {
    const restartApplication = async () => {
      const previous = application;
      const signalsSent = ['SIGTERM'];
      previous.kill('SIGTERM');
      await waitFor(() => previous.exitCode !== null || previous.signalCode !== null, 'graceful SIGTERM exit', 30000);
      const exit = assertGracefulShutdown({ signalsSent, exitCode: previous.exitCode, signalCode: previous.signalCode });
      const restartedOrigin = await launchApplication(installation, new URL(origin).port);
      return { origin: restartedOrigin, exit };
    };
    const captureSafe = async (target, name) => {
      const safe = await evaluate(target, `(() => {
        if (location.hash !== '' || ${JSON.stringify(sensitiveValues)}.some(value => document.body.innerText.includes(value))) return false;
        document.querySelectorAll('input, textarea, [contenteditable]').forEach(element => { element.style.visibility = 'hidden'; });
        return true;
      })()`);
      assert.ok(safe, 'Refusing to capture a page with a bootstrap fragment or visible credential');
      await capture(target, name);
    };
    const restarted = await qualifyRestart({ fixture: restartFixture, origin, makeTarget, cdp, evaluate, ready, waitFor, delay,
      readOutput: () => applicationOutput, restartApplication, captureSafe, sensitiveValues });
    report.restart = restarted.evidence;
    report.requests.restart = restarted.requests;
    report.jobDataCreated = true;
  }
  if (values.mode === 'audit') {
    report.audit = await qualifyAudit({ origin, repo, manifest, evidenceDirectory: root, cdp, makeTarget, evaluate, ready, capture, delay });
    await delay(100); // Drain resource events from the last measured target.
    report.auditVerdict = assertAudit(report.audit, manifest, targets.filter((target) => !target.cspProbe).flatMap((target) => target.responses), origin);
    assert.deepEqual(report.auditVerdict.failures, [], `Packaged audit failures:\n${report.auditVerdict.failures.join('\n')}`);
    assert.ok(targets.filter((target) => !target.cspProbe).every((target) => target.requests.every((entry) => entry.url.startsWith(origin + '/') || entry.url.startsWith('data:'))), 'Audit fetched an external dependency');
    assert.equal(await fs.stat(data).then(() => true, () => false), false, 'Fixture-backed audit created job data');
    report.jobDataCreated = false;
  }
  if (values.mode === 'public' || values.mode === 'session' || values.mode === 'upload' || values.mode === 'metadata' || values.mode === 'history' || values.mode === 'scale' || values.mode === 'source-tree' || values.mode === 'live') {
    const identityExpression = `(() => ({ buildId: document.querySelector('meta[name="decomp-ui-build"]')?.content, applicationVersion: document.querySelector('meta[name="decomp-application-version"]')?.content, page: location.pathname, text: document.body.innerText }))()`;
    const home = await makeTarget();
    await cdp.call('Page.navigate', { url: `${origin}/nested/` }, home.sessionId);
    await ready(home, `document.querySelector('h1')?.textContent === 'Your work, with its evidence'`, 'rendered packaged home');
    await ready(home, `document.activeElement === document.querySelector('main h1')`, 'home heading focus');
    assert.equal(await evaluate(home, `document.querySelectorAll('main').length`), 1, 'Shell must expose one main landmark');
    assert.equal(await evaluate(home, `document.title`), 'Jobs · Decomp Workbench');
    await evaluate(home, `document.querySelector('.skip-link').focus()`);
    const skip = await evaluate(home, `(() => {
      const link = document.querySelector('.skip-link');
      const box = link.getBoundingClientRect();
      return { href: link.getAttribute('href'), visible: box.top >= 0 && box.bottom <= innerHeight,
        outline: getComputedStyle(link).outlineWidth };
    })()`);
    assert.equal(skip.href, '#main');
    assert.equal(skip.visible, true, 'Focused skip link must be visible');
    assert.ok(parseFloat(skip.outline) >= 2, 'Focused skip link must have a visible outline');
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, home.sessionId);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, home.sessionId);
    await ready(home, `document.activeElement === document.querySelector('main') && location.hash === '#main'`, 'keyboard skip navigation');
    const homeIdentity = await evaluate(home, identityExpression);
    assert.equal(homeIdentity.buildId, manifest.buildId);
    assert.equal(homeIdentity.applicationVersion, manifest.applicationVersion);
    const presentation = await ready(home, `(() => { const image = document.querySelector('.brand img'); return image?.complete && image.naturalWidth > 0 ? { icon: image.currentSrc, iconWidth: image.naturalWidth, bodyMargin: getComputedStyle(document.body).margin, layout: getComputedStyle(document.querySelector('.app-layout')).display } : false; })()`, 'packaged icon');
    assert.ok(presentation.icon.startsWith(`${origin}/nested/assets/ui/`));
    assert.equal(presentation.bodyMargin, '0px');
    assert.equal(presentation.layout, 'grid');
    await capture(home, 'home.png');
    await evaluate(home, `document.querySelector('a[href="/nested/upload"]').focus()`);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, home.sessionId);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, home.sessionId);
    await ready(home, `document.querySelector('h1')?.textContent === 'Upload a binary' && document.title === 'Upload a binary · Decomp Workbench' && document.activeElement === document.querySelector('main h1')`, 'keyboard upload route navigation and heading focus');
    assert.equal(home.requests.filter((request) => request.type === 'Document').length, 1, 'Upload client navigation reloaded the document');
    await cdp.call('Page.reload', {}, home.sessionId);
    await ready(home, `document.querySelector('h1')?.textContent === 'Upload a binary' && document.querySelector('nav[aria-label="Breadcrumbs"]')?.textContent.includes('All jobs')`, 'upload direct reload');
    await ready(home, `document.activeElement === document.querySelector('main h1')`, 'direct upload heading focus');
    assert.equal(await evaluate(home, 'location.pathname'), '/nested/upload');
    assert.equal(home.requests.filter((request) => request.method !== 'GET').length, 0);
    report.uploadRoute = { clientNavigation: true, directReload: true, pageTitle: true, breadcrumbs: true, mutationRequests: 0 };

    await evaluate(home, `document.querySelector('a[href="/nested/runtime"]').focus()`);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, home.sessionId);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, home.sessionId);
    await ready(home, `document.querySelector('h1')?.textContent === 'Runtime status' && document.body.innerText.includes(${JSON.stringify(manifest.buildId)}) && document.activeElement === document.querySelector('main h1')`, 'lazy packaged Runtime identity and heading focus');
    await evaluate(home, `history.back()`);
    await ready(home, `location.pathname === '/nested/upload' && document.querySelector('main h1')?.textContent === 'Upload a binary' && document.activeElement === document.querySelector('main h1')`, 'browser Back restores upload heading focus');
    await evaluate(home, `history.forward()`);
    await ready(home, `location.pathname === '/nested/runtime' && document.querySelector('main h1')?.textContent === 'Runtime status' && document.activeElement === document.querySelector('main h1')`, 'browser Forward restores Runtime heading focus');
    const runtimeIdentity = await evaluate(home, identityExpression);
    assert.equal(runtimeIdentity.page, '/nested/runtime');
    assert.ok(runtimeIdentity.text.includes(manifest.applicationVersion));
    assert.ok(runtimeIdentity.text.includes(manifest.buildId));
    assert.ok(runtimeIdentity.text.includes('Runtime information is not connected'));
    assert.equal(home.requests.filter((entry) => entry.type === 'Document').length, 2, 'Runtime client navigation added a document load after the explicit upload reload');
    assert.deepEqual(home.exceptions, []);
    await capture(home, 'runtime.png');
    const runtimeAsset = manifest.files.find((entry) => /^assets\/Runtime-.+\.js$/.test(entry.path));
    assert.ok(runtimeAsset, 'Expected the runtime lazy chunk in the packaged manifest');
    const runtimeUrl = `${origin}/nested/assets/ui/${runtimeAsset.path}`;
    assert.ok(home.responses.some((entry) => entry.url === runtimeUrl && entry.status === 200));
    assert.ok(home.responses.some((entry) => entry.type === 'Stylesheet' && entry.status === 200));
    const ax = await cdp.call('Accessibility.getFullAXTree', {}, home.sessionId);
    assert.equal(ax.nodes.filter((node) => !node.ignored && node.role?.value === 'main').length, 1, 'Accessibility tree must expose one main landmark');
    assert.ok(ax.nodes.some((node) => !node.ignored && node.role?.value === 'heading' && node.name?.value === 'Runtime status'), 'Accessibility tree must expose the Runtime heading');
    report.home = { heading: 'Your work, with its evidence', ...presentation, identity: homeIdentity,
      accessibility: { mainLandmarks: 1, skipLinkKeyboard: true, visibleSkipFocus: true,
        headingFocus: ['home', 'upload', 'direct-upload', 'runtime-lazy', 'back', 'forward'], accessibilityTree: true } };
    report.runtime = { identity: runtimeIdentity, lazyChunk: runtimeAsset.path, responseStatus: 200 };
    console.log('Packaged home, CSS/icon, lazy Runtime and exact manifest identities verified.');

    const boundary = await makeTarget();
    const missingRoute = '/nested/not-a-packaged-route';
    await cdp.call('Page.navigate', { url: origin + '/nested/' }, boundary.sessionId);
    await ready(boundary, `document.querySelector('h1')?.textContent === 'Your work, with its evidence'`, 'not-found fixture home');
    await evaluate(boundary, `history.pushState({}, '', '${missingRoute}'); dispatchEvent(new PopStateEvent('popstate'))`);
    await ready(boundary, `document.querySelector('h1')?.textContent === 'This page could not be found'`, 'packaged client not-found route');
    await cdp.call('Page.reload', {}, boundary.sessionId);
    await ready(boundary, `document.readyState === 'complete' && document.body.innerText.length > 0`, 'inert missing-route reload');
    assert.ok(boundary.responses.some((response) => response.url === origin + missingRoute && response.status === 404));
    const inertRoute = '/nested/api/v1/bootstrap';
    await cdp.call('Page.navigate', { url: origin + inertRoute }, boundary.sessionId);
    await ready(boundary, `document.contentType === 'application/json' && document.body.innerText.length > 0`, 'inert API navigation');
    assert.ok(boundary.responses.some((response) => response.url === origin + inertRoute && response.status === 401));
    assert.deepEqual(boundary.exceptions, []);
    const redirect = await makeTarget();
    await cdp.call('Page.navigate', { url: origin + '/nested/runtime/' }, redirect.sessionId);
    await ready(redirect, `location.pathname === '/nested/runtime' && document.querySelector('h1')?.textContent === 'Runtime status'`, 'packaged canonical route redirect');
    const redirectHops = redirect.documentRequests;
    assert.equal(redirectHops.length, 2, 'Canonical route redirect did not produce two Document request hops');
    assert.deepEqual(redirectHops.map((hop) => [hop.route, hop.status, hop.source]), [
      ['/nested/runtime/', 308, 'requestWillBeSent.redirectResponse'],
      ['/nested/runtime', 200, 'responseReceived'],
    ]);
    assert.deepEqual(redirect.exceptions, []);
    report.routeBoundaries = { notFoundClientNavigation: true, missingRouteReloadInert: true,
      inertJsonNavigation: true, canonicalRedirectDocumentHops: 2 };

    const recovery = await makeTarget();
    const interceptionErrors = [];
    let intercepted = 0;
    cdp.on('Fetch.requestPaused', (event) => {
      intercepted += 1;
      cdp.call('Fetch.fulfillRequest', { requestId: event.requestId, responseCode: 404, responseHeaders: [{ name: 'Content-Type', value: 'text/plain' }], body: Buffer.from('Unavailable application chunk fixture').toString('base64') }, recovery.sessionId).catch((error) => interceptionErrors.push(error.message));
    }, recovery.sessionId);
    await cdp.call('Fetch.enable', { patterns: [{ urlPattern: runtimeUrl, requestStage: 'Request' }] }, recovery.sessionId);
    await cdp.call('Page.navigate', { url: `${origin}/nested/` }, recovery.sessionId);
    await ready(recovery, `document.querySelector('h1')?.textContent === 'Your work, with its evidence'`, 'second packaged home');
    await evaluate(recovery, `document.querySelector('a[href="/nested/runtime"]').click()`);
    await ready(recovery, `document.querySelector('h1')?.textContent === 'This view is unavailable' && document.querySelector('#asset-notice-title')?.textContent === 'The application may have updated'`, 'missing-chunk recovery notice');
    await delay(5000);
    const warning = await evaluate(recovery, `({ notices: document.querySelectorAll('[role="alert"]').length, buttons: [...document.querySelectorAll('button')].map((button) => ({text:button.textContent,disabled:button.disabled})), text: document.body.innerText })`);
    assert.equal(warning.notices, 1);
    assert.ok(warning.buttons.some((button) => button.text === 'Reload application' && !button.disabled));
    assert.ok(warning.text.includes(manifest.buildId));
    assert.equal(intercepted, 1, 'Lazy chunk was automatically retried');
    assert.equal(recovery.requests.filter((entry) => entry.type === 'Document').length, 1, 'Page reloaded automatically');
    assert.deepEqual(interceptionErrors, []);
    assert.deepEqual(recovery.exceptions, []);
    assert.ok(await evaluate(recovery, `document.querySelector('#asset-notice-title').getBoundingClientRect().top >= 0`), 'Recovery title scrolled above viewport');
    await capture(recovery, 'recovery.png');
    await cdp.call('Fetch.disable', {}, recovery.sessionId);
    try {
      await evaluate(recovery, `[...document.querySelectorAll('button')].find((button) => button.textContent === 'Reload application').click()`);
    } catch (error) {
      if (!/context|navigat/i.test(error.message)) throw error;
    }
    await ready(recovery, `document.querySelector('h1')?.textContent === 'Runtime status' && document.body.innerText.includes(${JSON.stringify(manifest.buildId)}) && document.querySelectorAll('[role="alert"]').length === 0`, 'explicit reload recovery');
    await delay(1000);
    assert.equal(recovery.requests.filter((entry) => entry.type === 'Document').length, 2, 'Explicit reload was not exactly one document request');
    assert.equal(intercepted, 1);
    assert.ok(recovery.responses.some((entry) => entry.url === runtimeUrl && entry.status === 200));
    const allRequests = [...home.requests, ...recovery.requests];
    assert.ok(allRequests.every((entry) => ['GET', 'HEAD'].includes(entry.method)), 'Navigation/recovery sent a mutation');
    assert.ok(allRequests.every((entry) => entry.url.startsWith(origin + '/')), 'Browser fetched an external dependency');
    assert.deepEqual(recovery.exceptions, []);
    assert.equal(await fs.stat(data).then(() => true, () => false), populated, 'Public SPA browsing changed job-root existence');
    report.recovery = { interceptedLazyChunk: runtimeAsset.path, simulatedStatus: 404, warningCount: warning.notices, observationSeconds: 5, automaticReloads: 0, automaticChunkRetries: 0, explicitReloadDocumentRequests: 1, recoveredRuntime: true, mutationRequests: 0, noticeTitleWithinViewport: true };
    report.jobDataCreated = false;
    report.requests = { normal: home.requests, boundary: boundary.requests, redirect: redirect.requests, recovery: recovery.requests };
  }

  if (values.mode === 'proxy') {
    vite = startOwned(process.execPath, [join(repo, 'frontend/node_modules/vite/bin/vite.js'), '--mode', 'backend'], {
      cwd: join(repo, 'frontend'), env: { ...process.env, DECOMP_DEV_BACKEND_ORIGIN: origin,
        DECOMP_DEV_BASE_PATH: '/nested/', DECOMP_DEV_PORT: String(developmentPort) },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    vite.stderr.on('data', (chunk) => { viteError = (viteError + chunk).slice(-1048576); });
    await waitFor(async () => {
      if (vite.exitCode !== null || vite.signalCode !== null) throw new Error(`Vite exited: ${viteError}`);
      try { return (await fetch(browserOrigin + '/nested/')).ok; } catch { return false; }
    }, 'explicit Vite backend proxy');
    report.frontendOrigin = browserOrigin;
    report.requests = {};
  }

  if (values.mode === 'session' || values.mode === 'upload' || values.mode === 'metadata' || values.mode === 'history' || values.mode === 'scale' || values.mode === 'source-tree' || values.mode === 'live' || values.mode === 'proxy') {
    const bootstrapUrl = await waitFor(() => applicationOutput.split(/\s+/).find((part) => part.startsWith(browserOrigin + '/nested/#bootstrap=')), 'local bootstrap handoff');
    const token = new URL(bootstrapUrl).hash.slice('#bootstrap='.length);
    sensitiveValues.push(token);
    const authenticated = await makeTarget();
    let hmrConnected = false;
    cdp.on('Network.webSocketFrameReceived', (event) => {
      if (event.response.payloadData.includes('"type":"connected"')) hmrConnected = true;
    }, authenticated.sessionId);
    await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
      const requests = []; Object.defineProperty(window, '__sessionTestRequests', { value: requests });
      const original = window.fetch;
      window.fetch = function(input, options) {
        requests.push({ path: new URL(typeof input === 'string' ? input : input.url, location.href).pathname, method: options?.method ?? 'GET', fragmentEmpty: location.hash === '' });
        return original.apply(this, arguments);
      };
    })();` }, authenticated.sessionId);
    const authenticationUrl = new URL(bootstrapUrl);
    if (sourceTreeFixture) authenticationUrl.pathname = '/nested/runtime';
    await cdp.call('Page.navigate', { url: authenticationUrl.href }, authenticated.sessionId);
    await ready(authenticated, `document.body.innerText.includes('Local session connected.')`, 'authenticated packaged session');
    if (sourceTreeFixture) {
      await ready(authenticated, `document.querySelector('h1')?.textContent === 'Runtime status'`, 'authenticated source-tree session route');
      report.sourceTreeScale = await qualifySourceTree({ fixture: sourceTreeFixture, makeTarget, cdp, evaluate, ready,
        browserOrigin, serverPid: application.pid, profile: values.profile });
      report.sourceTreeScale.coldFirstDataPage = {
        profile: sourceTreeColdSummary.profile,
        requiredSamples: sourceTreeColdSummary.gate.requiredSamples,
        attemptedSamples: sourceTreeColdSummary.gate.attemptedSamples,
        successfulSamples: sourceTreeColdSummary.gate.successfulSamples,
        failedSamples: sourceTreeColdSummary.gate.failedSamples,
        medianMs: sourceTreeColdSummary.medianMs,
        nearestRankP95Ms: sourceTreeColdSummary.nearestRankP95Ms,
        gate: sourceTreeColdSummary.gate,
        fullSamplesAt: 'sourceTreeColdSamples.samples',
      };
      report.jobDataCreated = true;
      report.session = { authenticated: true, sessionRoute: '/nested/runtime', jobDataCreated: true,
        automaticMutationRetries: 0, installationUnchanged: true };
      report.requests.authenticated = authenticated.requests;
    } else {
    if (values.mode === 'proxy') {
      await waitFor(() => hmrConnected, 'real Vite HMR connection');
      report.hmrConnected = true;
      const apiProof = await evaluate(authenticated, `fetch('/nested/api/v1/bootstrap', { credentials: 'same-origin' }).then(async response => ({ status: response.status, cors: response.headers.get('access-control-allow-origin'), buildId: (await response.json()).data.uiBuildId }))`);
      assert.equal(apiProof.status, 200);
      assert.equal(apiProof.cors, null);
      assert.equal(apiProof.buildId, manifest.buildId);
      report.backendBootstrap = apiProof;
    }
    await ready(authenticated, `document.body.innerText.includes('${libraryText}')`, 'persistent job library');
    await evaluate(authenticated, `(() => {
      const field = [...document.querySelectorAll('label')].find(label => label.textContent.startsWith('Filename or label search')).querySelector('input');
      field.value = 'absent fixture'; field.dispatchEvent(new Event('input', { bubbles: true }));
    })()`);
    await evaluate(authenticated, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Apply filters').click()`);
    await ready(authenticated, `document.body.innerText.includes('No jobs match these filters.')`, 'filtered empty job library');
    assert.equal(dashboardFiltersWithSnapshot(await evaluate(authenticated, 'location.search')), '?search=absent+fixture');
    await cdp.call('Page.reload', {}, authenticated.sessionId);
    await ready(authenticated, `document.body.innerText.includes('Local session connected.') && document.body.innerText.includes('No jobs match these filters.')`, 'saved job filters after reload');
    await evaluate(authenticated, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Reset filters').click()`);
    await ready(authenticated, `document.body.innerText.includes('${libraryText}')`, 'reset job library');
    assert.equal(dashboardFiltersWithSnapshot(await evaluate(authenticated, 'location.search')), '');
    report.dashboard = { emptyLibrary: !populated, populatedLibrary: populated, noMatches: true, filtersSurviveReload: true, resetFilters: true };
    if (historyFixture) {
      const row = await evaluate(authenticated, `(() => {
        const row = document.querySelector('ul[aria-label="Uploaded jobs"] li');
        const facts = Object.fromEntries([...row.querySelectorAll('dt')].map(dt => [dt.textContent, dt.nextElementSibling.textContent]));
        return { facts, href: row.querySelector('a').getAttribute('href'), count: document.querySelector('ul[aria-label="Uploaded jobs"]').children.length };
      })()`);
      assert.equal(row.count, 1);
      assert.equal(row.href, '/nested/jobs/' + historyFixture.jobId);
      assert.equal(row.facts.Size, '64 bytes');
      assert.equal(Date.parse(row.facts.Created), Date.parse(JSON.parse(historyFixture.retained['job.json']).created_at));
      assert.equal(row.facts['Workflow state'], 'Completed');
      assert.equal(row.facts['Latest attempt'], 'run_fixture_54');
      assert.equal(row.facts['Accepted revision'], 'No accepted revision recorded');
      assert.ok(row.facts.Updated);
      report.dashboard.exactRowMetadata = true;
      report.dashboard.jobAndRunIdentityDistinct = true;
    }
    const firstRequests = await evaluate(authenticated, 'window.__sessionTestRequests');
    assert.ok(firstRequests.length >= 2);
    assert.ok(firstRequests.every((request) => request.fragmentEmpty));
    assert.equal(authenticated.requests.filter((request) => request.method === 'POST').length, 1);
    assert.equal(await evaluate(authenticated, 'location.hash'), '');
    assert.equal(await evaluate(authenticated, `document.body.innerText.includes(${JSON.stringify(token)})`), false);
    const cookies = (await cdp.call('Network.getCookies', { urls: [browserOrigin + '/nested/'] }, authenticated.sessionId)).cookies;
    const localCookie = cookies.find((cookie) => cookie.path === '/nested/' && cookie.httpOnly);
    assert.ok(localCookie, 'Expected HttpOnly local session cookie');
    assert.equal(localCookie.sameSite, 'Strict');
    assert.equal(localCookie.secure, false);
    assert.equal(await evaluate(authenticated, 'localStorage.length + sessionStorage.length'), 0);
    await evaluate(authenticated, `document.querySelector('a[href="/nested/runtime"]').click()`);
    await ready(authenticated, `document.querySelector('h1')?.textContent === 'Runtime status' && document.querySelector('#server-runtime-title')?.textContent === 'Connected server'`, 'authenticated Runtime');
    assert.equal((await evaluate(authenticated, 'window.__sessionTestRequests')).length, firstRequests.length,
      'Opening Runtime issued a probe or another bootstrap request');
    // The packaged environment configures no agent: agent options report that reason, unimplemented workflows say so.
    assert.ok(await evaluate(authenticated, `(() => { const text = document.body.innerText; return text.includes('workflow-reconstruct-agent: unavailable')
      && text.includes('HARNESS_NOT_CONFIGURED') && text.includes('workflow-build: unsupported') && text.includes('WORKFLOW_NOT_IMPLEMENTED')
      && !text.includes('Workflow actions are unavailable in this preview.') && text.includes('33554432 bytes'); })()`));
    const scheduler = await evaluate(authenticated, `(() => {
      const section = document.querySelector('section[aria-labelledby="scheduler-title"]');
      return { text: section.innerText, values: Array.from(section.querySelectorAll('dd')).map(node => node.textContent), sampledAt: section.querySelector('time')?.dateTime };
    })()`);
    assert.deepEqual(scheduler.values, ['running', '0', '2', '0', '32']);
    assert.ok(scheduler.text.includes('approximate aggregate observations') && scheduler.text.includes('own approximate queue position is shown on its attempt page'));
    assert.ok(Number.isFinite(Date.parse(scheduler.sampledAt)));
    const retention = await evaluate(authenticated, `(() => {
      const section = document.querySelector('section[aria-labelledby="retention-title"]');
      return { text: section.innerText, values: Array.from(section.querySelectorAll('dd')).map(node => node.textContent), sampledAt: section.querySelector('time')?.dateTime };
    })()`);
    assert.ok(retention.text.includes('Periodic progress cleanup is enabled.') && retention.text.includes('reset on restart') && retention.text.includes('does not promise an exact expiry time'));
    assert.ok(retention.values.slice(0, 3).every(value => /^(0|[1-9][0-9]*)$/.test(value)));
    assert.ok(Number.isFinite(Date.parse(retention.sampledAt)));
    report.runtimeSnapshot = { retention: { enabled: true, processLocalCounters: true, sampledAt: retention.sampledAt, boundedScanExplained: true }, connected: true, unavailableCapabilitiesExplained: true, scheduler: { approximate: true, lifecycle: 'running', activeWorkers: 0, workerLimit: 2, queuedTasks: 0, queueCapacity: 32, sampledAt: scheduler.sampledAt, queuePositionUnknown: true }, navigationRequests: 0 };

    await cdp.call('Page.reload', {}, authenticated.sessionId);
    await ready(authenticated, `document.querySelector('h1')?.textContent === 'Runtime status' && document.body.innerText.includes('Local session connected.')`, 'cookie session restored after reload');
    assert.equal(authenticated.requests.filter((request) => request.method === 'POST').length, 1);
    const postReload = await evaluate(authenticated, 'window.__sessionTestRequests');
    assert.ok(postReload.every((request) => request.method === 'GET' && request.fragmentEmpty));
    await capture(authenticated, 'authenticated-runtime.png');
    const jobTab = await makeTarget();
    const absentJobPath = '/nested/jobs/' + 'a'.repeat(32);
    await cdp.call('Page.navigate', { url: browserOrigin + absentJobPath }, jobTab.sessionId);
    await ready(jobTab, `document.querySelector('h1')?.textContent === 'Job overview' && document.body.innerText.includes('This job is unavailable. It may have been removed.')`, 'durable job deep link');
    await cdp.call('Page.reload', {}, jobTab.sessionId);
    await ready(jobTab, `document.querySelector('h1')?.textContent === 'Job overview' && document.body.innerText.includes('This job is unavailable. It may have been removed.')`, 'durable job refresh');
    assert.ok(jobTab.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
    assert.deepEqual(jobTab.exceptions, []);
    report.dashboard.jobDeepLinkAndRefresh = true;
    report.dashboard.missingJobExplained = true;
    report.requests.job = jobTab.requests;
    const runTab = await makeTarget();
    await cdp.call('Page.navigate', { url: browserOrigin + absentJobPath + '/runs/run_missing' }, runTab.sessionId);
    await ready(runTab, `document.querySelector('h1')?.textContent === 'Workflow attempt' && document.body.innerText.includes('This attempt is unavailable for this job.')`, 'pinned attempt deep link');
    await cdp.call('Page.reload', {}, runTab.sessionId);
    await ready(runTab, `document.title === 'Workflow attempt · Decomp Workbench' && document.body.innerText.includes('This attempt is unavailable for this job.')`, 'pinned attempt reload');
    assert.equal(await evaluate(runTab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'Return to job overview')?.getAttribute('href')`), absentJobPath);
    assert.ok(runTab.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
    assert.deepEqual(runTab.exceptions, []);
    report.attemptRoute = { directLink: true, reload: true, missingExplained: true, exactJobReturn: true, mutationRequests: 0 };
    report.requests.attempt = runTab.requests;
    await evaluate(runTab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'Browse attempt history').click()`);
    await ready(runTab, `document.querySelector('h1')?.textContent === 'Attempt history' && document.body.innerText.includes('Attempt history is unavailable. Check the job and local session.')`, 'attempt history navigation');
    await cdp.call('Page.reload', {}, runTab.sessionId);
    await ready(runTab, `document.title === 'Attempt history · Decomp Workbench' && document.body.innerText.includes('Attempt history is unavailable. Check the job and local session.')`, 'attempt history reload');
    assert.ok(runTab.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
    report.attemptHistory = { navigation: true, directReload: true, missingExplained: true, mutationRequests: 0 };

    if (scaleFixture) report.scale = await qualifyScale({ fixture: scaleFixture, makeTarget, cdp, evaluate, ready, browserOrigin });
    if (liveFixture) {
      report.liveDashboard = await qualifyLive({ fixture: liveFixture, makeTarget, cdp, evaluate, ready, waitFor, browserOrigin });
      report.jobDataCreated = true;
    }
    if (historyFixture) {
      report.populatedHistory = await qualifyHistory({ fixture: historyFixture, makeTarget, cdp, evaluate, ready, browserOrigin });
      report.jobDataCreated = true;
    }
    if (values.mode === 'metadata') {
      report.upload = await qualifyUpload({ makeTarget, cdp, evaluate, ready, browserOrigin, data });
      report.jobDataCreated = true;
    }
    if (values.mode === 'upload') {
      report.upload = await qualifyUpload({ makeTarget, cdp, evaluate, ready, browserOrigin, data });
      report.uploadFailures = await qualifyUploadFailures({ makeTarget, cdp, evaluate, ready, browserOrigin, data });
      report.measuredUpload = await qualifyMeasuredUpload({ makeTarget, cdp, evaluate, ready, waitFor, browserOrigin, data });
      report.jobDataCreated = true;
    }

    // A tab without peer notifications must still reconcile a server rejection.
    let unnotified;
    let unnotifiedState;
    if (historyFixture) {
      unnotified = await makeTarget();
      await cdp.call('Page.addScriptToEvaluateOnNewDocument', {
        source: "Object.defineProperty(globalThis, 'BroadcastChannel', { value: undefined, configurable: true });",
      }, unnotified.sessionId);
      await cdp.call('Page.navigate', { url: browserOrigin + `/nested/jobs/${historyFixture.jobId}/runs/run_fixture_3` }, unnotified.sessionId);
      await cdp.call('Page.bringToFront', {}, unnotified.sessionId);
      await ready(unnotified, `document.querySelector('section[aria-label="Progress retention"]') !== null`, 'unnotified private attempt');
      await evaluate(unnotified, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Read progress pin').click()`);
      await ready(unnotified, `document.body.innerText.includes('Progress history is not pinned.')`, 'unnotified initial policy');
      assert.equal(await evaluate(unnotified, 'typeof BroadcastChannel'), 'undefined');
      unnotifiedState = await fs.readFile(join(historyFixture.directory, 'workflow-state.json'));
    }

    const peer = await makeTarget();
    await cdp.call('Page.navigate', { url: browserOrigin + '/nested/runtime' }, peer.sessionId);
    await ready(peer, `document.querySelector('#server-runtime-title') !== null`, 'peer private Runtime');
    await evaluate(peer, `(() => {
      window.__sessionInvalidations = [];
      window.__sessionInvalidationChannel = new BroadcastChannel('decomp-session-v1:/nested');
      window.__sessionInvalidationChannel.onmessage = event => window.__sessionInvalidations.push(event.data);
    })()`);
    const peerReads = peer.requests.filter(request => request.url.includes('/api/v1/')).length;
    assert.ok(peerReads > 0);
    await evaluate(authenticated, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Sign out').click()`);
    await ready(authenticated, `document.body.innerText.includes('You signed out of this browser.')`, 'explicit logout');
    assert.equal(authenticated.requests.filter((request) => request.method === 'DELETE').length, 1);
    assert.equal(await evaluate(authenticated, `document.querySelector('#server-runtime-title') !== null`), false, 'Logout retained private runtime evidence');
    report.runtimeSnapshot.clearedOnLogout = true;
    await ready(peer, `document.body.innerText.includes('Another tab reported a session change.') && window.__sessionInvalidations.length === 1`, 'cross-tab private data invalidation');
    assert.equal(await evaluate(peer, `document.querySelector('#server-runtime-title') !== null`), false);
    assert.deepEqual(await evaluate(peer, 'window.__sessionInvalidations'), [{ version: 1, type: 'session-invalidated' }]);
    await delay(3000);
    assert.equal(peer.requests.filter(request => request.url.includes('/api/v1/')).length, peerReads, 'Peer invalidation must not initiate requests');
    assert.ok(peer.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
    assert.deepEqual(peer.exceptions, []);
    assert.equal(await evaluate(peer, 'localStorage.length + sessionStorage.length'), 0);
    await evaluate(peer, 'window.__sessionInvalidationChannel.close()');
    report.sessionInvalidation = { privateRuntimeCleared: true, credentialFreeMessage: true, automaticPeerRequests: 0, peerMutationRequests: 0, storageEntries: 0 };

    if (unnotified) {
      assert.equal(await evaluate(unnotified, `document.querySelector('section[aria-label="Progress retention"]') !== null`), true,
        'The test tab unexpectedly received a peer invalidation');
      await cdp.call('Page.bringToFront', {}, unnotified.sessionId);
      await ready(unnotified, `[...document.querySelectorAll('button')].some(button => button.textContent === 'Read progress pin' && !button.disabled)`, 'unnotified tab foreground controls');
      const before = unnotified.requests.length;
      await evaluate(unnotified, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Read progress pin').click()`);
      await ready(unnotified, `document.body.innerText.includes('To access private work, open the sign-in link') && document.body.innerText.includes('Connect a local session to view this attempt.')`, 'server rejection clears shared attempt state');
      assert.equal(await evaluate(unnotified, `document.querySelector('section[aria-label="Progress retention"]') === null && document.querySelector('ol[aria-label="Activity observations"]') === null`), true);
      await delay(3000);
      const requests = unnotified.requests.slice(before);
      assert.equal(requests.length, 1, 'Session rejection must not trigger automatic probes or retries');
      assert.equal(requests[0].method, 'GET');
      assert.equal(requests[0].url, browserOrigin + `/nested/api/v1/jobs/${historyFixture.jobId}/runs/run_fixture_3/progress-pin`);
      assert.ok(unnotified.responses.some(response => response.url === requests[0].url && response.status === 401), 'Expected an actual server HTTP 401');
      assert.ok(unnotified.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
      assert.equal(await evaluate(unnotified, 'localStorage.length + sessionStorage.length'), 0);
      assert.deepEqual(unnotified.exceptions, []);
      assert.deepEqual(await fs.readFile(join(historyFixture.directory, 'workflow-state.json')), unnotifiedState);
      report.unnotifiedSessionRevocation = { peerNotificationsUnavailable: true, privateAttemptRetainedUntilRead: true,
        actualServer401: true, sharedAttemptStateCleared: true, pinControlsRemoved: true, activityRemoved: true,
        privateReadRequests: 1, automaticFollowupRequests: 0, mutationRequests: 0, workflowStateUnchanged: true, storageEntries: 0 };
      report.requests.unnotified = unnotified.requests;
    }

    await cdp.call('Page.reload', {}, authenticated.sessionId);
    await ready(authenticated, `document.body.innerText.includes('To access private work, open the sign-in link')`, 'revoked session after reload');
    await cdp.call('Page.navigate', { url: bootstrapUrl }, authenticated.sessionId);
    await ready(authenticated, `document.body.innerText.includes('This sign-in link is no longer available.')`, 'consumed link denial');
    await delay(5000);
    assert.equal(authenticated.requests.filter((request) => request.method === 'POST').length, 2);
    assert.equal(authenticated.requests.filter((request) => request.method === 'DELETE').length, 1);
    assert.equal(await evaluate(authenticated, 'location.hash'), '');
    assert.deepEqual(authenticated.exceptions, []);
    assert.equal(await evaluate(authenticated, 'localStorage.length + sessionStorage.length'), 0);
    assert.ok(authenticated.requests.every((request) => request.url.startsWith(browserOrigin + '/')));
    assert.ok(authenticated.requests.every((request) => ['GET', 'HEAD'].includes(request.method) || request.url === browserOrigin + '/nested/api/v1/session'));
    assert.equal(await fs.stat(data).then(() => true, () => false), values.mode === 'upload' || values.mode === 'metadata' || populated);
    report.session = { authenticated: true, cookie: { httpOnly: true, sameSite: 'Strict', path: '/nested/', secure: false }, fragmentRemovedBeforeFetch: true, restoredAfterReload: true, explicitLogoutRequests: 1, successfulExchangeRequests: 1, consumedLinkRequests: 1, automaticMutationRetries: 0, storageEntries: 0, installationUnchanged: true, jobDataCreated: values.mode === 'upload' || values.mode === 'metadata' || populated };
    report.requests.authenticated = authenticated.requests;
    }
  }

  }
  // Let the final DevTools events drain before taking the evidence snapshot.
  await delay(100);
  report.contentSecurityPolicy = cspEvidence();
  assert.equal(report.contentSecurityPolicy.violationCount, 0,
    `Browser observed CSP violations: ${JSON.stringify(report.contentSecurityPolicy.inspectedTargets)}`);
  assert.ok(report.contentSecurityPolicy.documentRequestCount > 0, 'No packaged Document request was inspected for CSP');
  assert.equal(report.contentSecurityPolicy.documentResponseCount, report.contentSecurityPolicy.documentRequestCount,
    'Not every packaged Document request was correlated to a response');
  assert.deepEqual(report.contentSecurityPolicy.unresolvedDocumentRequests, [],
    'A packaged Document request did not receive a correlated response');
  assert.deepEqual(report.contentSecurityPolicy.orphanDocumentResponses, [],
    'A packaged Document response did not correlate to its request');
  assert.deepEqual(report.contentSecurityPolicy.invalidDocumentUrls, [],
    'A packaged Document request or response had an invalid URL');
  if (values.mode !== 'proxy') assert.deepEqual(report.contentSecurityPolicy.missingPolicyDocuments, [],
    'A packaged production Document response omitted CSP');
  assert.deepEqual(report.contentSecurityPolicy.unsafePolicyDocuments, [],
    'A packaged Document response enabled unsafe-inline or unsafe-eval');
  if (values.mode === 'source-tree' && !sourceTreeColdSummary?.gate?.passed) {
    throw new Error('The fresh-process source-tree cold-page gate failed');
  }
  if (externalCancellation) throw new Error(`Packaged source-tree run was cancelled by ${externalCancellation}`);
  assert.deepEqual(await snapshot(installation.app), installation.before, 'Read-only installation bytes changed');
  report.installationUnchanged = true;

  report.status = 'passed';

} catch (error) {
  report.status = 'failed';
  report.contentSecurityPolicy = cspEvidence();
  report.error = safeDiagnostic(error.stack);
  report.applicationError = safeDiagnostic(applicationError);
  report.browserError = safeDiagnostic(browserError);
  report.viteError = safeDiagnostic(viteError);
  console.error(safeDiagnostic(error.stack));
  process.exitCode = 1;
  if (lastTarget && cdp && lastTarget.initializationComplete) {
    try {
      // Fail closed if the handoff has not been scrubbed. Hide editable fields
      // before a diagnostic capture, and never capture visible credential text.
      const safe = await evaluate(lastTarget, `(() => {
        if (location.hash !== '' || ${JSON.stringify(sensitiveValues)}.some(value => document.body.innerText.includes(value))) return false;
        document.querySelectorAll('input, textarea, [contenteditable]').forEach(element => { element.style.visibility = 'hidden'; });
        return true;
      })()`);
      if (safe) {
        await capture(lastTarget, 'failure.png');
        report.failureScreenshot = 'failure.png';
      } else report.failureScreenshotSkipped = 'Uncleared fragment or visible handoff credential';
    } catch {
      report.failureScreenshotSkipped = 'Attached page unavailable within the bounded DevTools request deadline';
    }
  } else if (lastTarget && !lastTarget.initializationComplete) report.failureScreenshotSkipped = 'Target initialization failed before page commands completed';
} finally {
  if (cdp) await cdp.call('Browser.close').catch(() => {});
  const cleanup = await Promise.allSettled([stop(browser), stop(application), stop(vite)]);
  const coldSupervisorShutdownConfirmed = values.mode !== 'source-tree'
    || !coldSupervisorLaunched || coldSupervisorCleanupConfirmed;
  if (values.mode === 'source-tree') report.coldSupervisorShutdownConfirmed = coldSupervisorShutdownConfirmed;
  if (values.mode === 'restart' && application && forcedKill.has(application)) {
    report.status = 'failed'; report.forcedShutdown = true; process.exitCode = 1;
  }
  report.shutdownConfirmed = cleanup.every((result) => result.status === 'fulfilled') && coldSupervisorShutdownConfirmed;
  if (externalCancellation) {
    report.status = 'failed';
    report.externalCancellation = externalCancellation;
    process.exitCode = 1;
  }
  if (!report.shutdownConfirmed) {
    report.status = 'failed';
    report.cleanupErrors = cleanup.filter((result) => result.status === 'rejected').map((result) => safeDiagnostic(result.reason));
    process.exitCode = 1;
  }
  report.cdpTargetDiagnostics = cdpDiagnostics.snapshot();
  report.workRetained = true;
  if (report.shutdownConfirmed && !values['keep-workdir']) {
    try {
      await removeOwnedWork();
      await fs.rm(profile, { recursive: true, force: true });
      if (browserTmp) await fs.rm(browserTmp, { recursive: true, force: true });
      report.workRetained = false;
      report.workCleanupConfirmed = true;
    } catch (error) {
      report.status = 'failed';
      report.workCleanupConfirmed = false;
      report.workCleanupError = safeDiagnostic(error.stack);
      process.exitCode = 1;
    }
  }
  await externalizeSourceTreeRequestEvidence();
  const retained = scrubTokens(boundReport(report), sensitiveValues);
  await fs.writeFile(join(root, 'report.json'), JSON.stringify(retained, null, 2) + '\n');
  if (values['cold-report']) await fs.writeFile(values['cold-report'], JSON.stringify(retained, null, 2) + '\n');
  if (externalCancellation && (retained.externalCancellation !== externalCancellation || retained.status !== 'failed')) {
    report.status = 'failed';
    report.externalCancellation = externalCancellation;
    const cancelledReport = scrubTokens(boundReport(report), sensitiveValues);
    await fs.writeFile(join(root, 'report.json'), JSON.stringify(cancelledReport, null, 2) + '\n');
    if (values['cold-report']) await fs.writeFile(values['cold-report'], JSON.stringify(cancelledReport, null, 2) + '\n');
  }
  finalReportWritten = true;
  if (externalCancellation) process.exitCode = 1;
  console.log(JSON.stringify(retained, null, 2));
  console.log(`Shutdown ${report.shutdownConfirmed ? 'confirmed' : 'UNCONFIRMED'}. Report: ${join(root, 'report.json')}`);
}
