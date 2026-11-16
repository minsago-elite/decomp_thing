import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = await fs.realpath(resolve(dirname(fileURLToPath(import.meta.url)), '..'));
const driver = join(repo, 'scripts/check-packaged-web-browser.mjs');
const supervisor = join(repo, 'scripts/packaged-browser-process-supervisor.py');
const args = process.argv.slice(2);
const optionValue = (name, fallback) => {
  const index = args.indexOf(name);
  if (index < 0) {
    const inline = args.find(argument => argument.startsWith(`${name}=`));
    return inline ? inline.slice(name.length + 1) : fallback;
  }
  assert.ok(index + 1 < args.length && !args[index + 1].startsWith('--'), `${name} requires a value`);
  return args[index + 1];
};
assert.equal(optionValue('--mode', 'source-tree'), 'source-tree', 'This wrapper only runs source-tree mode');
const python = optionValue('--python', '/usr/bin/python3');
const workParent = optionValue('--work-parent', join(repo, 'build'));
for (const [label, path] of [['python', python], ['work parent', workParent]]) {
  assert.ok(isAbsolute(path), `${label} path must be absolute`);
}
await fs.access(python);
assert.ok((await fs.stat(workParent)).isDirectory(), '--work-parent must already exist');
const canonicalWorkParent = await fs.realpath(workParent);
const workParentRelative = relative(repo, canonicalWorkParent);
assert.ok(workParentRelative !== '..' && !workParentRelative.startsWith(`..${sep}`) && !isAbsolute(workParentRelative),
  '--work-parent must remain inside the repository');
const buildPath = join(repo, 'build');
await fs.mkdir(buildPath, { recursive: true });
const buildRoot = await fs.realpath(buildPath);
const buildRootRelative = relative(repo, buildRoot);
assert.ok(buildRootRelative !== '..' && !buildRootRelative.startsWith(`..${sep}`) && !isAbsolute(buildRootRelative),
  'Repository build directory must resolve inside the repository');

const profile = optionValue('--profile', 'loopback');
assert.ok(['loopback', 'constrained'].includes(profile), '--profile must be loopback or constrained');
const internalRunDirectory = join(canonicalWorkParent, `.source-tree-supervised-${randomUUID()}`);
await fs.mkdir(internalRunDirectory, { recursive: false });
const reportDirectory = join(buildRoot, 'packaged-web-ci');
await fs.mkdir(reportDirectory, { recursive: true });
const runDirectory = join(reportDirectory, `source-tree-${profile}-${randomUUID()}`);
await fs.mkdir(runDirectory, { recursive: false });
const receiptPath = join(runDirectory, 'process-tree-receipt.json');
const reportPath = join(runDirectory, 'report.json');
const driverReportPath = join(internalRunDirectory, 'driver-report.json');
const childArgs = args.filter((argument, index) => {
  if (argument === '--keep-workdir') return false;
  if (argument === '--cold-report') return false;
  if (argument.startsWith('--cold-report=')) return false;
  if (index > 0 && args[index - 1] === '--cold-report') return false;
  if (argument === '--work-parent') return false;
  if (argument.startsWith('--work-parent=')) return false;
  if (index > 0 && args[index - 1] === '--work-parent') return false;
  return true;
});
if (!args.some(argument => argument === '--mode' || argument.startsWith('--mode='))) childArgs.push('--mode', 'source-tree');
childArgs.push('--work-parent', internalRunDirectory, '--keep-workdir', '--cold-report', driverReportPath);
const executionTimeoutSeconds = 3600;
const command = [supervisor, '--receipt', receiptPath,
  '--execution-timeout-seconds', String(executionTimeoutSeconds), '--', process.execPath, driver, ...childArgs];
let child;
let forwardedSignal = null;
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    forwardedSignal ??= signal;
    child?.kill(signal);
  });
}

try {
  child = spawn(python, command, { cwd: repo, env: {
    ...process.env,
    DECOMP_PACKAGED_SOURCE_TREE_SUPERVISED: '1',
  }, stdio: 'inherit' });
  const exit = await new Promise((resolveExit, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolveExit({ code, signal }));
  });
  let receipt = null;
  let driverReport = null;
  try { receipt = JSON.parse(await fs.readFile(receiptPath, 'utf8')); } catch { /* Missing receipt is a failed qualification. */ }
  try { driverReport = JSON.parse(await fs.readFile(driverReportPath, 'utf8')); } catch { /* Preserve a wrapper failure report below. */ }
  const processTreeConfirmed = !!receipt && receipt.status === 'passed'
    && receipt.cleanup === 'clean' && receipt.cleanupScanIncomplete === false
    && Array.isArray(receipt.survivors) && receipt.survivors.length === 0
    && receipt.commandExitCode === 0;
  let ownedTempCleanup = { attempted: false, confirmed: false };
  const evidenceReference = driverReport?.sourceTreeScale?.requestEvidence ?? null;
  let requestEvidenceArtifact = { required: !!evidenceReference, confirmed: false };
  let ownedDriverPaths = null;
  if (driverReport) {
    try {
      const testDirectory = resolve(driverReport.testDirectory);
      const testDirectoryRelative = relative(resolve(internalRunDirectory), testDirectory);
      assert.ok(testDirectoryRelative !== '..' && !testDirectoryRelative.startsWith(`..${sep}`)
        && !isAbsolute(testDirectoryRelative) && dirname(testDirectoryRelative) === '.',
      'Driver evidence directory escaped its supervised run owner');
      assert.match(basename(testDirectory), /^packaged-browser-/u, 'Driver evidence directory lacks its owned name');
      const expectedProfile = join(testDirectory, 'browser profile');
      assert.equal(resolve(driverReport.browserProfileDirectory), expectedProfile,
        'Browser profile path does not match the supervised driver directory');
      const browserTempDirectory = resolve(driverReport.browserTempDirectory);
      assert.equal(await fs.realpath(dirname(browserTempDirectory)), buildRoot,
        'Chromium temp directory escaped the short build path');
      assert.match(basename(browserTempDirectory), /^\.ct-[A-Za-z0-9]+$/u,
        'Chromium temp directory lacks its unique owner name');
      ownedDriverPaths = { testDirectory, expectedProfile, browserTempDirectory };
    } catch (error) {
      ownedTempCleanup.error = `${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`;
    }
  }
  const processTreeEvidenceStable = !!receipt && receipt.cleanupScanIncomplete === false
    && Array.isArray(receipt.survivors) && receipt.survivors.length === 0
    && ['clean', 'terminated-leaked'].includes(receipt.cleanup);
  if (evidenceReference && ownedDriverPaths && processTreeEvidenceStable) {
    try {
      const evidence = evidenceReference;
      assert.equal(evidence.file, 'source-tree-scale-evidence.json',
        'The driver report must bind the complete source-tree scale evidence artifact');
      assert.ok(Number.isSafeInteger(evidence.bytes) && evidence.bytes > 0 && evidence.bytes <= 8 * 1024 * 1024,
        'Source-tree scale evidence is outside its byte bound');
      assert.match(evidence.sha256 ?? '', /^[a-f0-9]{64}$/u, 'Source-tree scale evidence lacks a SHA-256 binding');
      const evidenceSource = join(ownedDriverPaths.testDirectory, evidence.file);
      const evidenceRealPath = await fs.realpath(evidenceSource);
      assert.equal(dirname(evidenceRealPath), await fs.realpath(ownedDriverPaths.testDirectory),
        'Source-tree scale evidence escaped the owned driver evidence directory');
      const evidenceStat = await fs.lstat(evidenceSource);
      assert.ok(evidenceStat.isFile() && !evidenceStat.isSymbolicLink(),
        'Source-tree scale evidence must be a regular non-symlink file');
      const evidenceBytes = await fs.readFile(evidenceSource);
      assert.equal(evidenceBytes.length, evidence.bytes, 'Source-tree scale evidence byte count changed');
      const evidenceSha256 = createHash('sha256').update(evidenceBytes).digest('hex');
      assert.equal(evidenceSha256, evidence.sha256, 'Source-tree scale evidence digest changed');
      const evidenceDocument = JSON.parse(evidenceBytes.toString('utf8'));
      assert.equal(evidenceDocument.schema, 'decompengine.packaged-source-tree-scale-evidence.v1');
      assert.equal(evidenceDocument.profile, driverReport.profile);
      assert.equal(evidenceDocument.driverCommit, driverReport.driverCommit);
      assert.equal(evidenceDocument.workflowSha, driverReport.workflowSha);
      assert.deepEqual(evidenceDocument.runtime, {
        archiveSha256: driverReport.archiveSha256,
        applicationJarSha256: driverReport.applicationJarSha256,
        buildId: driverReport.buildId,
        browserProduct: driverReport.browser?.product ?? null,
        chromeSha256: driverReport.tools?.chromeSha256,
        javaSha256: driverReport.tools?.javaSha256,
        javaModulesSha256: driverReport.tools?.javaModulesSha256,
        javaReleaseSha256: driverReport.tools?.javaReleaseSha256,
        checkoutParents: driverReport.checkoutParents,
        pullRequestIdentity: driverReport.pullRequestIdentity,
        sourceTreeDriverSha256: driverReport.sourceTreeDriverSha256,
      }, 'Full source-tree evidence package/browser/source identity differs from the driver report');
      assert.deepEqual(evidenceDocument.fixture, driverReport.sourceTreeScale.fixture,
        'Full source-tree evidence fixture identity differs from the driver report');
      assert.ok(Array.isArray(evidenceDocument.coldSamples));
      assert.equal(evidenceDocument.coldSamples.length, driverReport.sourceTreeColdSamples?.sampleCount,
        'Full cold sample evidence count differs from the driver summary');
      assert.deepEqual(Object.fromEntries(Object.entries(evidenceDocument.requests ?? {}).map(([route, entries]) =>
        [route, Array.isArray(entries) ? entries.length : null])), evidence.counts,
      'Full request evidence route counts differ from the driver summary');
      const evidenceTarget = join(runDirectory, evidence.file);
      await fs.writeFile(evidenceTarget, evidenceBytes, { flag: 'wx', mode: 0o600 });
      requestEvidenceArtifact = { required: true, confirmed: true, file: evidence.file,
        bytes: evidenceBytes.length, sha256: evidenceSha256, schema: evidenceDocument.schema,
        coldSampleCount: evidenceDocument.coldSamples.length, counts: evidence.counts,
        copiedAfterProcessTreeStop: true, qualificationStatus: driverReport.status };
    } catch (error) {
      requestEvidenceArtifact.error = `${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`;
    }
  } else if (evidenceReference) {
    requestEvidenceArtifact.error = 'Evidence source was unavailable or process-tree teardown was not confirmed';
  }
  if (processTreeConfirmed && ownedDriverPaths) {
    ownedTempCleanup.attempted = true;
    try {
      await fs.rm(ownedDriverPaths.expectedProfile, { recursive: true, force: true });
      await fs.rm(ownedDriverPaths.browserTempDirectory, { recursive: true, force: true });
      ownedTempCleanup.confirmed = true;
    } catch (error) {
      ownedTempCleanup.error = `${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`;
    }
  }
  const passed = exit.code === 0 && exit.signal === null && !forwardedSignal
    && processTreeConfirmed && driverReport?.status === 'passed'
    && driverReport.shutdownConfirmed === true && ownedTempCleanup.confirmed
    && requestEvidenceArtifact.required && requestEvidenceArtifact.confirmed;
  const finalReport = {
    ...(driverReport ?? { mode: 'source-tree', status: 'failed' }),
    status: passed ? 'passed' : 'failed',
    shutdownConfirmed: passed,
    fullRunProcessTree: {
      scope: 'entire-source-tree-driver-including-cold-samples-and-warm-journey',
      receipt: 'process-tree-receipt.json',
      receiptEvidence: receipt,
      supervisorExitCode: exit.code,
      supervisorSignal: exit.signal,
      receiptStatus: receipt?.status ?? 'missing-or-invalid',
      cleanup: receipt?.cleanup ?? 'unavailable',
      cleanupScanIncomplete: receipt?.cleanupScanIncomplete ?? true,
      survivors: receipt?.survivors ?? null,
      confirmed: processTreeConfirmed,
      forwardedSignal,
    },
    ownedTempCleanup,
    requestEvidenceArtifact,
    workRetained: true,
    workCleanup: 'retained-until-post-supervisor-review',
  };
  const temporary = `${reportPath}.tmp`;
  await fs.writeFile(temporary, `${JSON.stringify(finalReport, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  await fs.rename(temporary, reportPath);
  console.log(`Full source-tree process-tree report: ${reportPath}`);
  process.exitCode = passed ? 0 : 1;
} catch (error) {
  const failureReport = {
    mode: 'source-tree', status: 'failed', shutdownConfirmed: false,
    wrapperFailure: `${error?.name ?? 'Error'}: ${error?.message ?? String(error)}`,
    processTreeReceipt: 'process-tree-receipt.json', workRetained: true,
  };
  await fs.writeFile(reportPath, `${JSON.stringify(failureReport, null, 2)}\n`, { mode: 0o600 });
  console.error(`Full source-tree process-tree supervision failed; evidence retained at ${reportPath}`);
  process.exitCode = 1;
}
