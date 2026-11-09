import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { basename, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const COLD_SAMPLE_COUNT = 20;
export const COLD_SAMPLE_TIMEOUT_MS = 45_000;
export const COLD_PROFILES = Object.freeze({
  loopback: Object.freeze({ name: 'loopback', firstPageLimitMs: 500, cpuRate: 1, latencyMs: 0, downloadBytesPerSecond: 0, uploadBytesPerSecond: 0 }),
  constrained: Object.freeze({ name: 'constrained', firstPageLimitMs: 1000, cpuRate: 4, latencyMs: 100, downloadBytesPerSecond: 1_250_000, uploadBytesPerSecond: 250_000 }),
});

export function structureProfile(name = 'loopback') {
  const profile = COLD_PROFILES[name];
  if (!profile) throw new TypeError(`unknown structure profile: ${name}`);
  return profile;
}

async function waitForProcessGroupExit(pid, timeoutMs) {
  if (process.platform !== 'linux' || !Number.isSafeInteger(pid) || pid <= 0) return false;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { process.kill(-pid, 0); }
    catch (error) { return error?.code === 'ESRCH'; }
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  try { process.kill(-pid, 0); return false; }
  catch (error) { return error?.code === 'ESRCH'; }
}

export function summarizeColdSamples(samples, expected = COLD_SAMPLE_COUNT) {
  if (!Number.isSafeInteger(expected) || expected < 1) throw new TypeError('expected sample count must be positive');
  if (!Array.isArray(samples) || samples.length !== expected) throw new RangeError(`expected exactly ${expected} samples; received ${samples?.length ?? 'invalid'}`);
  const validRawCount = sample => Number.isSafeInteger(sample?.rawFailedRequests) && sample.rawFailedRequests >= 0;
  const successful = samples.filter(s => s?.status === 'passed' && validRawCount(s) && s.rawFailedRequests === 0
    && Number.isFinite(s.firstPageMs) && s.firstPageMs >= 0);
  const values = successful.map(s => s.firstPageMs).sort((a,b) => a-b);
  const failures = samples.reduce((n,s) => n + (s?.status === 'passed' ? 0 : 1)
    + (validRawCount(s) ? s.rawFailedRequests : 1), 0);
  const p95 = values.length ? values[Math.ceil(values.length * .95)-1] : null;
  const median = values.length ? (values.length % 2 ? values[(values.length-1)/2] : (values[values.length/2-1]+values[values.length/2])/2) : null;
  return { expectedSamples: expected, sampleCount: samples.length, samples, successfulSamples: successful.length,
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
  timeoutMs = COLD_SAMPLE_TIMEOUT_MS, reportReader = readChildReport }) {
  if (count !== COLD_SAMPLE_COUNT) throw new RangeError(`cold structure run requires exactly ${COLD_SAMPLE_COUNT} samples`);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30 * 60_000) throw new RangeError('cold sample timeout is outside its allowed bound');
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
        let settled = false, timedOut = false;
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
          const childClosedInGrace = childClosed || await Promise.race([new Promise(resolve => child.once('close', () => resolve(true))), new Promise(resolve => setTimeout(() => resolve(false), 10_000))]);
          let shutdownConfirmed = childClosedInGrace && await waitForProcessGroupExit(processGroupId, 1000);
          if (!shutdownConfirmed) {
            try {
              if (process.platform === 'linux' && child.pid) process.kill(-child.pid, 'SIGKILL');
              else child.kill('SIGKILL');
            } catch {}
            const childClosedAfterKill = childClosed || await Promise.race([new Promise(resolve => child.once('close', () => resolve(true))),
              new Promise(resolve => setTimeout(() => resolve(false), 10_000))]);
            shutdownConfirmed = childClosedAfterKill && await waitForProcessGroupExit(processGroupId, 10_000);
          }
          // A closed launcher process is not proof that Chrome or the JVM exited.
          // Only the process-group probe confirms that no owned descendant remains.
          settle({ timeout: true, shutdownConfirmed });
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
      processTreeConfirmed = outcome.shutdownConfirmed ?? (childClosed && processGroupId
        ? await waitForProcessGroupExit(processGroupId, 10_000) : false);
      const shutdownConfirmed = processTreeConfirmed;
      const diagnostic = stderr.length ? { byteLength: Buffer.byteLength(stderr), sha256: createHash('sha256').update(stderr).digest('hex') } : null;
      const passed = !interrupted && !timedOut && exitCode === 0 && report?.status === 'passed' && evidence?.passed === true
        && evidence?.profileApplied === profile.name && rawFailedRequests === 0 && firstPageMs !== null && shutdownConfirmed;
      samples.push({ index: index + 1, status: passed ? 'passed' : 'failed', profile: profile.name, exitCode, firstPageMs, rawFailedRequests,
        browserHeapBytes: evidence?.browserHeapMemory?.sampledPeakBytes ?? null,
        jvmRssIncrementBytes: evidence?.jvmMemory?.incrementalPeakBytes ?? null,
        profileApplied: evidence?.profileApplied ?? null,
        reportPath: childReport?.path ?? null, reportSha256: childReport?.sha256 ?? null, driverCommit: report?.driverCommit ?? null,
        archiveSha256: report?.archiveSha256 ?? null, applicationJarSha256: report?.applicationJarSha256 ?? null,
        testDirectory: report?.testDirectory ?? null, browserProfileDirectory: report?.browserProfileDirectory ?? null,
        runtimeProcesses: report?.runtimeProcesses ?? null,
        shutdownConfirmed, timedOut, error: outcome.error ? String(outcome.error.message).slice(0, 512)
          : evidence?.failures?.[0] ?? (evidence?.profileApplied !== profile.name ? 'Child report did not confirm the requested profile' : null),
        diagnostic });
      if (!shutdownConfirmed) break; // Never overlap another run with an unconfirmed child process tree.
      if (interrupted) break;
    } catch (error) {
      if (!processTreeConfirmed && childClosed && processGroupId) processTreeConfirmed = await waitForProcessGroupExit(processGroupId, 10_000).catch(() => false);
      samples.push({ index: index + 1, status: 'failed', profile: profile.name, exitCode, firstPageMs: null,
        rawFailedRequests: null, shutdownConfirmed: processTreeConfirmed, timedOut, error: String(error.message).slice(0, 512),
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
    .map(sample => [sample.driverCommit, sample.archiveSha256, sample.applicationJarSha256]);
  const identityConsistent = identities.length === count && identities.every(identity => identity.every(Boolean)
    && identity.every((value, index) => value === identities[0][index]));
  const directories = samples.map(sample => sample.testDirectory);
  const runDirectoriesUnique = directories.every(Boolean) && new Set(directories).size === count;
  const processIdentitiesPresent = samples.every(sample => Number.isSafeInteger(sample.runtimeProcesses?.applicationPid)
    && sample.runtimeProcesses.applicationPid > 0 && Number.isSafeInteger(sample.runtimeProcesses?.browserPid) && sample.runtimeProcesses.browserPid > 0
    && sample.browserProfileDirectory && sample.testDirectory && sample.browserProfileDirectory.startsWith(sample.testDirectory + '/'));
  return { profile: profile.name, firstPageLimitMs: profile.firstPageLimitMs, ...summary, identityConsistent,
    runDirectoriesUnique, processIdentitiesPresent,
    overBudgetSamples: samples.filter(sample => Number.isFinite(sample.firstPageMs) && sample.firstPageMs > profile.firstPageLimitMs)
      .map(sample => ({ index: sample.index, firstPageMs: sample.firstPageMs })),
    passed: summary.successfulSamples === count && summary.rawFailedRequests === 0 && identityConsistent && runDirectoriesUnique && processIdentitiesPresent
      && Number.isFinite(summary.nearestRankP95FirstPageMs) && summary.nearestRankP95FirstPageMs <= profile.firstPageLimitMs };
}

async function readChildReport(stdout) {
  const match = stdout.match(/Report: (.+\/report\.json)\s*$/m);
  if (!match) return null;
  const path = resolve(match[1]);
  const bytes = await fs.readFile(path);
  const report = JSON.parse(bytes.toString('utf8'));
  return { path, report, sha256: createHash('sha256').update(bytes).digest('hex') };
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
