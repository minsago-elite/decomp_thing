import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { createCanaryTracker, WORKFLOW_CANARY_VIEWS } from './packaged-browser-canary.mjs';

// Kept identical to PackagedFakeReconstruction.LIMITS.
const LIMITS = { wallClockMs: '180000', idleMs: '180000', maxOutputBytes: '16777216', maxToolCalls: '0' };
// Untrusted user-controlled name: markup and a bidi override must stay inert text.
const UPLOAD_NAME = '<img src=x onerror=globalThis.__decompInjected=3>\u202Efdl.elf';

/**
 * Fake-engine packaged journey. The extracted application JAR runs one test-owned adapter that never
 * reads the uploaded bytes beyond hashing them; every step is driven by explicit control files.
 */
export async function qualifyWorkflow(context) {
  const { installation, makeTarget, cdp, evaluate, ready, waitFor, capture, origin, launch, stop } = context;
  const control = installation.fixture.control;
  const canary = installation.fixture.canary;
  const canaryTracker = createCanaryTracker(canary);
  const observeCanary = (target, label) => canaryTracker.observe(target, evaluate, label);
  const data = installation.data;
  const result = { executionOfUploadedBinary: false, engine: 'test-owned fake reconstruction adapter' };
  const tabs = [];
  // Hidden tabs pause reads and commands by design, so every driven tab is brought to the front.
  const front = (target) => cdp.call('Page.bringToFront', {}, target.sessionId);
  const tab = async () => {
    const target = await makeTarget(); tabs.push(target);
    // A retained upload guards navigation with beforeunload; this journey navigates deliberately.
    cdp.on('Page.javascriptDialogOpening', () => { void cdp.call('Page.handleJavaScriptDialog', { accept: true }, target.sessionId).catch(() => {}); }, target.sessionId);
    await front(target); return target;
  };
  const text = (target) => evaluate(target, 'document.body.innerText');
  const step = (runId, value) => fs.writeFile(join(control, `${runId}.step`), String(value));
  const marker = (runId, name) => waitFor(() => fs.stat(join(control, `${runId}.${name}`)).then(() => true, () => false), `fake engine ${name} for ${runId}`, 30000);
  const signIn = async (target) => {
    const url = await waitFor(context.bootstrapUrl, 'fixture bootstrap handoff');
    context.sensitiveValues.push(new URL(url).hash.slice('#bootstrap='.length));
    await front(target);
    await cdp.call('Page.navigate', { url }, target.sessionId);
    await ready(target, `document.body.innerText.includes('Local session connected.')`, 'fixture session');
  };
  // The adapter's marker precedes the service's terminal record; wait for the recorded state itself.
  const settled = (run, state) => waitFor(async () => (await evaluate(main, `fetch('/nested/api/v1/jobs/' + location.pathname.split('/')[3] + '/runs/${run}', { headers: { Accept: 'application/json' } })
    .then(response => response.json()).then(body => body.data?.state)`)) === state, `recorded ${state} state for ${run}`, 30000);
  const injected = (target) => evaluate(target, `({ flag: typeof globalThis.__decompInjected, images: [...document.querySelectorAll('main img')].filter(image => image.getAttribute('src') === 'x').length })`);

  // 1. Disk-full upload admission is refused truthfully, and nothing is published.
  const main = await tab();
  await signIn(main);
  await fs.writeFile(join(control, 'disk-full'), '');
  await cdp.call('Page.navigate', { url: `${origin}/nested/upload` }, main.sessionId);
  const choose = () => evaluate(main, `(() => {
    const bytes = new Uint8Array(64); bytes.set([127, 69, 76, 70, 2, 1, 1]);
    const view = new DataView(bytes.buffer); view.setUint16(16, 2, true); view.setUint16(18, 62, true);
    view.setUint32(20, 1, true); view.setUint16(52, 64, true);
    const transfer = new DataTransfer(); transfer.items.add(new File([bytes], ${JSON.stringify(UPLOAD_NAME)}));
    const picker = document.querySelector('#binary-file'); picker.files = transfer.files;
    picker.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);
  const submit = () => evaluate(main, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Upload binary').click()`);
  await ready(main, `document.querySelector('#binary-file') !== null && [...document.querySelectorAll('button')].some(button => button.textContent === 'Upload binary')`, 'upload controls');
  await choose();
  await ready(main, `document.body.innerText.includes('Selected: ') && [...document.querySelectorAll('button')].some(button => button.textContent === 'Upload binary' && !button.disabled)`, 'disk-full fixture selection');
  await submit();
  await ready(main, `document.body.innerText.includes('The server has no upload capacity. Wait or free storage, then retry this file.')`, 'disk-full upload refusal');
  assert.equal(await fs.stat(data).then(async () => (await fs.readdir(data)).filter(name => /^[a-f0-9]{32}$/.test(name)).length, () => 0), 0,
    'A disk-full refusal published a job');
  await observeCanary(main, 'disk-full upload');
  await context.sample('disk-full upload');
  result.diskFullUpload = { refused: true, jobsPublished: 0, explanation: 'no upload capacity' };
  await fs.rm(join(control, 'disk-full'));

  // 2. Upload an untrusted name through the same control, then start explicitly with one key.
  await cdp.call('Page.reload', {}, main.sessionId);
  await ready(main, `document.querySelector('#binary-file') !== null && document.body.innerText.includes('Local session connected.')`, 'upload after storage recovery');
  await choose();
  await ready(main, `document.body.innerText.includes('Selected: ') && [...document.querySelectorAll('button')].some(button => ['Upload binary', 'Retry this upload'].includes(button.textContent) && !button.disabled)`, 'fixture selection');
  await observeCanary(main, 'selected upload');
  await evaluate(main, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Upload binary' || button.textContent === 'Retry this upload').click()`);
  await ready(main, `/^\\/nested\\/jobs\\/[0-9a-f]{32}$/.test(location.pathname)`, 'uploaded job route');
  const jobId = (await evaluate(main, 'location.pathname')).split('/').at(-1);
  await ready(main, `document.body.innerText.includes(${JSON.stringify(UPLOAD_NAME)})`, 'untrusted filename shown as text');
  assert.deepEqual(await injected(main), { flag: 'undefined', images: 0 }, 'Uploaded filename markup became active');
  await observeCanary(main, 'uploaded job');
  const version = () => evaluate(main, `fetch('/nested/api/v1/jobs/${jobId}', { headers: { Accept: 'application/json' } }).then(job => job.headers.get('ETag'))`);
  // A duplicate submission repeats the exact request: the same key and the same displayed job version.
  const start = (key, etag) => evaluate(main, `(async () => {
    const bootstrap = await (await fetch('/nested/api/v1/bootstrap', { headers: { Accept: 'application/json' } })).json();
    const response = await fetch('/nested/api/v1/jobs/${jobId}/runs', { method: 'POST', headers: {
      Accept: 'application/json', 'Content-Type': 'application/json', 'X-CSRF-Token': bootstrap.data.csrfToken,
      'If-Match': ${JSON.stringify(etag)}, 'Idempotency-Key': ${JSON.stringify(key)} },
      body: JSON.stringify({ workflow: 'reconstruct', inputRevisionId: null, harnessCapabilityId: null, limits: ${JSON.stringify(LIMITS)} }) });
    const body = await response.json();
    return { status: response.status, replayed: response.headers.get('Idempotency-Replayed'), runId: body.data?.runId ?? null, code: body.error?.code ?? null };
  })()`);
  const key = `packaged-${randomUUID()}`;
  const displayed = await version();
  const first = await start(key, displayed);
  assert.equal(first.status, 202, `Explicit start was not admitted: ${JSON.stringify(first)}`);
  const runId = first.runId;
  await marker(runId, 'started');
  // A duplicated submission with the same key replays the same attempt; it never starts another.
  const duplicate = await start(key, displayed);
  assert.deepEqual([duplicate.status, duplicate.replayed, duplicate.runId], [202, 'true', runId], 'Duplicate start was not a replay');
  const second = await start(`packaged-${randomUUID()}`, await version());
  assert.equal(second.status, 409, 'A second key started concurrent work');
  await context.sample('explicit start');
  result.start = { explicit: true, duplicateKeyReplayed: true, concurrentStartRefused: second.code };

  // 3. Live activity under a slow stream, then a browser-reported disconnect and reconnect.
  // The journal writer publishes asynchronously; before its first file exists the server truthfully reports
  // PROGRESS_UNAVAILABLE, so the live view is opened once the journal is durable.
  await waitFor(() => fs.stat(join(data, jobId, 'reports', 'runs', runId, 'agent-progress.json')).then(() => true, () => false),
    'durable progress journal', 30000);
  const activity = await tab();
  await cdp.call('Page.navigate', { url: `${origin}/nested/jobs/${jobId}/runs/${runId}/activity` }, activity.sessionId);
  await ready(activity, `[...document.querySelectorAll('button')].some(button => button.textContent === 'Follow activity')`, 'activity controls');
  await evaluate(activity, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Follow activity').click()`);
  await ready(activity, `/analyzing/i.test(document.querySelector('ol[aria-label="Activity observations"]')?.innerText ?? '')`, 'live analyzing observation');
  await cdp.call('Network.emulateNetworkConditions', { offline: false, latency: 400, downloadThroughput: 4096, uploadThroughput: 4096 }, activity.sessionId);
  await step(runId, 1);
  await marker(runId, 'planning');
  await ready(activity, `/planning/i.test(document.querySelector('ol[aria-label="Activity observations"]')?.innerText ?? '')`, 'slow-stream planning observation');
  await cdp.call('Network.emulateNetworkConditions', { offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 }, activity.sessionId);
  await evaluate(activity, `dispatchEvent(new Event('offline'))`);
  await ready(activity, `document.body.innerText.includes('Browser reports offline. Activity reads are suspended.')`, 'truthful offline activity');
  assert.equal(await evaluate(activity, `document.body.innerText.includes('completed')`), false, 'Offline activity claimed completion');
  const observed = `[...document.querySelectorAll('ol[aria-label="Activity observations"] li')].map(item => item.textContent.match(/Sequence (\\d+)/)?.[1]).filter(Boolean).map(Number)`;
  const beforeReconnect = await evaluate(activity, observed);
  // The engine emits its next observation while the browser is offline; only a real post-reconnect
  // read can deliver it, and the earlier rows must not be delivered again.
  await step(runId, 2);
  await marker(runId, 'agent-running');
  assert.equal(await evaluate(activity, `/agent_running/i.test(document.querySelector('ol[aria-label="Activity observations"]')?.innerText ?? '')`), false,
    'An offline page displayed an observation emitted after the disconnect');
  await cdp.call('Network.emulateNetworkConditions', { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 }, activity.sessionId);
  await evaluate(activity, `dispatchEvent(new Event('online'))`);
  await ready(activity, `!document.body.innerText.includes('Browser reports offline.') && /agent_running/i.test(document.querySelector('ol[aria-label="Activity observations"]')?.innerText ?? '')`, 'new observation delivered after reconnect');
  const sequences = await evaluate(activity, observed);
  assert.equal(new Set(sequences).size, sequences.length, `Reconnect duplicated observations: ${sequences}`);
  assert.ok(Math.max(...sequences) > Math.max(...beforeReconnect), `Reconnect delivered no newer observation: ${beforeReconnect} -> ${sequences}`);
  result.liveActivity = { slowStream: true, offlineExplained: true, reconnected: true, newObservationsAfterReconnect: sequences.length - beforeReconnect.length,
    duplicateObservations: 0, observations: sequences.length };
  await observeCanary(activity, 'live activity');
  await capture(activity, 'workflow-live-activity.png');

  // 4. Restart the server mid-attempt. The retained attempt must not claim to still run or to have completed.
  // Sample the first JVM's RSS high-water mark before it exits.
  await context.sample('before restart');
  await stop();
  await launch();
  await signIn(main);
  await cdp.call('Page.navigate', { url: `${origin}/nested/jobs/${jobId}/runs/${runId}` }, main.sessionId);
  await ready(main, `document.querySelector('h1')?.textContent === 'Workflow attempt' && /interrupted/i.test(document.body.innerText)`, 'interrupted attempt after restart');
  const interrupted = await text(main);
  assert.ok(!/\bRunning\b/.test(interrupted) && !interrupted.includes(sourceBrowse), 'Restarted attempt claimed progress or sources');
  await observeCanary(main, 'interrupted attempt');
  await context.sample('after restart');
  result.restart = { attemptInterrupted: true, sourcesClaimed: false };

  // 5. Explicit retry through the attempt controls, then complete it.
  await evaluate(main, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Read available actions').click()`);
  await ready(main, `[...document.querySelectorAll('button')].some(button => button.textContent === 'Retry as a new attempt' && !button.disabled)`, 'retry control');
  await evaluate(main, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Retry as a new attempt').click()`);
  const retryHref = await ready(main, `[...document.querySelectorAll('a')].find(a => /\\/runs\\/[^/]+$/.test(a.getAttribute('href') ?? '') && a.textContent.startsWith('Open new attempt'))?.getAttribute('href')`, 'retry created link');
  const retryRun = retryHref.split('/').at(-1);
  assert.notEqual(retryRun, runId);
  await marker(retryRun, 'started');
  await step(retryRun, 3);
  await marker(retryRun, 'completed');
  await settled(retryRun, 'completed');
  await cdp.call('Page.navigate', { url: `${origin}${retryHref}` }, main.sessionId);
  await ready(main, `[...document.querySelectorAll('a')].some(a => a.textContent === ${JSON.stringify(sourceBrowse)})`, 'completed retry offers its sources');
  await observeCanary(main, 'completed retry');
  await context.sample('completed retry');
  result.retry = { throughAttemptControls: true, completed: true };

  // 6. Sources: directory, highlighted file through the worker, and an exact download digest.
  await evaluate(main, `[...document.querySelectorAll('a')].find(a => a.textContent === ${JSON.stringify(sourceBrowse)}).click()`);
  await ready(main, `[...document.querySelectorAll('main a')].some(a => a.textContent.endsWith('.c') || a.textContent === 'src')`, 'source directory');
  result.sources = await inspectSources(context, main, jobId, retryRun);
  assert.deepEqual(await injected(main), { flag: 'undefined', images: 0 }, 'Generated source markup became active');
  await observeCanary(main, 'recorded source');
  await context.sample('source inspection');
  await capture(main, 'workflow-source.png');

  // 7. A genuine ENOSPC inside the engine fails the next attempt without a candidate.
  await cdp.call('Page.navigate', { url: `${origin}/nested/jobs/${jobId}/runs/${retryRun}` }, main.sessionId);
  await ready(main, `document.querySelector('h1')?.textContent === 'Workflow attempt'`, 'completed attempt');
  // Completed attempts are not recovered; a new explicit start creates the disk-full attempt.
  const third = await start(`packaged-${randomUUID()}`, await version());
  assert.equal(third.status, 202);
  await fs.writeFile(join(control, `${third.runId}.enospc`), '');
  await marker(third.runId, 'started');
  await step(third.runId, 3);
  await marker(third.runId, 'enospc');
  await settled(third.runId, 'failed');
  await cdp.call('Page.navigate', { url: `${origin}/nested/jobs/${jobId}/runs/${third.runId}` }, main.sessionId);
  await ready(main, `/failed/i.test(document.body.innerText) && document.querySelector('h1')?.textContent === 'Workflow attempt'`, 'disk-full attempt failure');
  assert.equal(await evaluate(main, `[...document.querySelectorAll('a')].some(a => a.textContent === ${JSON.stringify(sourceBrowse)})`), false,
    'A disk-full attempt offered sources');
  await observeCanary(main, 'failed attempt');
  await context.sample('engine disk full');
  result.engineDiskFull = { errno: 'ENOSPC', attemptFailed: true, sourcesOffered: false };

  // 8. Canary and untrusted content across live and retained views, storage and logs.
  const leaks = [];
  for (const [index, target] of tabs.entries()) {
    await observeCanary(target, `final tab ${index}`);
  }
  if (context.serverLog().includes(canary)) leaks.push('server log');
  for (const name of await listFiles(join(data, jobId))) {
    if ((await fs.readFile(name)).includes(canary)) leaks.push(name.slice(data.length));
  }
  assert.deepEqual(leaks, [], 'The server secret canary escaped redaction');
  result.canary = { ...canaryTracker.summary([...WORKFLOW_CANARY_VIEWS, ...tabs.map((_, index) => `final tab ${index}`)]),
    serverLog: true, retainedFiles: true };
  return result;
}

const sourceBrowse = 'Browse recorded source inputs';

async function listFiles(directory) {
  const output = [];
  for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await listFiles(path));
    else if (entry.isFile()) output.push(path);
  }
  return output;
}

async function inspectSources(context, target, jobId, runId) {
  const { evaluate, ready } = context;
  // Descend until a C file is listed, then open it.
  for (let depth = 0; depth < 4; depth++) {
    const fileLink = await evaluate(target, `[...document.querySelectorAll('main a')].find(a => /\\.c$/.test(a.textContent))?.getAttribute('href') ?? null`);
    if (fileLink) {
      await evaluate(target, `document.querySelector('main a[href=${JSON.stringify(fileLink)}]').click()`);
      break;
    }
    await evaluate(target, `[...document.querySelectorAll('main a')].find(a => a.textContent === 'src').click()`);
    await ready(target, `[...document.querySelectorAll('main a')].some(a => /\\.c$/.test(a.textContent))`, 'nested source directory');
  }
  const committedDigest = `[...document.querySelectorAll('dt')].find(dt => dt.textContent === 'Committed SHA-256')?.nextElementSibling?.textContent.trim()`;
  await ready(target, `document.querySelector('h1')?.textContent === 'Recorded source file' && /^[a-f0-9]{64}$/.test(${committedDigest} ?? '')`, 'source file metadata');
  // The packaged runtime reports maxSourceChunkBytes=0, so text previews (and the highlight worker) stay off.
  assert.ok(await evaluate(target, `document.body.innerText.includes('The reported runtime does not enable source text previews.')`));
  const committed = await evaluate(target, committedDigest);
  await evaluate(target, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Check file digest').click()`);
  await ready(target, `document.body.innerText.includes('The server reported matching bytes, size and recorded digest')`, 'server digest check');
  const download = await evaluate(target, `(async () => {
    const link = [...document.querySelectorAll('a')].find(a => a.textContent === 'Download complete recorded input');
    const response = await fetch(link.getAttribute('href'), { headers: { Accept: 'application/octet-stream' } });
    const bytes = new Uint8Array(await response.arrayBuffer());
    const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
    return { status: response.status, digest, size: bytes.length, path: decodeURIComponent(location.pathname) };
  })()`);
  assert.equal(download.status, 200);
  assert.equal(download.digest, committed, 'Downloaded source bytes differ from the committed digest');
  const runDirectory = join(context.installation.data, jobId, 'reports', 'runs', runId);
  const archive = join(runDirectory, 'source-tree.zip');
  // Independent stdlib verifier: strict extraction, complete manifest coverage and exact digests.
  const verified = JSON.parse(execFileSync(context.python, [join(context.repo, 'scripts/verify-source-archive.py'), archive],
    { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 }));
  assert.ok(Object.values(verified.files).includes(download.digest), 'Downloaded source bytes are not an archived payload file');
  return { textPreview: 'runtime-disabled', committedDigestShown: true, serverDigestCheck: 'matched', downloadSha256: download.digest,
    archive: { sha256: verified.archiveSha256, files: Object.keys(verified.files).length, manifestComplete: true,
      downloadedFileInArchive: true, verifier: 'scripts/verify-source-archive.py' } };
}
