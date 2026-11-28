import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { sampleProcessTree } from './soak626/resources.mjs';
import { waitForSuccessfulStreamOpen } from './soak626/stream-renewal.mjs';
import { routeFeedbackExpression } from './soak626/route-feedback.mjs';
import { LIMITS } from './soak626/evaluate.mjs';
import { sampleRetention } from './soak626/listener-retention.mjs';
import { createDashboardListingTracker } from './soak626/dashboard-listing.mjs';

const RUN_PREFIX = 'run_fixture_soak_';
const JOB_PREFIX = 'c';
const OBSERVATIONS = 205;
const PROFILE_ID = 'generated-c-make-v1';
const PROFILE_SHA256 = 'a448a139a09f28ad9f2e08bfcebcb9d85765a0a557ebb11db6d7634bc145f28f';
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

/** Credential-free, inert history fixtures. All writes finish before the packaged server starts. */
export async function seedSoak(root) {
  await fs.mkdir(root, { mode: 0o700 });
  const createdAt = new Date(Date.now() - 300_000).toISOString();
  const jobs = [];
  for (let index = 0; index < 4; index++) {
    const letter = String(index + 1);
    const jobId = JOB_PREFIX.repeat(31) + letter;
    const runId = `${RUN_PREFIX}${letter}`;
    const directory = join(root, jobId);
    await fs.mkdir(directory, { mode: 0o700 });
    const input = Buffer.alloc(64);
    input.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
    input.writeUInt16LE(2, 16); input.writeUInt16LE(62, 18); input.writeUInt32LE(1, 20); input.writeUInt16LE(64, 52);
    const sourceContent = `all:\n\t@echo inert-soak-source-${letter}\n`;
    const sourceBytes = Buffer.from(sourceContent);
    const sourceDigest = sha256(sourceBytes);
    const sourceRevisionSha256 = sha256(Buffer.from(`8:Makefile:${sourceBytes.length}:${sourceDigest}\n`));
    const revisionId = `source_${sourceRevisionSha256}`;
    const job = { id: jobId, filename: `synthetic-soak-${letter}.elf`, status: 'uploaded', created_at: createdAt,
      updated_at: createdAt, size_bytes: input.length, binary_path: join(directory, 'input.elf'), metadata: {
        format: 'ELF64', endianness: 'little', elf_version: 1, os_abi: 'System V', object_type: 'executable',
        machine: 'x86-64', entry_point: 0, elf_header_size: 64, program_header_count: 0,
        section_header_count: 0, section_name_table_index: 0,
      } };
    const jobBytes = JSON.stringify(job);
    const workflowVersion = `version_${sha256(Buffer.from(`soak-state-${letter}`)).slice(0, 32)}`;
    const run = { runId, jobId, workflow: 'reconstruct', state: 'completed', version: workflowVersion,
      createdAt, startedAt: createdAt, endedAt: new Date(Date.parse(createdAt) + 1000).toISOString(), previousRunId: null,
      inputRevisionId: null, harnessCapabilityId: null,
      limits: { wallClockMs: '60000', idleMs: '15000', maxOutputBytes: '1048576', maxToolCalls: '16' },
      terminalReason: 'COMPLETED', usage: { inputTokens: '0', outputTokens: '0', cachedInputTokens: '0', toolCalls: '0', wallClockMs: '1000' },
      candidate: { revisionId, sourceSha256: sourceRevisionSha256 }, acceptedRevision: null };
    const state = { schemaVersion: 1, jobId, version: workflowVersion,
      legacy: { originalJobSha256: '0'.repeat(64), status: 'uploaded', recoveredInterrupted: false },
      attempts: [run], acceptedRevision: null };
    // The state reader validates the legacy binding against the exact retained job bytes.
    state.legacy.originalJobSha256 = createHash('sha256').update(jobBytes).digest('hex');
    await fs.writeFile(join(directory, 'input.elf'), input, { flag: 'wx', mode: 0o600 });
    await fs.writeFile(join(directory, 'job.json'), jobBytes, { flag: 'wx', mode: 0o600 });
    await fs.writeFile(join(directory, 'workflow-state.json'), JSON.stringify(state), { flag: 'wx', mode: 0o600 });
    const reportDirectory = join(directory, 'reports', 'runs', runId);
    await fs.mkdir(reportDirectory, { recursive: true, mode: 0o700 });
    const sourceRoot = join(reportDirectory, 'source-tree');
    await fs.mkdir(join(sourceRoot, 'reports'), { recursive: true, mode: 0o700 });
    await fs.writeFile(join(sourceRoot, 'Makefile'), sourceBytes, { flag: 'wx', mode: 0o600 });
    const manifest = { schemaVersion: 3, profileId: PROFILE_ID, profileSha256: PROFILE_SHA256,
      inputSha256: sha256(input), files: [{ path: 'Makefile', sha256: sourceDigest, generator: 'packaged-soak-fixture',
        promptSha256: null, acceptedImplementation: null, contentKind: 'utf8-text',
        roles: ['archive-payload', 'build-definition', 'build-input', 'editable', 'viewable'], entityIds: [] }],
      unresolvedEntityIds: [], unresolvedImplementationIds: [] };
    await fs.writeFile(join(sourceRoot, 'source_tree_manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    const buildContract = { schemaVersion: 3, sourceRevisionSha256,
      sourceInputs: [{ path: 'Makefile', bytes: sourceBytes.length, sha256: sourceDigest }], command: ['make', '-f', 'Makefile'] };
    await fs.writeFile(join(sourceRoot, 'reports', 'build_contract.json'), JSON.stringify(buildContract), { flag: 'wx', mode: 0o600 });
    const progress = JSON.stringify({ schemaVersion: 1, displayOnly: true, nextSequence: OBSERVATIONS,
      queueDropped: 0, historyDropped: 0, truncated: false,
      events: Array.from({ length: OBSERVATIONS }, (_, sequence) => ({ sequence, runId, workflow: 'reconstruct',
        time: new Date(Date.parse(createdAt) + sequence).toISOString(), taskId: `soak_${letter}`,
        sessionIdSha256: 'a'.repeat(64), kind: 'workflow_phase', phase: 'planning',
        text: `Soak ${letter} observation ${sequence}` })) });
    const progressPath = join(reportDirectory, 'agent-progress.json');
    await fs.writeFile(progressPath, progress, { flag: 'wx', mode: 0o600 });
    jobs.push({ index, jobId, runId, revisionId, sourceRevisionSha256, filename: job.filename, sourceContent, progressPath, progress });
  }
  return { jobs, observationCount: OBSERVATIONS };
}

const activityRows = `Array.from(document.querySelectorAll('ol[aria-label="Activity observations"] li span')).map(node => node.textContent)`;

async function clickHref(tab, evaluate, href, measureRouteCommit = false) {
  if (measureRouteCommit) {
    const target = new URL(href, 'http://soak.invalid');
    const heading = target.pathname === '/nested/' ? { id: 'workspace-title', text: 'Your work, with its evidence' }
      : /^\/nested\/jobs\/[^/]+$/.test(target.pathname) ? { id: 'job-title', text: 'Job overview' }
        : /^\/nested\/jobs\/[^/]+\/runs\/[^/]+$/.test(target.pathname) ? { id: 'attempt-title', text: 'Workflow attempt' }
          : /^\/nested\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/sources\/root$/.test(target.pathname)
            ? { id: 'source-title', text: 'Recorded source inputs' } : null;
    assert.ok(heading, `No route-heading expectation is defined for measured route ${target.pathname}`);
    const result = await evaluate(tab, routeFeedbackExpression({ href, headingId: heading.id, headingText: heading.text }));
    assert.equal(result.found, true, `Expected in-app link ${href}; destination route measurement found no link`);
    assert.equal(result.address, target.pathname + target.search, `In-app route did not synchronously publish ${href}`);
    assert.equal(result.settled, true, `Destination heading did not commit and receive focus for ${href}`);
    assert.equal(result.settledAddress, target.pathname + target.search, `Destination changed before route feedback completed for ${href}`);
    return result.elapsedMs;
  }
  const started = Date.now();
  const result = await evaluate(tab, `(() => { const links = [...document.querySelectorAll('a')]; const link = links.find(a => a.getAttribute('href') === ${JSON.stringify(href)}); if (!link) return { found: false, path: location.pathname, heading: document.querySelector('h1')?.textContent, text: document.body.innerText.slice(0, 900), links: links.map(a => a.getAttribute('href')).slice(0, 32) }; link.click(); return { found: true, address: location.pathname + location.search }; })()`);
  assert.equal(result.found, true, `Expected in-app link ${href}; page ${JSON.stringify(result)}`);
  const expected = new URL(href, 'http://soak.invalid');
  assert.equal(result.address, expected.pathname + expected.search, `In-app route did not synchronously publish ${href}`);
  return Date.now() - started;
}

async function publishProgress(path, value) {
  const temporary = `${path}.soak-publication`;
  await fs.writeFile(temporary, JSON.stringify(value), { flag: 'wx', mode: 0o600 });
  await fs.rename(temporary, path);
}

/** Repeated same-document navigation and real authenticated history/activity reads. */
export async function qualifySoak({ fixture, tab, cdp, evaluate, ready, origin, applicationPid, delay,
  durationMs = 20 * 60_000, onProgress = () => {}, onPartial = () => {} }) {
  assert.equal(fixture.jobs.length, 4);
  const slotMs = 10_000;
  const slots = Math.ceil(durationMs / slotMs);
  const routeSamples = [];
  const feedbackSamples = [];
  const eventSamples = [];
  const activityPageSamples = [];
  const firstDataSamples = [];
  const delivered = new Set();
  const selectedJobs = [];
  let activityRowsDelivered = 0;
  let identityViolation = false;
  let reconnects = 0;
  let reconnectDeliveries = 0;
  let visibilityTransitions = 0;
  let retentionGapRecovered = false;
  let sourceReads = 0;
  let latestRouteMs = 0;
  let latestEventMs = 0;
  let stage = 'startup';
  const samples = [];
  const checkpoints = [];
  const retentionSamples = [];
  const openStreams = new Set();
  const pendingEventStreams = new Set();
  const dashboardListingTracker = createDashboardListingTracker({ cdp, sessionId: tab.sessionId, origin });
  let streamLimitResponses = 0;
  let successfulStreamOpens = 0;
  const leaseRenewals = [];
  let drainSeconds = 0;
  cdp.on('Network.requestWillBeSent', (event) => {
    const path = new URL(event.request.url).pathname;
    const accept = event.request.headers.Accept ?? event.request.headers.accept ?? '';
    if (path.endsWith('/events') && accept === 'text/event-stream') {
      pendingEventStreams.add(event.requestId);
    }
  }, tab.sessionId);
  cdp.on('Network.responseReceived', (event) => {
    if (!pendingEventStreams.has(event.requestId)) return;
    if (event.response.status === 200) {
      openStreams.add(event.requestId);
      successfulStreamOpens++;
    } else if (event.response.status === 429) streamLimitResponses++;
  }, tab.sessionId);
  for (const eventName of ['Network.loadingFinished', 'Network.loadingFailed']) {
      cdp.on(eventName, (event) => { openStreams.delete(event.requestId); pendingEventStreams.delete(event.requestId); }, tab.sessionId);
  }

  await cdp.call('Performance.enable', {}, tab.sessionId);
  await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: `(() => { const original = fetch; let count = 0;
    Object.defineProperty(window, '__soakSnapshotReads', { get: () => count });
    window.fetch = function(input, init) { if (String(input).includes('/snapshot')) count++; return original.call(this, input, init); };
  })();` }, tab.sessionId);
  await cdp.call('Page.navigate', { url: `${origin}/nested/` }, tab.sessionId);
  await ready(tab, `document.querySelector('h1')?.textContent === 'Your work, with its evidence'`, 'soak dashboard');
  await ready(tab, `!!document.querySelector('ul[aria-label="Uploaded jobs"] a[href="/nested/jobs/${fixture.jobs[0].jobId}"]')`, 'seeded jobs visible on dashboard');
  const listenerProbeVersion = await evaluate(tab, 'window.__workbenchListenerRetention?.snapshot()?.version ?? null');
  assert.equal(listenerProbeVersion, 1, 'Listener-retention instrumentation must run before the packaged frontend');
  const initialDocumentCount = tab.documentRequests.length;
  await cdp.call('HeapProfiler.enable', {}, tab.sessionId);
  await cdp.call('HeapProfiler.collectGarbage', {}, tab.sessionId);
  const initialHeap = await cdp.call('Performance.getMetrics', {}, tab.sessionId);
  const initialBrowserHeapMiB = (initialHeap.metrics.find(metric => metric.name === 'JSHeapUsedSize')?.value ?? NaN) / (1024 * 1024);
  assert.ok(Number.isFinite(initialBrowserHeapMiB), 'Initial renderer heap measurement is missing');
  const baselineProcess = await sampleProcessTree(applicationPid);
  const baseline = { jvmTreeRssMiB: baselineProcess.jvmTreeRssBytes / (1024 * 1024), fdCount: baselineProcess.fdCount,
    pids: Object.fromEntries(baselineProcess.processIdentities.map(process => [process.pid, process.startTime])) };
  const samplingOrigin = performance.now();
  const startedAt = Date.now();
  let sampling = true;
  const publishPartial = () => onPartial({ incomplete: true, stage, workloadDurationMs: activeScheduleMs,
    wallDurationMs: Date.now() - startedAt, slotDurationMs: slotMs, slots, selectedJobs: [...selectedJobs],
    uniqueJobs: [...new Set(selectedJobs)], activityRowsDelivered, routeLatencyMs: routeSamples,
    routeFeedbackLatencyMs: feedbackSamples, activityReadLatencyMs: eventSamples,
    activityPageLatencyMs: activityPageSamples, firstDataLatencyMs: firstDataSamples.length ? Math.max(...firstDataSamples) : null,
    jobSwitches: Math.max(0, selectedJobs.length - 1), sameDocument: true, identityViolation, sourceReads,
    initialBrowserHeapMiB, finalBrowserHeapMiB: null, baseline, samples, checkpoints, leaseRenewals,
    retention: { version: 1, sampleEverySlots: 5, samples: retentionSamples, complete: false },
    fdPeak: Math.max(...samples.map(sample => sample.fdCount), baseline.fdCount), fdQuiescent: null, drainSeconds,
    coverage: { activityRows: activityRowsDelivered, fourJobs: delivered.size === 4, slots: selectedJobs.length,
      reconnects, reconnectDeliveries, visibilityTransitions, naturalLeaseRenewals: leaseRenewals.length,
      retentionGapRecovered, sourceReads, streamLimitResponses, successfulStreamOpens,
      listenerRetentionSamples: retentionSamples.length, retentionNavigations: retentionSamples.length,
      finalCleanup: openStreams.size === 0 } });
  const sampleTask = (async () => {
    const observedIdentities = new Map(Object.entries(baseline.pids).map(([pid, start]) => [Number(pid), start]));
    while (sampling) {
      const process = await sampleProcessTree(applicationPid);
      for (const identity of process.processIdentities) {
        const previous = observedIdentities.get(identity.pid);
        if (previous !== undefined && previous !== identity.startTime) throw new Error('PID reused with a different process start identity');
        observedIdentities.set(identity.pid, identity.startTime);
      }
      const metrics = await cdp.call('Performance.getMetrics', {}, tab.sessionId);
      const heap = metrics.metrics.find(metric => metric.name === 'JSHeapUsedSize')?.value;
      if (!Number.isFinite(heap)) throw new Error('Renderer heap telemetry is missing');
      samples.push({ pid: process.rootPid, startTime: process.rootStartTime,
        jvmTreeRssMiB: process.jvmTreeRssBytes / (1024 * 1024), fdCount: process.fdCount,
        rendererHeapMiB: heap / (1024 * 1024), streamCount: openStreams.size,
        eventLatencyMs: latestEventMs, routeLatencyMs: latestRouteMs, sampledAtMonotonicMs: performance.now() - samplingOrigin });
      if (samples.length > durationMs / 1000 + 360) throw new Error('Resource telemetry exceeded the bounded sample envelope');
      publishPartial();
      await delay(1000);
    }
  })();
  let activeScheduleMs = 0;
  const drainAtCheckpoint = async (label) => {
    await clickHref(tab, evaluate, '/nested/runtime');
    await ready(tab, `location.pathname === '/nested/runtime' && document.querySelector('#server-runtime-title')`, `Runtime checkpoint ${label}`);
    const start = Date.now();
    while (openStreams.size > 0 && Date.now() - start < LIMITS.drainSeconds * 1000) await delay(100);
    const elapsed = (Date.now() - start) / 1000;
    drainSeconds = Math.max(drainSeconds, elapsed);
    assert.equal(openStreams.size, 0, `Activity stream did not drain within the 35-second budget at ${label}`);
  };
  try { for (let slot = 0; slot < slots; slot++) {
    stage = `slot-${slot}-dashboard`;
    const slotStartedAt = Date.now();
    const job = fixture.jobs[slot % fixture.jobs.length];
    const routeStarted = Date.now();
    const current = await evaluate(tab, 'location.pathname');
    if (current !== '/nested/') feedbackSamples.push(await clickHref(tab, evaluate, '/nested/', true));
    await ready(tab, `location.pathname === '/nested/'`, `dashboard before slot ${slot}`);
    try {
      await ready(tab, `!!document.querySelector('ul[aria-label="Uploaded jobs"] a[href="/nested/jobs/${job.jobId}"]')`, `job ${job.index} visible before slot ${slot}`);
    } catch (failure) {
      const listing = tab.responses.filter(response => response.url.endsWith('/api/v1/jobs')).at(-1);
      let listingFailure = { status: listing?.status ?? null };
      if (listing) {
        try {
          const body = await cdp.call('Network.getResponseBody', { requestId: listing.requestId }, tab.sessionId);
          const payload = JSON.parse(body.body);
          listingFailure = { status: listing.status, errorCode: payload.error?.code ?? null,
            errorMessage: typeof payload.error?.message === 'string' ? payload.error.message.slice(0, 240) : null };
        } catch (bodyFailure) { listingFailure.bodyReadError = String(bodyFailure.message).slice(0, 160); }
      }
      throw new Error(`Job library did not expose job ${job.index}: ${JSON.stringify(listingFailure)}; ${failure.message}`);
    }
    stage = `slot-${slot}-job`;
    feedbackSamples.push(await clickHref(tab, evaluate, `/nested/jobs/${job.jobId}`, true));
    try {
      await ready(tab, `location.pathname === '/nested/jobs/${job.jobId}' && document.body.innerText.includes(${JSON.stringify(job.filename)})`, `selected job ${job.index}`);
    } catch (failure) {
      const response = tab.responses.filter(item => item.url.endsWith(`/api/v1/jobs/${job.jobId}`)).at(-1);
      let responseSummary = { status: response?.status ?? null };
      if (response) {
        try {
          const body = await cdp.call('Network.getResponseBody', { requestId: response.requestId }, tab.sessionId);
          const payload = JSON.parse(body.body);
          const data = payload.data;
          responseSummary = { status: response.status, envelopeKeys: Object.keys(payload), dataKeys: data ? Object.keys(data) : [],
            returnedJobId: data?.jobId ?? null, filename: data?.displayFilename ?? null, latestRunId: data?.latestRunId ?? null };
        } catch (bodyFailure) { responseSummary.bodyReadError = String(bodyFailure.message).slice(0, 160); }
      }
      throw new Error(`Selected job page did not settle: ${JSON.stringify(responseSummary)}; ${failure.message}`);
    }
    stage = `slot-${slot}-attempt`;
    feedbackSamples.push(await clickHref(tab, evaluate, `/nested/jobs/${job.jobId}/runs/${job.runId}`, true));
    await ready(tab, `location.pathname === '/nested/jobs/${job.jobId}/runs/${job.runId}'`, `attempt ${job.runId}`);
    const sourceDirectory = `/nested/jobs/${job.jobId}/runs/${job.runId}/revisions/${job.revisionId}/sources/root`;
    stage = `slot-${slot}-source-directory`;
    await ready(tab, `!!document.querySelector('a[href=${JSON.stringify(sourceDirectory)}]')`, `attempt source link ${job.index}`);
    feedbackSamples.push(await clickHref(tab, evaluate, sourceDirectory, true));
    await ready(tab, `location.pathname === ${JSON.stringify(sourceDirectory)} && document.body.innerText.includes('Makefile')`, `source directory ${job.index}`);
    const sourceHref = await evaluate(tab, `([...document.querySelectorAll('a')].find(link => link.textContent.includes('Makefile'))?.getAttribute('href'))`);
    assert.ok(sourceHref && sourceHref.includes('/source-files/'), 'Source directory did not expose its authenticated file route');
    stage = `slot-${slot}-source-file`;
    await clickHref(tab, evaluate, sourceHref);
    try {
      await ready(tab, `[...document.querySelectorAll('h2')].some(heading => heading.textContent === 'Makefile')`, `source metadata ${job.index}`);
    } catch (failure) {
      const page = await evaluate(tab, `({ path: location.pathname, headings: [...document.querySelectorAll('h1,h2,h3')].map(node => node.textContent).slice(0, 12),
        alerts: [...document.querySelectorAll('[role=alert],[role=status]')].map(node => node.textContent.slice(0, 240)).slice(0, 8),
        buttons: [...document.querySelectorAll('button')].map(node => node.textContent).slice(0, 16), text: document.body.innerText.slice(0, 900) })`)
        .catch(error => ({ evaluationError: String(error.message).slice(0, 160) }));
      const response = tab.responses.filter(item => item.url.includes('/source-files/')).at(-1);
      let fileResponse = { status: response?.status ?? null };
      if (response) {
        try {
          const body = await cdp.call('Network.getResponseBody', { requestId: response.requestId }, tab.sessionId);
          const payload = JSON.parse(body.body);
          fileResponse = { status: response.status, envelopeKeys: Object.keys(payload), dataKeys: payload.data ? Object.keys(payload.data) : [],
            fileName: payload.data?.item?.displayName ?? null, errorCode: payload.error?.code ?? null,
            errorMessage: typeof payload.error?.message === 'string' ? payload.error.message.slice(0, 180) : null };
        } catch (bodyFailure) { fileResponse.bodyReadError = String(bodyFailure.message).slice(0, 160); }
      }
      throw new Error(`Source metadata did not settle: ${JSON.stringify({ page, fileResponse })}; ${failure.message}`);
    }
    const previewAvailable = await evaluate(tab, `[...document.querySelectorAll('button')].some(button => button.textContent === 'Open source preview')`);
    if (!previewAvailable) {
      // Reconnection deliberately leaves previously loaded metadata marked stale. Use the page's
      // explicit refresh before requiring a fresh bounded content read.
      await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Refresh file metadata').click()`);
      await ready(tab, `[...document.querySelectorAll('button')].some(button => button.textContent === 'Open source preview')`, `refreshed source preview capability ${job.index}`);
    }
    await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Open source preview').click()`);
    await ready(tab, `document.body.innerText.includes(${JSON.stringify(`inert-soak-source-${job.index + 1}`)})`, `source body ${job.index}`);
    sourceReads += 2;
    stage = `slot-${slot}-activity-route`;
    await clickHref(tab, evaluate, `/nested/jobs/${job.jobId}/runs/${job.runId}`);
    await ready(tab, `location.pathname === '/nested/jobs/${job.jobId}/runs/${job.runId}'`, `return to attempt ${job.index}`);
    await ready(tab, `!!document.querySelector('a[href=${JSON.stringify(sourceDirectory)}]')`, `attempt refreshed after source read ${job.index}`);
    latestRouteMs = Date.now() - routeStarted;
    routeSamples.push(latestRouteMs);
    selectedJobs.push(job.jobId);
    delivered.add(job.jobId);

    stage = `slot-${slot}-activity-start`;
    const beforeEvent = Date.now();
    // Activity is a real route panel; use its visible control, not direct endpoint stubs.
    const followed = await evaluate(tab, `(() => { const button = [...document.querySelectorAll('button')].find(b => b.textContent === 'Follow activity'); if (!button) return false; button.click(); return true; })()`);
    assert.equal(followed, true, `Each job must start a real Activity read; page ${JSON.stringify(await evaluate(tab, `({path:location.pathname,buttons:[...document.querySelectorAll('button')].map(button=>button.textContent),text:document.body.innerText.slice(-1400)})`))}`);
    stage = `slot-${slot}-activity-first-page`;
    await ready(tab, `(${activityRows}).length === 200`, `activity page for job ${job.index}`, 15000);
    const firstDataMs = Date.now() - beforeEvent;
    firstDataSamples.push(firstDataMs);
    const firstRows = await evaluate(tab, activityRows);
    assert.equal(firstRows[0], 'Sequence 0');
    const nextSequence = JSON.parse(await fs.readFile(job.progressPath, 'utf8')).nextSequence;
    const expectedTail = Array.from({ length: Math.min(200, Math.max(0, nextSequence - 200)) }, (_, i) => `Sequence ${i + 200}`);
    let continuedRows = [];
    // Every slot reads the bounded 200-row page. Continue to the tail on the initial and every
    // reconnect slot, keeping a live stream available for the reconnect and retention controls
    // without opening a new leased stream on every rapid route switch.
    if (slot === 0 || slot % 6 === 5) {
      const focusContinuation = await evaluate(tab, `(() => { const button = [...document.querySelectorAll('button')].find(b => b.textContent === 'Continue activity on next page'); if (!button || button.disabled) return null; button.focus(); return document.activeElement.textContent; })()`);
      assert.equal(focusContinuation, 'Continue activity on next page', 'Continuation control must receive keyboard focus');
      stage = `slot-${slot}-activity-continuation`;
      await evaluate(tab, `([...document.querySelectorAll('button')].find(button => button.textContent === 'Continue activity on next page')).click()`);
      await ready(tab, `(${activityRows}).length === ${expectedTail.length}`, 'activity continuation page', 15000);
      continuedRows = await evaluate(tab, activityRows);
      assert.deepEqual(continuedRows, expectedTail);
    }
    const activityIdentityMatches = await evaluate(tab, `Array.from(document.querySelectorAll('ol[aria-label="Activity observations"] li')).every(row =>
      [...row.querySelectorAll('a')].some(link => link.getAttribute('href') === ${JSON.stringify(`/nested/jobs/${job.jobId}/runs/${job.runId}`)}) &&
      row.innerText.includes(${JSON.stringify(job.runId)}))`);
    if (!activityIdentityMatches) identityViolation = true;
    assert.equal(activityIdentityMatches, true, 'Rendered Activity rows must identify the selected job and attempt');
    activityRowsDelivered += firstRows.length + continuedRows.length;
    latestEventMs = firstDataMs;
    activityPageSamples.push(Date.now() - beforeEvent);
    if (slot === 0) {
      const original = JSON.parse(job.progress);
      const appended = { ...original, nextSequence: OBSERVATIONS + 1,
        events: [...original.events, { ...original.events.at(-1), sequence: OBSERVATIONS,
          time: new Date().toISOString(), text: 'Synthetic soak gap probe' }] };
      await publishProgress(job.progressPath, appended);
      await ready(tab, `(${activityRows}).includes('Sequence ${OBSERVATIONS}')`, 'retention probe delivered');
      await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Pause activity').click()`);
      await ready(tab, `document.body.innerText.includes('Activity paused.')`, 'pause before retention reset');
      await publishProgress(job.progressPath, original);
      await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Resume activity').click()`);
      await ready(tab, `document.querySelector('[role="alert"]')?.textContent.includes('Retained history has a gap')`, 'retained Activity gap surfaced');
      await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Read fresh activity history').click()`);
      await ready(tab, `(${activityRows}).length === 200 && !document.querySelector('[role="alert"]')`, 'explicit retention-gap recovery');
      retentionGapRecovered = true;
    }
    if (slot % 6 === 5) {
      const snapshotsBefore = await evaluate(tab, 'window.__soakSnapshotReads');
      await cdp.call('Network.emulateNetworkConditions', { offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0 }, tab.sessionId);
      await delay(300);
      await cdp.call('Network.emulateNetworkConditions', { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 }, tab.sessionId);
      await ready(tab, `document.body.innerText.includes('Following retained activity.')`, 'activity reconnect recovery', 15000);
      await ready(tab, `window.__soakSnapshotReads > ${snapshotsBefore}`, 'post-reconnect snapshot reconciliation', 15000);
      const persisted = JSON.parse(await fs.readFile(job.progressPath, 'utf8'));
      const sequence = persisted.nextSequence;
      const occurredAt = new Date().toISOString();
      persisted.nextSequence = sequence + 1;
      persisted.events.push({ ...persisted.events.at(-1), sequence, time: occurredAt,
        text: `Synthetic reconnect delivery ${reconnects + 1}` });
      await publishProgress(job.progressPath, persisted);
      await ready(tab, `(${activityRows}).includes('Sequence ${sequence}')`, 'new observation after reconnect', 15000);
      // The shell schedules authenticated session revalidation shortly after the browser's
      // online event. Let that bounded refresh finish before the next private source read.
      eventSamples.push(Date.now() - Date.parse(occurredAt));
      await delay(1500);
      reconnects++;
      reconnectDeliveries++;
    }
    if (slot % 12 === 11) {
      const peer = await cdp.call('Target.createTarget', { url: 'about:blank' });
      const attached = await cdp.call('Target.attachToTarget', { targetId: peer.targetId, flatten: true });
      await cdp.call('Page.bringToFront', {}, attached.sessionId);
      await ready(tab, `document.visibilityState === 'hidden'`, 'background activity suspension');
      await cdp.call('Page.bringToFront', {}, tab.sessionId);
      await ready(tab, `document.visibilityState === 'visible'`, 'foreground activity reconciliation');
      await cdp.call('Target.closeTarget', { targetId: peer.targetId });
      visibilityTransitions++;
    }
    const remaining = slotMs - (Date.now() - slotStartedAt);
    if (remaining < 0) throw new Error(`Soak slot ${slot} exceeded its ten-second schedule by ${-remaining}ms`);
    if (remaining > 0) await delay(remaining);
    activeScheduleMs += slotMs;
    if ((slot + 1) % 5 === 0) {
      stage = `retention-sample-${slot + 1}-dashboard`;
      const dashboardNavigationStartedAt = Date.now();
      const dashboardListingObservation = dashboardListingTracker.begin();
      await clickHref(tab, evaluate, '/nested/');
      await ready(tab, `location.pathname === '/nested/'`, `dashboard for retention sample ${slot + 1}`);
      const dashboardNavigationMs = Date.now() - dashboardNavigationStartedAt;
      await ready(tab, `!!document.querySelector('ul[aria-label="Uploaded jobs"] a[href="/nested/jobs/${fixture.jobs[0].jobId}"]')`,
        `dashboard fixture job visible for retention sample ${slot + 1}`);
      const dashboardListing = await dashboardListingTracker.waitForCompletion(dashboardListingObservation);
      await ready(tab, `(() => { const button = [...document.querySelectorAll('button')].find(item => item.textContent === 'Refresh jobs'); return !!button && !button.disabled; })()`,
        `dashboard listing settled before retention sample ${slot + 1}`);
      const drainStarted = Date.now();
      while (openStreams.size > 0 && Date.now() - drainStarted < LIMITS.drainSeconds * 1000) await delay(100);
      const streamDrainMs = Date.now() - drainStarted;
      assert.equal(openStreams.size, 0, `Activity stream request did not close within ${LIMITS.drainSeconds} seconds before retention sample ${slot + 1}`);
      const retention = await sampleRetention({ cdp, tab, evaluate, index: slot + 1, settledRoute: '/nested/' });
      retention.openStreamCount = openStreams.size;
      retention.dashboardNavigationMs = dashboardNavigationMs;
      retention.dashboardListing = dashboardListing;
      retention.streamDrainMs = streamDrainMs;
      retentionSamples.push(retention);
      assert.ok(retentionSamples.length <= Math.ceil(slots / 5), 'Listener-retention observations exceeded the bounded sample envelope');
      publishPartial();
    }
    if ((slot + 1) % 30 === 0) {
      const minute = (slot + 1) / 6;
      await drainAtCheckpoint(minute);
      await cdp.call('HeapProfiler.collectGarbage', {}, tab.sessionId);
      const checkpointHeap = await cdp.call('Performance.getMetrics', {}, tab.sessionId);
      const browserHeapMiB = (checkpointHeap.metrics.find(metric => metric.name === 'JSHeapUsedSize')?.value ?? NaN) / (1024 * 1024);
      const checkpointProcess = await sampleProcessTree(applicationPid);
      checkpoints.push({ minute, browserHeapMiB, jvmTreeRssMiB: checkpointProcess.jvmTreeRssBytes / (1024 * 1024),
        fdCount: checkpointProcess.fdCount, processCount: checkpointProcess.processCount });
      await onProgress({ minute, slot: slot + 1, slots, elapsedMs: activeScheduleMs, wallElapsedMs: Date.now() - startedAt });
      if (slot + 1 < slots) {
        feedbackSamples.push(await clickHref(tab, evaluate, '/nested/', true));
        await ready(tab, `location.pathname === '/nested/'`, `resume after minute ${minute} checkpoint`);
      }
    }
  }
    // Re-enter a real Activity view after the final checkpoint; the checkpoint itself deliberately
    // drained and closed that stream. Keep this document foregrounded for each natural renewal.
    const finalJob = fixture.jobs[(slots - 1) % fixture.jobs.length];
    const finalAttempt = `/nested/jobs/${finalJob.jobId}/runs/${finalJob.runId}`;
    feedbackSamples.push(await clickHref(tab, evaluate, '/nested/', true));
    await ready(tab, `location.pathname === '/nested/'`, 'dashboard before final renewal');
    await ready(tab, `(() => { const button = [...document.querySelectorAll('button')].find(item => item.textContent === 'Refresh jobs'); return !!button && !button.disabled; })()`,
      'final dashboard listing settled');
    const finalJobHref = `/nested/jobs/${finalJob.jobId}`;
    let finalJobVisible = await evaluate(tab, `!!document.querySelector('ul[aria-label="Uploaded jobs"] a[href=${JSON.stringify(finalJobHref)}]')`);
    if (!finalJobVisible) {
      // The shell marks previously loaded pages stale after transport recovery. A final
      // lifecycle read must explicitly refresh the dashboard before selecting the job.
      const refreshed = await evaluate(tab, `(() => { const button = [...document.querySelectorAll('button')].find(item => item.textContent === 'Refresh jobs');
        if (!button || button.disabled) return false; button.click(); return true; })()`);
      assert.equal(refreshed, true, `Dashboard did not expose a usable refresh after recovery: ${JSON.stringify(await evaluate(tab,
        `({ path: location.pathname, headings: [...document.querySelectorAll('h1,h2')].map(node => node.textContent).slice(0, 8),
          alerts: [...document.querySelectorAll('[role=alert]')].map(node => node.textContent.slice(0, 220)),
          buttons: [...document.querySelectorAll('button')].map(node => node.textContent).slice(0, 16) })`))}`);
      try { await ready(tab, `!!document.querySelector('ul[aria-label="Uploaded jobs"] a[href=${JSON.stringify(finalJobHref)}]')`, 'refreshed final dashboard job'); }
      catch (failure) {
        const listing = tab.responses.filter(response => response.url.endsWith('/api/v1/jobs')).at(-1);
        let listingSummary = { status: listing?.status ?? null };
        if (listing) {
          try {
            const body = await cdp.call('Network.getResponseBody', { requestId: listing.requestId }, tab.sessionId);
            const payload = JSON.parse(body.body);
            const items = payload.data?.items;
            listingSummary = { status: listing.status, dataKeys: payload.data ? Object.keys(payload.data) : [],
              itemCount: Array.isArray(items) ? items.length : null, containsFinalJob: Array.isArray(items) && items.some(item => item.jobId === finalJob.jobId),
              errorCode: payload.error?.code ?? null };
          } catch (bodyFailure) { listingSummary.bodyReadError = String(bodyFailure.message).slice(0, 160); }
        }
        throw new Error(`Final dashboard refresh did not restore the selected fixture job: ${JSON.stringify(listingSummary)}; ${failure.message}`);
      }
    }
    feedbackSamples.push(await clickHref(tab, evaluate, `/nested/jobs/${finalJob.jobId}`, true));
    await ready(tab, `location.pathname === '/nested/jobs/${finalJob.jobId}' && document.body.innerText.includes(${JSON.stringify(finalJob.filename)})`, 'job before final renewal');
    feedbackSamples.push(await clickHref(tab, evaluate, finalAttempt, true));
    await ready(tab, `location.pathname === ${JSON.stringify(finalAttempt)}`, 'final activity attempt');
    await ready(tab, `[...document.querySelectorAll('button')].some(button => button.textContent === 'Follow activity')`, 'final Activity control');
    await evaluate(tab, ` [...document.querySelectorAll('button')].find(button => button.textContent === 'Follow activity').click()`);
    await ready(tab, `(${activityRows}).length === 200`, 'final Activity first page');
    const finalContinuation = await evaluate(tab, `(() => { const button = [...document.querySelectorAll('button')].find(b => b.textContent === 'Continue activity on next page'); if (!button || button.disabled) return null; button.focus(); return document.activeElement.textContent; })()`);
    assert.equal(finalContinuation, 'Continue activity on next page');
    const streamStart = successfulStreamOpens;
    // The stream response can arrive before either first-page or rendered-tail readiness settles.
    await evaluate(tab, `document.activeElement.click()`);
    const finalNextSequence = JSON.parse(await fs.readFile(finalJob.progressPath, 'utf8')).nextSequence;
    const finalTailCount = Math.min(200, Math.max(0, finalNextSequence - 200));
    await ready(tab, `(${activityRows}).length === ${finalTailCount} && document.body.innerText.includes('Following retained activity.')`, 'final live Activity stream');
    const streamOpened = await waitForSuccessfulStreamOpen({ startCount: streamStart, getCount: () => successfulStreamOpens,
      // A prior Activity lease may still be draining after the route transition;
      // allow one 30-second lease horizon plus one bounded stream retry interval.
      deadlineMs: Date.now() + 45_000, delay });
    assert.ok(streamOpened, 'Tail continuation must open a successful leased Activity stream');
    // Four natural foreground dwells demonstrate renewal across the server's 30-second lease.
    for (let renewal = 0; renewal < 4; renewal++) {
      const before = successfulStreamOpens;
      const dwellStarted = Date.now();
      // Keep a little scheduling headroom above the evaluator's strict 35s floor.
      await delay(35_250);
      assert.ok(successfulStreamOpens > before, `Foreground stream did not successfully renew during dwell ${renewal + 1}`);
      leaseRenewals.push({ dwellMs: Date.now() - dwellStarted, streamOpensBefore: before, streamOpensAfter: successfulStreamOpens });
    }
    await drainAtCheckpoint('final');
    await cdp.call('HeapProfiler.collectGarbage', {}, tab.sessionId);
  } finally {
    sampling = false;
    await sampleTask;
  }
  assert.equal(selectedJobs.length, slots);
  assert.equal(new Set(selectedJobs).size, 4);
  assert.equal(tab.documentRequests.length, initialDocumentCount, 'In-app soak navigation must retain one browser document');
  assert.equal(tab.instrumentationTruncated, false, 'Bounded browser observation storage truncated during the soak');
  const finalProcess = await sampleProcessTree(applicationPid);
  const finalMetrics = await cdp.call('Performance.getMetrics', {}, tab.sessionId);
  const finalBrowserHeapMiB = (finalMetrics.metrics.find(metric => metric.name === 'JSHeapUsedSize')?.value ?? NaN) / (1024 * 1024);
  assert.ok(Number.isFinite(finalBrowserHeapMiB), 'Final renderer heap measurement is missing');
  return { workloadDurationMs: activeScheduleMs, wallDurationMs: Date.now() - startedAt, slotDurationMs: slotMs, slots, selectedJobs,
    uniqueJobs: [...new Set(selectedJobs)], activityRowsDelivered, routeLatencyMs: routeSamples, identityViolation,
    routeFeedbackLatencyMs: feedbackSamples, activityReadLatencyMs: eventSamples, activityPageLatencyMs: activityPageSamples,
    firstDataLatencyMs: Math.max(...firstDataSamples),
    jobSwitches: slots - 1, sameDocument: true, sourceReads,
    initialBrowserHeapMiB, finalBrowserHeapMiB, baseline, samples, checkpoints, leaseRenewals,
    fdPeak: Math.max(...samples.map(s => s.fdCount), baseline.fdCount),
    fdQuiescent: finalProcess.fdCount - baseline.fdCount, drainSeconds,
    retention: { version: 1, sampleEverySlots: 5, samples: retentionSamples, complete: true },
    coverage: { activityRows: activityRowsDelivered, fourJobs: delivered.size === 4, slots, reconnects, visibilityTransitions,
      reconnectDeliveries, naturalLeaseRenewals: leaseRenewals.length, retentionGapRecovered, sourceReads,
      streamLimitResponses, successfulStreamOpens, listenerRetentionSamples: retentionSamples.length,
      retentionNavigations: retentionSamples.length,
      finalCleanup: openStreams.size === 0 },
    note: 'Each slot reads the bounded 200-row activity page. The initial slot and every reconnect slot continue to the tail; other rapid job switches avoid creating unnecessary leased streams. Every fifth slot adds one in-app dashboard navigation and waits for the Activity stream request to close before its post-GC retention sample; this instrumented workload is distinct from earlier soak measurements. Source complexity is one inert Makefile per job.' };
}
