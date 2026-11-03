import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const RUN = 'run_fixture_3';
const MAX_REPORT_BYTES = 512 * 1024;

/** Replace-by-rename publication, so a reader never observes a partial progress journal. */
export async function publishAtomically(path, text) {
  const publication = path + '.browser-publication';
  await fs.rm(publication, { force: true });
  await fs.writeFile(publication, text, { flag: 'wx', mode: 0o600 });
  await fs.rename(publication, path);
}

/** Finds one local-bootstrap handoff in captured JVM output; returns null if absent. */
export function findBootstrap(output, origin) {
  const prefix = origin + '/nested/#bootstrap=';
  const url = String(output).split(/\s+/).find(part => part.startsWith(prefix) && /^[A-Za-z0-9_-]+$/.test(part.slice(prefix.length)));
  return url ? { url, token: url.slice(prefix.length) } : null;
}

/** Graceful means exactly one SIGTERM, then a normal JVM exit; never a kill escalation. */
export function assertGracefulShutdown({ signalsSent, exitCode, signalCode }) {
  assert.deepEqual(signalsSent, ['SIGTERM'], 'Restart must send exactly one SIGTERM and no other signal');
  const clean = (exitCode === 0 || exitCode === 143) && signalCode === null || exitCode === null && signalCode === 'SIGTERM';
  assert.ok(clean, `Application did not exit as a graceful SIGTERM shutdown: code=${exitCode} signal=${signalCode}`);
  return { signalsSent: ['SIGTERM'], exitCode, signalCode };
}

export function scrubTokens(value, tokens) {
  const live = tokens.filter(Boolean);
  const text = value => {
    let safe = value.replaceAll(/#bootstrap=[A-Za-z0-9_-]+/g, '#bootstrap=[redacted]');
    for (const token of live) safe = safe.replaceAll(token, '[redacted]');
    return safe;
  };
  if (Array.isArray(value)) return value.map(item => scrubTokens(item, tokens));
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, scrubTokens(v, tokens)]));
  return typeof value === 'string' ? text(value) : value;
}

/** Keeps a retained report under a byte bound by replacing request lists with counts. */
export function boundReport(report, maxBytes = MAX_REPORT_BYTES) {
  if (Buffer.byteLength(JSON.stringify(report), 'utf8') <= maxBytes) return report;
  const bounded = structuredClone(report);
  if (bounded.requests) bounded.requests = Object.fromEntries(Object.entries(bounded.requests)
    .map(([name, list]) => [name, Array.isArray(list) ? { count: list.length, truncated: true } : list]));
  assert.ok(Buffer.byteLength(JSON.stringify(bounded), 'utf8') <= maxBytes, 'Report exceeds its byte bound after truncation');
  return bounded;
}

export function summarizeRequests(requests) {
  const methods = {};
  for (const request of requests) methods[request.method] = (methods[request.method] ?? 0) + 1;
  return { total: requests.length, methods, mutations: requests.filter(r => !['GET', 'HEAD'].includes(r.method)) };
}

export function isProgressReadUrl(value) {
  try {
    const path = new URL(value).pathname;
    return path.endsWith('/events') || path.endsWith('/snapshot');
  } catch {
    return false;
  }
}

export function matchingResponse(request, responses) {
  return responses.find(response => response.requestId === request.requestId) ?? null;
}

export function hasOpenEventStream(streams) {
  return [...streams.values()].some(stream => stream.open);
}

/** Only the known session exchanges and progress-pin PUTs may mutate in this fixture. */
export function assertOnlyPinWrites(requests, pinUrl, expectedPuts, sessionUrl = null, expectedSessionPosts = 0) {
  const mutations = requests.filter(r => !['GET', 'HEAD'].includes(r.method));
  const pinWrites = mutations.filter(r => r.method === 'PUT' && r.url === pinUrl);
  const sessionPosts = mutations.filter(r => r.method === 'POST' && sessionUrl !== null && r.url === sessionUrl);
  assert.ok(mutations.every(r => (r.method === 'PUT' && r.url === pinUrl) ||
    (r.method === 'POST' && sessionUrl !== null && r.url === sessionUrl)),
  `Unexpected mutation outside the selected attempt and session exchange: ${JSON.stringify(mutations)}`);
  assert.equal(pinWrites.length, expectedPuts, `Expected ${expectedPuts} pin PUT request(s), saw ${pinWrites.length}`);
  assert.equal(sessionPosts.length, expectedSessionPosts,
    `Expected ${expectedSessionPosts} explicit session exchange(s), saw ${sessionPosts.length}`);
  assert.equal(mutations.length, expectedPuts + expectedSessionPosts, 'Unexpected mutation count');
}

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

export async function qualifyRestart({ fixture, origin, makeTarget, cdp, evaluate, ready, waitFor, delay, readOutput, restartApplication,
  captureSafe, sensitiveValues }) {
  const basePath = '/nested';
  const runPath = `${basePath}/jobs/${fixture.jobId}/runs/${RUN}`;
  const pinUrl = `${origin}${basePath}/api/v1/jobs/${fixture.jobId}/runs/${RUN}/progress-pin`;
  const statePath = join(fixture.directory, 'workflow-state.json');
  const rows = `Array.from(document.querySelectorAll('ol[aria-label="Activity observations"] li span')).map(row => row.textContent)`;
  const button = label => `[...document.querySelectorAll('button')].find(b => b.textContent === ${JSON.stringify(label)})`;
  const evidence = { phases: [] };
  const serverInstance = tab => evaluate(tab, `fetch('${basePath}/api/v1/bootstrap', { credentials: 'same-origin' }).then(r => r.json()).then(b => b.data.serverInstanceId ?? null)`);
  const track = tab => {
    tab.streams = 0;
    tab.eventStreams = new Map();
    cdp.on('Network.requestWillBeSent', event => {
      if (event.type === 'Fetch' && new URL(event.request.url).pathname.endsWith('/events') &&
        (event.request.headers.Accept ?? event.request.headers.accept) === 'text/event-stream') {
        tab.streams++;
        tab.eventStreams.set(event.requestId, { open: true, url: event.request.url });
      }
    }, tab.sessionId);
    for (const eventName of ['Network.loadingFinished', 'Network.loadingFailed']) {
      cdp.on(eventName, event => {
        const stream = tab.eventStreams.get(event.requestId);
        if (stream) stream.open = false;
      }, tab.sessionId);
    }
    return tab;
  };
  const progressReads = tab => tab.requests.filter(r => isProgressReadUrl(r.url)).length;
  const openRun = async (tab, label) => {
    await cdp.call('Page.navigate', { url: origin + runPath }, tab.sessionId);
    await cdp.call('Page.bringToFront', {}, tab.sessionId);
    await ready(tab, `document.querySelector('section[aria-label="Progress retention"]') !== null`, label);
  };
  const follow = async (tab, label) => {
    await evaluate(tab, `${button('Follow activity')}.click()`);
    await ready(tab, `(${rows}).length === 200`, label);
  };
  const continueFollowing = async (tab, label) => {
    await ready(tab, `[...document.querySelectorAll('button')].some(b => b.textContent === 'Continue activity on next page' && !b.disabled)`,
      label + ' continuation control');
    await evaluate(tab, `${button('Continue activity on next page')}.click()`);
    await ready(tab, `(${rows}).length === 5 && document.body.innerText.includes('Following retained activity.')`, label);
  };
  const readPin = async (tab, label, expected = 'Progress history is not pinned.') => {
    await ready(tab, `[...document.querySelectorAll('button')].some(b => b.textContent === 'Read progress pin' && !b.disabled)`, label + ' controls');
    await evaluate(tab, `${button('Read progress pin')}.click()`);
    await ready(tab, `document.body.innerText.includes(${JSON.stringify(expected)})`, label);
  };

  // Phase A: first JVM, one explicit bootstrap, a populated attempt page, and followed activity.
  const first = await waitFor(() => findBootstrap(readOutput(), origin), 'first local bootstrap handoff');
  sensitiveValues.push(first.token);
  const stateBefore = await fs.readFile(statePath);
  assert.equal(await fs.readFile(statePath, 'utf8'), fixture.retained['workflow-state.json']);
  const old = track(await makeTarget());
  await cdp.call('Page.navigate', { url: first.url }, old.sessionId);
  await ready(old, `document.body.innerText.includes('Local session connected.')`, 'first-process session');
  const instanceBefore = await serverInstance(old);
  assert.ok(instanceBefore, 'Bootstrap did not report serverInstanceId');
  await openRun(old, 'attempt before restart');
  await readPin(old, 'pin policy before restart');
  await follow(old, 'activity before restart');
  const rowsBefore = await evaluate(old, rows);
  await continueFollowing(old, 'activity following before restart');
  const automaticMutationsBaseline = old.requests.filter(r => !['GET', 'HEAD'].includes(r.method)).length;
  assert.equal(old.requests.filter(r => r.method === 'PUT' && r.url === pinUrl).length, 0,
    'The old tab must not write the pin before the deliberate pin action');
  // Cursor epochs are process-local; compare the durable sequence boundary instead.
  const snapshotBefore = await evaluate(old, `fetch('${basePath}/api/v1/jobs/${fixture.jobId}/runs/${RUN}/snapshot').then(r => r.json()).then(b => b.data.throughSequence)`);
  evidence.phases.push('first-process');

  // Graceful SIGTERM-only restart: same installation, data directory and port.
  const mutationsBeforeRestart = old.requests.filter(r => !['GET', 'HEAD'].includes(r.method)).length;
  assert.equal(mutationsBeforeRestart, automaticMutationsBaseline,
    'Unexpected mutation occurred before the restart');
  const restarted = await restartApplication();
  assert.equal(restarted.origin, origin, 'Restart did not preserve the origin');
  evidence.shutdown = restarted.exit;
  evidence.sameOrigin = origin;

  // Give reconnects time to invalidate the old session automatically. If the page remains
  // private, require a deliberate read and an actual 401 before treating it as cleared.
  const signInNotice = 'To access private work, open the sign-in link printed by your local application.';
  let privateClearPath = null;
  const clearDeadline = Date.now() + 20000;
  while (Date.now() < clearDeadline) {
    const state = await evaluate(old, `(() => {
      const retained = document.querySelector('section[aria-label="Progress retention"]') !== null;
      const notice = document.body.innerText.includes(${JSON.stringify(signInNotice)});
      return !retained && notice ? 'cleared' : retained ? 'private' : 'unknown';
    })()`);
    if (state === 'cleared') { privateClearPath = 'automatic-server-rejection'; break; }
    assert.equal(state, 'private', 'Old attempt page became indeterminate before session invalidation');
    await delay(75);
  }
  if (privateClearPath === null) {
    const readStart = old.requests.length;
    await readPin(old, 'explicit progress-pin read after restart', signInNotice);
    const rejectedReads = old.requests.slice(readStart).filter(r => r.method === 'GET' && r.url === pinUrl);
    assert.equal(rejectedReads.length, 1, 'Session invalidation must follow one deliberate pin GET');
    assert.equal(matchingResponse(rejectedReads[0], old.responses)?.status, 401,
      'The deliberate post-restart pin GET must receive an actual HTTP 401');
    privateClearPath = 'explicit-progress-pin-read-401';
  }
  assert.equal(await evaluate(old, `document.querySelector('ol[aria-label="Activity observations"]') === null && document.querySelector('section[aria-label="Progress retention"]') === null`), true,
    'Private attempt state survived restart rejection');
  assert.equal(summarizeRequests(old.requests).mutations.length, mutationsBeforeRestart, 'A mutation was replayed during restart');
  assert.equal(await evaluate(old, 'localStorage.length + sessionStorage.length'), 0);
  evidence.privateStateCleared = true;
  evidence.privateClearPath = privateClearPath;
  evidence.automaticMutationReplays = 0;

  // The consumed first link stays denied; only a fresh explicit bootstrap authenticates.
  const second = await waitFor(() => findBootstrap(readOutput(), origin), 'fresh local bootstrap handoff');
  assert.notEqual(second.token, first.token, 'Restart reused the previous bootstrap token');
  sensitiveValues.push(second.token);
  await cdp.call('Page.navigate', { url: first.url }, old.sessionId);
  await ready(old, `document.body.innerText.includes('This sign-in link is no longer available.')`, 'consumed first-process link denial');
  assert.equal(await evaluate(old, 'location.hash'), '');
  evidence.consumedOldLinkDenied = true;
  await cdp.call('Page.navigate', { url: second.url }, old.sessionId);
  await ready(old, `document.body.innerText.includes('Local session connected.')`, 'fresh explicit session');
  const instanceAfter = await serverInstance(old);
  assert.ok(instanceAfter && instanceAfter !== instanceBefore, 'serverInstanceId did not change across the restart');
  evidence.serverInstanceChanged = true;

  // Reconciliation: durable bytes, pin policy and activity match the pre-restart view.
  assert.deepEqual(await fs.readFile(statePath), stateBefore, 'Restart changed workflow-state bytes');
  evidence.workflowStateSha256 = sha256(stateBefore);
  await openRun(old, 'attempt after restart');
  await readPin(old, 'pin policy after restart');
  await follow(old, 'activity after restart');
  assert.deepEqual(await evaluate(old, rows), rowsBefore, 'Activity rows differ after restart');
  await continueFollowing(old, 'activity following after restart');
  assert.equal(await evaluate(old, `fetch('${basePath}/api/v1/jobs/${fixture.jobId}/runs/${RUN}/snapshot').then(r => r.json()).then(b => b.data.throughSequence)`), snapshotBefore);
  assert.deepEqual(await fs.readFile(statePath), stateBefore, 'Reconciliation reads changed workflow-state bytes');
  await captureSafe(old, 'restart-reconciled.png');
  evidence.activityContinuity = { rows: rowsBefore.length, throughSequence: snapshotBefore };
  evidence.phases.push('restarted-process');

  // Two tabs in one window: only the foreground tab may read; closing it leaves the survivor streaming.
  const peer = track(await makeTarget());
  await openRun(peer, 'second tab attempt');
  await follow(peer, 'second tab activity');
  await continueFollowing(peer, 'second tab following activity');
  await cdp.call('Page.bringToFront', {}, peer.sessionId);
  await ready(old, `document.visibilityState === 'hidden' && document.body.innerText.includes('Background tab: activity reads are suspended.')`,
    'hidden tab suspension (fail closed if the tab is not hidden)');
  const hiddenReads = progressReads(old);
  const peerReadsBefore = progressReads(peer);
  await ready(old, `true`, 'hidden tab stream cancellation observation');
  await delay(100);
  assert.equal(hasOpenEventStream(old.eventStreams), false, 'A hidden tab left its activity event stream open');
  await delay(3000);
  assert.equal(progressReads(old), hiddenReads, 'A hidden tab made progress requests');
  assert.equal(hasOpenEventStream(old.eventStreams), false, 'A hidden tab reopened its activity event stream');
  assert.equal(await evaluate(peer, 'document.visibilityState'), 'visible');
  evidence.backgroundTab = { hiddenRequests: 0, hiddenNoticeShown: true, foregroundReadsDuringObservation: progressReads(peer) - peerReadsBefore };

  await cdp.call('Target.closeTarget', { targetId: peer.targetId });
  await cdp.call('Page.bringToFront', {}, old.sessionId);
  await ready(old, `document.visibilityState === 'visible' && document.body.innerText.includes('Following retained activity.')`, 'survivor resumes');
  const streamsBefore = old.streams;
  const deadline = Date.now() + 10000;
  while (old.streams <= streamsBefore && Date.now() < deadline) await delay(50);
  assert.ok(old.streams > streamsBefore, 'Survivor did not reopen its activity stream');
  const original = fixture.progress;
  const appended = JSON.parse(original);
  appended.events.push({ ...appended.events[0], sequence: 205, text: 'Synthetic private streamed content' });
  appended.nextSequence = 206;
  try {
    await publishAtomically(fixture.progressPath, JSON.stringify(appended));
    await ready(old, `(${rows}).includes('Sequence 205')`, 'survivor streamed appended observation');
    assert.equal(await evaluate(old, `document.body.innerText.includes('Synthetic private streamed content')`), false);
    await evaluate(old, `${button('Pause activity')}.click()`);
  } finally {
    await publishAtomically(fixture.progressPath, original);
  }
  assert.equal(await fs.readFile(fixture.progressPath, 'utf8'), original);
  evidence.survivorStreaming = true;

  // Stale control: the second window keeps the pre-mutation policy while the first pins.
  await openRun(old, 'first window attempt');
  const other = track(await makeTarget({ newWindow: true }));
  await openRun(other, 'second window attempt');
  await readPin(old, 'first window policy');
  await readPin(other, 'second window policy');
  for (const tab of [old, other]) assert.equal(await evaluate(tab, 'document.visibilityState'), 'visible',
    'Two visible windows are required for the stale-control scenario (fail closed)');
  const putsBefore = old.requests.filter(r => r.method === 'PUT').length;
  const firstPinRequestIndex = old.requests.length;
  await evaluate(old, `${button('Pin progress history')}.click()`);
  await ready(old, `document.body.innerText.includes('Progress history is pinned.')`, 'first window pin');
  const firstPinRequest = old.requests.slice(firstPinRequestIndex).find(r => r.method === 'PUT' && r.url === pinUrl);
  assert.ok(firstPinRequest, 'First window did not issue the expected pin PUT');
  assert.equal(matchingResponse(firstPinRequest, old.responses)?.status, 200,
    'First window pin PUT did not receive an actual HTTP 200 response');
  const staleBefore = other.requests.length;
  await evaluate(other, `${button('Pin progress history')}.click()`);
  await ready(other, `document.body.innerText.includes('The attempt changed')`, 'stale second window rejection');
  await delay(3000);
  const staleRequests = other.requests.slice(staleBefore);
  assertOnlyPinWrites(staleRequests, pinUrl, 1);
  assert.equal(staleRequests.length, 1, 'Stale rejection triggered an automatic retry or follow-up request');
  const stalePut = staleRequests.find(r => r.method === 'PUT' && r.url === pinUrl);
  assert.equal(matchingResponse(stalePut, other.responses)?.status, 412, 'Expected the stale PUT to receive an actual HTTP 412 response');
  assertOnlyPinWrites(old.requests, pinUrl, putsBefore + 1, `${origin}${basePath}/api/v1/session`, 3);
  assert.deepEqual([...old.exceptions, ...other.exceptions], []);
  await captureSafe(other, 'restart-stale-control.png');
  evidence.staleControl = { first: { puts: 1, status: 200 }, second: { puts: 1, status: 412, retries: 0, crossAttemptWrites: 0 }, mutation: 'progress-pin',
    liveWorkerCancellationOrApprovalCovered: false };
  await cdp.call('Target.closeTarget', { targetId: other.targetId });
  evidence.requests = { restarted: summarizeRequests(old.requests), staleWindow: summarizeRequests(other.requests) };
  return { evidence, requests: { restarted: old.requests, staleWindow: other.requests } };
}
