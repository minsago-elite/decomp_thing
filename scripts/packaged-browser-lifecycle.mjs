import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { record, publish } from './packaged-browser-live.mjs';

// D3.6 (#173) packaged lifecycle: label, archive and deliberate deletion of one
// authored inert job against the real packaged JVM. No workflow is started.
const setInput = (selector, value) => `(() => {
  const input = document.querySelector(${JSON.stringify(selector)}); input.focus();
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
  input.dispatchEvent(new Event('input', { bubbles: true }));
})()`;
const click = (text) => `[...document.querySelectorAll('button')].find(button => button.textContent === ${JSON.stringify(text)}).click()`;
const status = (section) => `document.querySelector('section[aria-labelledby="${section}"] [role="status"]')?.textContent`;
const deletion = `document.querySelector('section[aria-labelledby="job-delete-title"]')`;
const deletedHeadline = 'This job was deleted from the library and cannot be recovered. Its deletion record is kept for at least 24 hours.';
const cleanupRunning = 'File cleanup is still running and resumes after a restart if interrupted. Its files are not yet confirmed removed.';
const cleanupFinished = 'File cleanup finished: its files were removed.';
const cleanupUnknown = 'This page has not observed whether file cleanup finished.';
const headlineFor = reference => reference === null ? deletedHeadline : `${deletedHeadline} Reference ID: ${reference}.`;
const deletedAlert = (reference = null) => `[...document.querySelectorAll('section[aria-labelledby="job-title"] [role="alert"]')]
  .find(alert => alert.querySelector('p')?.textContent === ${JSON.stringify(headlineFor(reference))})`;
const deletedControlsGone = `(() => {
  const route = document.querySelector('section[aria-labelledby="job-title"]');
  return !!route && [...route.querySelectorAll('button, input, select, textarea, form, a[href], [role="button"], [role="link"]')]
    .every(control => control.tagName === 'A' && control.getAttribute('href') === '/nested/');
})()`;
function deletionParagraphs(acknowledged, reference) {
  const headline = headlineFor(reference);
  if (!acknowledged) return [headline, cleanupUnknown];
  assert.ok(['running', 'completed'].includes(acknowledged.state), 'Unexpected DELETE acknowledgement state');
  if (acknowledged.state === 'running') return [headline, 'The deletion is running.', cleanupRunning];
  if (acknowledged.recoveryRequired) return [
    headline,
    'The deletion requires storage recovery. Restart the server, then refresh the job.',
    'File cleanup did not finish (completed). Some files may remain until recovery completes.',
  ];
  return [headline, 'The job and its stored files were permanently deleted.', cleanupFinished];
}

export const deletionVerdict = (acknowledged = null, reference = null) => {
  const paragraphs = deletionParagraphs(acknowledged, reference);
  return `(() => {
    const alert = ${deletedAlert(reference)};
    if (!alert) return false;
    const expected = ${JSON.stringify(paragraphs)};
    const paragraphs = [...alert.children].filter(child => child.tagName === 'P').map(child => child.textContent);
    return paragraphs.length === expected.length && paragraphs.every((text, index) => text === expected[index])
      && alert.querySelector('a[href="/nested/"]')?.textContent === 'Return to jobs' && ${deletedControlsGone};
  })()`;
};
const keys = { Tab: { key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, Enter: { key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' } };
async function press(cdp, tab, name) {
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', ...keys[name] }, tab.sessionId);
  const { text, ...up } = keys[name];
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', ...up }, tab.sessionId);
}
export const deletedNotice = `!!(${deletedAlert()})`;

// Capture only this tab’s next 410 GET of the selected job. Peer and reload use separate requests.
function observeJobTombstone(cdp, tab, url) {
  let response;
  cdp.on('Network.responseReceived', event => {
    if (response || event.response.status !== 410 || event.response.url !== url) return;
    if (tab.requests.some(request => request.requestId === event.requestId && request.method === 'GET')) {
      response = event.response;
    }
  }, tab.sessionId);
  return () => response;
}

async function tombstoneReference(observation, waitFor) {
  const response = await waitFor(observation, 'job GET returned 410');
  const reference = Object.entries(response.headers).find(([name]) => name.toLowerCase() === 'x-request-id')?.[1];
  assert.match(reference ?? '', /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    'The job GET must supply a canonical X-Request-ID');
  return reference;
}

// CDP reports the request, response and terminal event separately. Network is only a bounded
// event and identity observer: it never reads a body (the Fetch stage owns the single read).
// Early events are held until the first DELETE is identified; later ones are ignored.
export const DELETION_CAPTURE_WINDOW = 64;
export const DELETION_TRACE_LIMIT = 16;
export function createDeletionCapture() {
  const recent = new Map();
  let deletionId;

  function observe(id, eventName, update) {
    if (deletionId !== undefined && id !== deletionId) return;
    let entry = recent.get(id);
    if (!entry) {
      if (recent.size >= DELETION_CAPTURE_WINDOW) recent.delete(recent.keys().next().value);
      entry = { trace: [] };
      recent.set(id, entry);
    }
    if (entry.trace.length < DELETION_TRACE_LIMIT) entry.trace.push(eventName);
    update(entry);
  }

  return {
    request(id, method) {
      if (method === 'DELETE' && deletionId === undefined) {
        deletionId = id;
        for (const key of recent.keys()) {
          if (key !== id) recent.delete(key);
        }
      }
      observe(id, 'requestWillBeSent:' + method, entry => { entry.method ??= method; });
    },
    response(id, response) {
      observe(id, 'responseReceived:' + response.status, entry => { entry.response ??= response; });
    },
    finished(id) {
      observe(id, 'loadingFinished', entry => { entry.terminal ??= 'finished'; });
    },
    failed(id, errorText, canceled) {
      const reason = String(errorText).slice(0, 160);
      observe(id, 'loadingFailed:' + reason + (canceled ? ':canceled' : ''), entry => {
        entry.failure ??= { errorText: reason, canceled: Boolean(canceled) };
        entry.terminal ??= canceled ? 'canceled' : 'failed';
      });
    },
    deletionId: () => deletionId,
    size: () => recent.size,
    responseOf: id => recent.get(id)?.response,
    terminalOf: id => recent.get(id)?.terminal,
    describe(id) {
      const entry = recent.get(id);
      if (!entry) return `no Network event observed for DELETE requestId ${id}`;
      const missing = [];
      if (!entry.method) missing.push('requestWillBeSent');
      if (!entry.response) missing.push('responseReceived');
      if (!entry.terminal) missing.push('loadingFinished or loadingFailed');
      return `DELETE requestId ${id} events [${entry.trace.join(', ')}]`
        + (missing.length ? `; missing ${missing.join(', ')}` : '')
        + (entry.failure ? `; loadingFailed ${JSON.stringify(entry.failure)}` : '');
    },
  };
}

// #1891/#512: Chrome may cancel the page's completed DELETE loader after the app has consumed the
// whole 202 body (loadingFailed net::ERR_ABORTED canceled, no loadingFinished), after which
// Network.getResponseBody has nothing to return. The Fetch domain, scoped to the job URL and
// paused at the response stage, reads the JVM's own body bytes exactly once before the page
// receives them, then continues the response unmodified. Every paused request is continued
// exactly once; the continued and error records are bounded.
export const INTERCEPTION_RECORD_LIMIT = 64;
export function createDeletionInterception(call) {
  let first;
  let bodyReads = 0;
  let paused = 0;
  const continued = [];
  const errors = [];
  const keep = (list, value) => { if (list.length < INTERCEPTION_RECORD_LIMIT) list.push(value); };
  return {
    async paused({ requestId, networkId, request, responseStatusCode, responseHeaders, responseErrorReason }) {
      paused++;
      const respond = responseErrorReason === undefined && responseStatusCode !== undefined;
      let read;
      if (request?.method === 'DELETE' && first === undefined && respond) {
        first = { requestId, networkId, url: request.url, status: responseStatusCode, headerList: (responseHeaders ?? []).slice(0, 64).map(({ name, value }) => ({ name, value })) };
        bodyReads++;
        first.body = Promise.resolve().then(() => call('Fetch.getResponseBody', { requestId })).catch(error => ({ error: String(error).slice(0, 200) }));
        read = first.body;
      }
      try { if (read) await read; } finally {
        try {
          await call(respond ? 'Fetch.continueResponse' : 'Fetch.continueRequest', { requestId });
          keep(continued, requestId);
        } catch (error) { keep(errors, String(error).slice(0, 200)); }
      }
    },
    captured: () => first !== undefined,
    first: () => first,
    bodyReads: () => bodyReads,
    pausedCount: () => paused,
    continued: () => [...continued],
    errors: () => [...errors],
  };
}

/** Enable response interception for `run` and always release it, whether `run` succeeds or throws. */
export async function withResponseInterception(call, patterns, run) {
  await call('Fetch.enable', { patterns });
  let failure;
  try { return await run(); } catch (error) { failure = error; throw error; } finally {
    try { await call('Fetch.disable', {}); } catch (error) {
      if (!failure) throw new Error('Fetch.disable failed: ' + String(error).slice(0, 200), { cause: error });
    }
  }
}

/** The Fetch-stage view of one response in the shape readDeletionAcknowledgement verifies. */
export function interceptedResponse(intercepted) {
  const headers = {};
  for (const { name, value } of intercepted.headerList) {
    const key = name.toLowerCase();
    assert.ok(!(key in headers), 'Intercepted DELETE repeats header ' + key);
    headers[key] = value;
  }
  return { status: intercepted.status, url: intercepted.url, headers };
}

export function readDeletionAcknowledgement(response, payload, jobId, jobApiUrl) {
  assert.equal(response.status, 202, 'DELETE did not acknowledge the operation');
  assert.equal(response.url, jobApiUrl);
  const headers = Object.fromEntries(Object.entries(response.headers).map(([key, value]) => [key.toLowerCase(), value]));
  const body = Buffer.from(payload.body, payload.base64Encoded ? 'base64' : 'utf8');
  const acknowledged = JSON.parse(body.toString('utf8')).data;
  assert.equal(acknowledged.jobId, jobId);
  assert.equal(acknowledged.action, 'job.delete');
  assert.match(acknowledged.operationId, /^jobdel_[0-9a-f]{32}$/);
  assert.equal(headers.location, new URL(jobApiUrl).pathname + '/operations/' + acknowledged.operationId);
  assert.ok(['running', 'completed'].includes(acknowledged.state), 'Unexpected DELETE acknowledgement state');
  return { acknowledged, location: headers.location, bodySha256: createHash('sha256').update(body).digest('hex') };
}

/**
 * Cross-check the single Fetch-stage read against the independent Network observation: the paused
 * DELETE is the tab's own DELETE, the response carries a nonempty X-Request-ID that the error-free
 * body envelope repeats, Content-Length equals the actual decoded body length, and Network saw the
 * same status, URL and identity headers. Only then is the acknowledgement read.
 */
export async function verifyInterceptedDeletion({ intercepted, observed, requestId, jobId, jobApiUrl, describe = () => '' }) {
  assert.ok(intercepted, 'No DELETE was paused at the Fetch response stage; ' + describe());
  assert.equal(intercepted.networkId, requestId, 'Intercepted DELETE is not the DELETE the tab sent');
  const payload = await intercepted.body;
  {
    assert.ok(payload && !payload.error && typeof payload.body === 'string', 'Original DELETE body unavailable: ' + payload?.error + '; ' + describe());
    const fetchResponse = interceptedResponse(intercepted);
    assert.ok(observed, 'Network never observed the DELETE response; ' + describe());
    assert.equal(observed.status, fetchResponse.status, 'Network and Fetch disagree on status');
    assert.equal(observed.url, fetchResponse.url, 'Network and Fetch disagree on URL');
    const observedHeaders = Object.fromEntries(Object.entries(observed.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value]));
    for (const name of ['location', 'x-request-id', 'content-type', 'content-length']) assert.equal(observedHeaders[name], fetchResponse.headers[name], 'Network and Fetch disagree on ' + name);
    const responseRequestId = fetchResponse.headers['x-request-id'];
    assert.ok(typeof responseRequestId === 'string' && responseRequestId.trim() !== '', 'DELETE response has no nonempty X-Request-ID');
    const bytes = Buffer.from(payload.body, payload.base64Encoded ? 'base64' : 'utf8');
    assert.ok(bytes.length > 0, 'DELETE body is empty');
    assert.match(String(fetchResponse.headers['content-length']), /^[0-9]+$/, 'DELETE response has no numeric Content-Length');
    assert.equal(Number(fetchResponse.headers['content-length']), bytes.length, 'DELETE body length differs from Content-Length');
    const envelope = JSON.parse(bytes.toString('utf8'));
    assert.equal(envelope.requestId, responseRequestId, 'DELETE body is not bound to its own X-Request-ID');
    const acknowledgement = readDeletionAcknowledgement(fetchResponse, payload, jobId, jobApiUrl);
    return { ...acknowledgement, fetchResponse, responseRequestId, bodyBytes: bytes.length };
  }
}

export function assertDeletionAlert(acknowledged, rendered) {
  assert.ok(['running', 'completed'].includes(acknowledged.state));
  const lines = [...deletionParagraphs(acknowledged, null), 'Return to jobs'];
  assert.deepEqual(rendered.split(/\n+/), lines, 'Deleting tab must show the exact state acknowledged by DELETE');
}

// A first-page collection admits one snapshot at a time; a competing read gets
// 503 LISTING_BUSY and should retry shortly (WebJobPages, docs/web-job-pagination.md).
// Only that bound refusal is retried, a few times; every other reply fails at once.
export const LISTING_BUSY_RETRY_DELAYS_MS = Object.freeze([250, 500, 1000, 2000, 2000]);
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const excerpt = body => typeof body === 'string' ? JSON.stringify(body.slice(0, 300)) : String(body);

function listingFailure(summary, reply, busy) {
  const prior = busy.length ? '; LISTING_BUSY request ids: ' + busy.map(entry => entry.requestId).join(', ') : '';
  const error = new Error(`job listing ${summary} (request id ${reply?.requestId ?? 'none'}, body ${excerpt(reply?.body)})${prior}`);
  error.busy = busy;
  return error;
}

/** The refusal is LISTING_BUSY only when the error envelope is bound to its own X-Request-ID. */
function busyRefusal(reply) {
  if (reply?.status !== 503 || typeof reply.requestId !== 'string' || reply.requestId === '') return null;
  let body;
  try { body = JSON.parse(reply.body); } catch { return null; }
  if (body?.apiVersion !== 1 || body.kind !== 'error' || body.requestId !== reply.requestId || body.error?.code !== 'LISTING_BUSY') return null;
  return { requestId: reply.requestId, message: String(body.error.message ?? '') };
}

function membership(reply, jobId, busy) {
  let data;
  try { data = JSON.parse(reply.body).data; } catch { throw listingFailure('200 body is not JSON', reply, busy); }
  const items = data?.items;
  if (!Array.isArray(items) || !items.every(item => typeof item?.jobId === 'string')) throw listingFailure('200 body has no identified items', reply, busy);
  if (data.page?.nextCursor !== null) throw listingFailure('200 body is not one complete page', reply, busy);
  return items.some(item => item.jobId === jobId);
}

export async function readListingMembership(read, jobId, { delays = LISTING_BUSY_RETRY_DELAYS_MS, sleep = pause } = {}) {
  const busy = [];
  for (let attempt = 0; ; attempt++) {
    const reply = await read();
    if (reply?.status === 200) return { listed: membership(reply, jobId, busy), busy };
    const refusal = busyRefusal(reply);
    if (!refusal) throw listingFailure(`${reply?.status} is not a bound LISTING_BUSY refusal`, reply, busy);
    busy.push({ attempt: attempt + 1, ...refusal });
    if (attempt >= delays.length) {
      throw listingFailure(`LISTING_BUSY persisted for ${busy.length} reads over ${delays.reduce((total, delay) => total + delay, 0)} ms of backoff`, reply, busy);
    }
    await sleep(delays[attempt]);
  }
}

async function listed(tab, evaluate, id, archived, busy) {
  const path = '/nested/api/v1/jobs?limit=100' + (archived ? '&archived=' + archived : '');
  const result = await readListingMembership(() => evaluate(tab, `(async () => {
    const response = await fetch(${JSON.stringify(path)});
    return { status: response.status, requestId: response.headers.get('X-Request-ID'), body: await response.text() };
  })()`), id);
  busy.push(...result.busy.map(entry => ({ archived: archived || 'exclude', ...entry })));
  return result.listed;
}

export async function qualifyLifecycle({ fixture, makeTarget, cdp, evaluate, ready, waitFor, browserOrigin }) {
  const job = { ...record(fixture.root, 4), filename: 'lifecycle-fixture.elf' };
  await publish(fixture.root, job, fixture.input);
  const directory = join(fixture.root, job.id);
  const evidence = async () => ({ input: await fs.readFile(join(directory, 'input.elf')), record: await fs.readFile(join(directory, 'job.json'), 'utf8') });
  const original = await evidence();
  assert.equal(original.input.length, 64, 'Lifecycle fixture input is not 64 bytes');
  const jobUrl = browserOrigin + '/nested/jobs/' + job.id;

  const tab = await makeTarget();
  const jobApiUrl = browserOrigin + '/nested/api/v1/jobs/' + job.id;
  const capture = createDeletionCapture();
  const listingBusy = [];
  cdp.on('Network.requestWillBeSent', ({ requestId, request }) => capture.request(requestId, request.method), tab.sessionId);
  cdp.on('Network.responseReceived', ({ requestId, response }) => capture.response(requestId, response), tab.sessionId);
  cdp.on('Network.loadingFinished', ({ requestId }) => capture.finished(requestId), tab.sessionId);
  cdp.on('Network.loadingFailed', ({ requestId, errorText, canceled }) => capture.failed(requestId, errorText, canceled), tab.sessionId);
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  await cdp.call('Page.navigate', { url: jobUrl }, tab.sessionId);
  await ready(tab, `document.querySelector('h2')?.textContent === 'lifecycle-fixture.elf' && document.querySelector('input[name="label"]:not(:disabled)') !== null`, 'lifecycle job route');
  assert.equal(await evaluate(tab, `document.body.innerText.includes('It does not export, compress or download a source archive, and removes nothing.')`), true);

  // 1. Display label: only organization.json changes; identity and evidence bytes stay exact.
  await evaluate(tab, setInput('input[name="label"]', 'Lifecycle label'));
  await evaluate(tab, click('Save organization'));
  await ready(tab, `${status('job-organize-title')} === 'Saved. The job was read again from the server.' && document.querySelector('h2')?.textContent === 'Lifecycle label'`, 'label saved and re-read');
  assert.equal(await evaluate(tab, `document.body.innerText.includes('File name: lifecycle-fixture.elf') && document.body.innerText.includes('${job.id}')`), true);
  assert.deepEqual(await evidence(), original, 'Label edit changed job evidence');
  assert.deepEqual(JSON.parse(await fs.readFile(join(directory, 'organization.json'), 'utf8')).label, 'Lifecycle label');

  // 2. Archive: hidden from default listing, present under archived=only; still no evidence change.
  await evaluate(tab, `document.querySelector('input[name="archived"]').click()`);
  await evaluate(tab, click('Save organization'));
  await ready(tab, `${status('job-organize-title')} === 'Saved. The job was read again from the server.' && document.querySelector('input[name="archived"]').checked`, 'archive saved and re-read');
  assert.deepEqual(await evidence(), original, 'Archive changed job evidence');
  assert.equal(JSON.parse(await fs.readFile(join(directory, 'organization.json'), 'utf8')).archived, true);
  assert.equal(await listed(tab, evaluate, job.id, '', listingBusy), false, 'Archived job remained in the default listing');
  assert.equal(await listed(tab, evaluate, job.id, 'only', listingBusy), true, 'Archived job missing from archived listing');
  const files = (await fs.readdir(directory)).sort();
  assert.deepEqual(files, ['input.elf', 'job.json', 'organization.json']);
  const sizes = await Promise.all(files.map(async name => (await fs.stat(join(directory, name))).size));
  const purgeBytes = sizes.reduce((total, size) => total + size, 0);

  // A second tab holds the same deep link while the first deletes it.
  const peer = await makeTarget();
  const peerTombstone = observeJobTombstone(cdp, peer, jobApiUrl);
  await cdp.call('Page.navigate', { url: jobUrl }, peer.sessionId);
  const peerHistoryLink = `[...document.querySelectorAll('a')].find(link => link.textContent === 'Browse attempt history')`;
  await ready(peer, `document.querySelector('h2')?.textContent === 'Lifecycle label' && ${peerHistoryLink} !== undefined`, 'peer tab on lifecycle job');
  await evaluate(peer, `${peerHistoryLink}.focus()`);
  assert.equal(await evaluate(peer, `document.activeElement === ${peerHistoryLink}`), true, 'Peer focus was not on its soon-to-depart job control');

  // 3. Deliberate deletion: reviewed preview, typed confirmation gate, one DELETE.
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  // bringToFront flips visibilityState before Preact re-renders the availability-gated control;
  // a click on the still-disabled button is a no-op, so act only once the physical control is enabled.
  const reviewControl = `[...document.querySelectorAll('button')].find(button => button.textContent === 'Review what would be deleted')`;
  await ready(tab, `document.visibilityState === 'visible' && ${reviewControl}?.disabled === false`, 'enabled deletion review control');
  const previewsBefore = tab.requests.filter(request => request.url.includes('/deletion-preview')).length;
  await evaluate(tab, click('Review what would be deleted'));
  await ready(tab, `${deletion}?.innerText.includes('Job to delete') && ${deletion}.innerText.includes('Retained after deletion: a deletion record') && ${deletion}.querySelector('input[name="confirm"]') !== null`, 'deletion preview');
  // The reviewed preview, scoped to the deletion section, names exactly this fixture and its 64-byte input.
  const previewFacts = await evaluate(tab, `(() => {
    const facts = {};
    for (const term of ${deletion}.querySelectorAll('dl.job-facts dt')) facts[term.textContent] = term.nextElementSibling.textContent;
    return facts;
  })()`);
  assert.equal(previewFacts.Identity, job.id, 'Deletion preview names a different job');
  assert.equal(previewFacts['Uploaded input'], '64 bytes', 'Deletion preview does not report the exact 64-byte input');
  assert.equal(previewFacts['Recorded attempts'], '0');
  const deleteDisabled = `[...document.querySelectorAll('button')].find(button => button.textContent === 'Delete permanently').disabled`;
  assert.equal(await evaluate(tab, deleteDisabled), true, 'Delete enabled before confirmation');
  await evaluate(tab, setInput('input[name="confirm"]', 'Lifecycle label'));
  assert.equal(await evaluate(tab, deleteDisabled), true, 'Delete accepted the label instead of the file name');
  await evaluate(tab, setInput('input[name="confirm"]', 'lifecycle-fixture.elf'));
  assert.equal(await evaluate(tab, deleteDisabled), false);
  // Only the exact job resource is paused during confirmation; nothing is fulfilled or rewritten.
  const interception = createDeletionInterception((method, params) => cdp.call(method, params, tab.sessionId));
  cdp.on('Fetch.requestPaused', event => { void interception.paused(event); }, tab.sessionId);
  const fetchCall = (method, params) => cdp.call(method, params, tab.sessionId);
  const requestId = await withResponseInterception(fetchCall, [{ urlPattern: jobApiUrl, requestStage: 'Response' }], async () => {
    // Continue from the confirmation input with real keyboard events: exactly one submit, then focus handoff.
    await press(cdp, tab, 'Tab');
    assert.equal(await evaluate(tab, `document.activeElement === [...document.querySelectorAll('button')].find(button => button.textContent === 'Delete permanently')`), true, 'Tab did not reach the enabled Delete control');
    await press(cdp, tab, 'Enter');
    await ready(tab, `${deletedNotice} && document.activeElement === ${deletedAlert()}?.querySelector('p[tabindex="-1"]')`, 'deleted notice and departing-control focus in deleting tab');
    assert.equal(tab.requests.filter(request => request.url.includes('/deletion-preview')).length - previewsBefore, 1, 'Deletion was not gated by exactly one reviewed preview');
    const deleteRequests = tab.requests.filter(request => request.method === 'DELETE');
    assert.equal(deleteRequests.length, 1);
    const [{ requestId: sent, url }] = deleteRequests;
    assert.equal(url, jobApiUrl);
    try {
      await waitFor(() => interception.captured() && interception.continued().includes(interception.first().requestId), 'original DELETE body at the Fetch response stage', 10_000);
    } catch (error) {
      throw new Error(error.message + '; ' + capture.describe(sent) + '; Fetch errors ' + JSON.stringify(interception.errors()), { cause: error });
    }
    return sent;
  });
  assert.deepEqual(interception.errors(), [], 'Fetch interception failed to continue a paused request');
  assert.equal(interception.bodyReads(), 1, 'DELETE body must be read exactly once, at the Fetch stage');
  const { acknowledged, location, bodySha256, fetchResponse, bodyBytes } = await verifyInterceptedDeletion({
    intercepted: interception.first(), observed: capture.responseOf(requestId), requestId, jobId: job.id, jobApiUrl, describe: () => capture.describe(requestId) });
  const networkTerminal = capture.describe(requestId);
  const { operationId } = acknowledged;
  await ready(tab, deletionVerdict(acknowledged), 'deleting tab displays its own acknowledgement');
  const rendered = await evaluate(tab, `${deletedAlert()}?.innerText`);
  assertDeletionAlert(acknowledged, rendered);
  // Disappearance from the library is not completion: await the server's completed operation.
  let operation = null;
  await waitFor(async () => {
    operation = await evaluate(tab, `fetch(${JSON.stringify(location)}, { headers: { Accept: 'application/json' } }).then(async response => {
      if (response.status !== 200) throw new Error('deletion operation ' + response.status);
      return (await response.json()).data;
    })`);
    return operation.state === 'completed';
  }, 'deletion operation completed', 40_000);
  assert.equal(operation.operationId, operationId);
  assert.equal(operation.jobId, job.id);
  assert.equal(operation.action, 'job.delete');
  assert.equal(operation.recoveryRequired, false);
  assert.equal(operation.message, `The job and its stored files were permanently deleted (${purgeBytes} bytes in ${files.length} entries). `
    + 'This cannot be undone; only this deletion record is retained.');
  // The detached purge staging for this operation is gone, as is the job directory itself.
  assert.ok(!(await fs.readdir(fixture.root)).includes(job.id), 'job directory remained after completed deletion');
  const staged = await fs.readdir(join(fixture.root, '.job-deletions'));
  assert.ok(!staged.includes(operationId + '.removing'), 'detached job data was not purged');
  assert.ok(staged.includes(operationId + '.json'), 'deletion record missing');
  assert.ok(!staged.some(name => name.endsWith('.removing')), 'detached deletion staging remains');

  // 4. Recovery and consistency: truthful copy, peer tab, deep-link reload, API 410, focusable return.
  // The permanent message itself says "cannot be undone"; what must be absent is any control offering to undo.
  await ready(tab, deletionVerdict(acknowledged), 'recorded acknowledgement and its observed cleanup state without stale route controls');
  assert.deepEqual(await evaluate(tab, `[...document.querySelectorAll('button, a[href], [role="button"], [role="link"], input, select, textarea')]
    .filter(control => /undo|restore|trash|recover/i.test((control.textContent || '') + ' ' + (control.value || '') + ' ' + (control.getAttribute('aria-label') || '') + ' ' + (control.getAttribute('title') || '')))
    .map(control => control.outerHTML)`), [], 'Deleted job offers an undo, restore or trash control');
  // Headless background targets may report hidden; bring the peer forward so its own re-read runs.
  await cdp.call('Page.bringToFront', {}, peer.sessionId);
  const peerReference = await tombstoneReference(peerTombstone, waitFor);
  await ready(peer, `${deletionVerdict(null, peerReference)} && document.activeElement === ${deletedAlert(peerReference)}?.querySelector('p[tabindex="-1"]')`, 'peer tombstone has unknown cleanup, no stale controls and departing-control focus');
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  const reloadTombstone = observeJobTombstone(cdp, tab, jobApiUrl);
  await cdp.call('Page.reload', {}, tab.sessionId);
  const reloadReference = await tombstoneReference(reloadTombstone, waitFor);
  await ready(tab, deletionVerdict(null, reloadReference), 'deleted deep link has unknown cleanup and no stale route controls after reload');
  assert.equal(await evaluate(tab, `fetch('/nested/api/v1/jobs/${job.id}').then(response => response.status)`), 410);
  assert.equal(await listed(tab, evaluate, job.id, 'all', listingBusy), false, 'Deleted job still listed');
  // Reach the alert's own recovery link by sequential Tab navigation from the top of the document.
  const recoveryLink = `${deletedAlert(reloadReference)}?.querySelector('a[href="/nested/"]')`;
  assert.equal(await evaluate(tab, `${recoveryLink}?.textContent`), 'Return to jobs', 'Deleted alert has no recovery link');
  await evaluate(tab, `(() => { document.activeElement?.blur(); window.getSelection()?.removeAllRanges(); })()`);
  let reached = false;
  for (let step = 0; step < 40 && !reached; step++) {
    await press(cdp, tab, 'Tab');
    reached = await evaluate(tab, `document.activeElement === ${recoveryLink}`);
  }
  assert.ok(reached, 'Recovery link inside the deletion alert is not reachable by Tab');
  await press(cdp, tab, 'Enter');
  await ready(tab, `location.pathname === '/nested/' && document.querySelector('ul[aria-label="Uploaded jobs"]') !== null && !document.querySelector('a[href="/nested/jobs/${job.id}"]')
    && document.activeElement === document.querySelector('main#main h1') && document.activeElement.textContent === 'Your work, with its evidence'`, 'keyboard return focuses dashboard heading');
  const landingFocus = await evaluate(tab, `document.activeElement.tagName + ':' + document.activeElement.textContent.slice(0, 40)`);

  // Untouched live fixture jobs survive the lifecycle scenario.
  for (const other of fixture.jobs) assert.ok((await fs.readdir(fixture.root)).includes(other.id));
  const methods = tab.requests.map(request => request.method).filter(method => !['GET', 'HEAD'].includes(method));
  assert.deepEqual(methods.sort(), ['DELETE', 'PATCH', 'PATCH']);
  assert.ok(peer.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
  assert.deepEqual(tab.exceptions, []);
  assert.deepEqual(peer.exceptions, []);
  return { realBackend: true, labelEditedEvidenceUnchanged: true, archiveOrganizationOnly: true, archiveDistinctFromExport: true,
    defaultListingHidesArchived: true, typedConfirmationRequiresFileName: true, deleteRequests: 1, jobDirectoryRemoved: true,
    deletionOperation: { location, operationId, jobId: job.id, action: acknowledged.action, status: 202, bodySha256, bodySource: 'Fetch.getResponseBody@Response', bodyReads: interception.bodyReads(), bodyBytes, networkTerminal, networkTerminalKind: capture.terminalOf(requestId) ?? null,
      requestId: fetchResponse.headers['x-request-id'], interceptedRequests: interception.continued().length,
      acknowledgedState: acknowledged.state, rendered, state: operation.state, message: operation.message }, detachedDataPurged: true, previewInputBytes: 64,
    peerTombstoneReference: peerReference, reloadTombstoneReference: reloadReference,
    acknowledgedCleanupPreserved: true, tombstoneCleanupUnknown: true, staleJobControlsCleared: true, departingControlFocus: true,
    peerTabReconciled: true, deepLinkReloadShowsDeleted: true, apiGone: 410, noUndoPromised: true,
    keyboardReturnFocus: landingFocus, mutationRequests: methods.length, listingBusyRetried: listingBusy, executionStarted: false };
}
