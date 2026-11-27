import assert from 'node:assert/strict';
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
const deletedAlert = `[...document.querySelectorAll('[role="alert"]')].find(alert => alert.textContent.includes('This job was deleted.'))`;
const keys = { Tab: { key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, Enter: { key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' } };
async function press(cdp, tab, name) {
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', ...keys[name] }, tab.sessionId);
  const { text, ...up } = keys[name];
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', ...up }, tab.sessionId);
}
const deletedNotice = `document.querySelector('[role="alert"]')?.textContent.includes('This job was deleted. Its files were removed and cannot be recovered')`;

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

  const listingBusy = [];
  const tab = await makeTarget();
  // Keep DELETE response headers so the test follows the server's own operation Location.
  const responseHeaders = new Map();
  cdp.on('Network.responseReceived', event => responseHeaders.set(event.requestId, event.response.headers), tab.sessionId);
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
  assert.deepEqual((await fs.readdir(directory)).sort(), ['input.elf', 'job.json', 'organization.json']);

  // A second tab holds the same deep link while the first deletes it.
  const peer = await makeTarget();
  await cdp.call('Page.navigate', { url: jobUrl }, peer.sessionId);
  await ready(peer, `document.querySelector('h2')?.textContent === 'Lifecycle label'`, 'peer tab on lifecycle job');

  // 3. Deliberate deletion: reviewed preview, typed confirmation gate, one DELETE.
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
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
  const deletesBefore = tab.requests.filter(request => request.method === 'DELETE').length;
  await evaluate(tab, click('Delete permanently'));
  await ready(tab, deletedNotice, 'deleted notice in deleting tab');
  const deleteRequests = tab.requests.filter(request => request.method === 'DELETE').slice(deletesBefore);
  assert.equal(deleteRequests.length, 1);
  assert.equal(new URL(deleteRequests[0].url).pathname, '/nested/api/v1/jobs/' + job.id);
  await waitFor(async () => responseHeaders.has(deleteRequests[0].requestId), 'DELETE response headers', 10_000);
  const headers = Object.fromEntries(Object.entries(responseHeaders.get(deleteRequests[0].requestId)).map(([name, value]) => [name.toLowerCase(), value]));
  const location = headers.location;
  assert.match(location ?? '', new RegExp(`^/nested/api/v1/jobs/${job.id}/operations/jobdel_[0-9a-f]{32}$`), 'DELETE did not return an operation Location');
  const operationId = location.split('/').pop();
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
  assert.match(operation.message, /^The job and its stored files were permanently deleted \(\d+ bytes in \d+ entries\)\. This cannot be undone; only this deletion record is retained\.$/);
  // The detached purge staging for this operation is gone, as is the job directory itself.
  assert.ok(!(await fs.readdir(fixture.root)).includes(job.id), 'job directory remained after completed deletion');
  const staged = await fs.readdir(join(fixture.root, '.job-deletions'));
  assert.ok(!staged.includes(operationId + '.removing'), 'detached job data was not purged');
  assert.ok(staged.includes(operationId + '.json'), 'deletion record missing');
  assert.ok(!staged.some(name => name.endsWith('.removing')), 'detached deletion staging remains');

  // 4. Recovery and consistency: truthful copy, peer tab, deep-link reload, API 410, focusable return.
  // The permanent message itself says "cannot be undone"; what must be absent is any control offering to undo.
  await ready(tab, `${deletedAlert}?.textContent.includes(${JSON.stringify(operation.message)})`, 'permanent deletion message in alert');
  assert.deepEqual(await evaluate(tab, `[...document.querySelectorAll('button, a[href], [role="button"], [role="link"], input, select, textarea')]
    .filter(control => /undo|restore|trash|recover/i.test((control.textContent || '') + ' ' + (control.value || '') + ' ' + (control.getAttribute('aria-label') || '') + ' ' + (control.getAttribute('title') || '')))
    .map(control => control.outerHTML)`), [], 'Deleted job offers an undo, restore or trash control');
  // Headless background targets may report hidden; bring the peer forward so its own re-read runs.
  await cdp.call('Page.bringToFront', {}, peer.sessionId);
  await ready(peer, deletedNotice, 'peer tab reconciles deletion');
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, deletedNotice, 'deleted deep link after reload');
  assert.equal(await evaluate(tab, `fetch('/nested/api/v1/jobs/${job.id}').then(response => response.status)`), 410);
  assert.equal(await listed(tab, evaluate, job.id, 'all', listingBusy), false, 'Deleted job still listed');
  // Reach the alert's own recovery link by sequential Tab navigation from the top of the document.
  const recoveryLink = `${deletedAlert}?.querySelector('a[href="/nested/"]')`;
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
    deletionOperation: { location, state: operation.state }, detachedDataPurged: true, previewInputBytes: 64,
    peerTabReconciled: true, deepLinkReloadShowsDeleted: true, apiGone: 410, noUndoPromised: true,
    keyboardReturnFocus: landingFocus, mutationRequests: methods.length, listingBusyRetried: listingBusy, executionStarted: false };
}
