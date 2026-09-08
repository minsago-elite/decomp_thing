import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';

/** Opt-in, real-time production idle deadline; no clock or response interception. */
export async function qualifyIdleExpiry({ fixture, bootstrapUrl, browserOrigin, makeTarget, cdp, evaluate, ready, checkLive, evidenceDirectory }) {
  const tab = await makeTarget();
  const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  await cdp.call('Page.navigate', { url: bootstrapUrl }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Local session connected.')`, 'idle-expiry sign-in');
  assert.equal(await evaluate(tab, 'location.hash'), '');
  const path = `/nested/jobs/${fixture.jobId}/runs/run_fixture_3`;
  await cdp.call('Page.navigate', { url: browserOrigin + path }, tab.sessionId);
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  await ready(tab, `document.querySelector('section[aria-label="Progress retention"]') !== null`, 'idle-expiry retained attempt');
  const readPin = () => evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Read progress pin').click()`);
  await readPin();
  await ready(tab, `document.body.innerText.includes('Progress history is not pinned.')`, 'idle-expiry initial private read');
  const before = new Map();
  for (const name of ['workflow-state.json', 'job.json', 'input.elf']) before.set(name, await fs.readFile(join(fixture.directory, name)));
  const progress = await fs.readFile(fixture.progressPath);
  // Allow already requested assets to settle before measuring a fully quiet interval.
  await pause(1000);
  const requestsBefore = tab.requests.length;
  const started = performance.now();
  const idleWaitMs = 30 * 60 * 1000 + 2000;
  while (performance.now() - started < idleWaitMs) {
    await pause(Math.min(30_000, idleWaitMs - (performance.now() - started)));
    checkLive();
    assert.equal(tab.requests.length, requestsBefore, 'Idle qualification must not refresh the server session');
    assert.deepEqual(tab.exceptions, []);
    const elapsedMs = Math.floor(performance.now() - started);
    await fs.writeFile(join(evidenceDirectory, 'idle-wait.json'), JSON.stringify({ status: 'waiting', elapsedMs, requiredMs: idleWaitMs, automaticRequests: 0 }) + '\n');
    console.log(`Idle expiry: ${elapsedMs}/${idleWaitMs} ms; server and browser live; no requests.`);
  }
  const realTimeIdleWaitMs = Math.floor(performance.now() - started);
  assert.equal(await evaluate(tab, `document.querySelector('section[aria-label="Progress retention"]') !== null`), true,
    'The browser must retain its view until the server reports idle expiry');
  await readPin();
  await ready(tab, `document.body.innerText.includes('Your local session expired.') && document.body.innerText.includes('Connect a local session to view this attempt.')`, 'actual server idle expiry clears shared state');
  assert.equal(await evaluate(tab, `document.querySelector('section[aria-label="Progress retention"]') === null`), true);
  assert.equal(await evaluate(tab, `document.body.innerText.includes('The server instance changed since this tab last connected.')`), false);
  await pause(3000);
  const requests = tab.requests.slice(requestsBefore);
  assert.equal(requests.length, 1, 'Idle expiry must stop automatic probes and retries');
  assert.equal(requests[0].method, 'GET');
  assert.equal(requests[0].url, browserOrigin + `/nested/api/v1/jobs/${fixture.jobId}/runs/run_fixture_3/progress-pin`);
  assert.ok(tab.responses.some(response => response.url === requests[0].url && response.status === 401));
  const mutations = tab.requests.filter(request => !['GET', 'HEAD'].includes(request.method));
  assert.equal(mutations.length, 1);
  assert.equal(mutations[0].method, 'POST');
  assert.equal(mutations[0].url, browserOrigin + '/nested/api/v1/session');
  assert.equal(await evaluate(tab, 'localStorage.length + sessionStorage.length'), 0);
  assert.deepEqual(tab.exceptions, []);
  for (const [name, bytes] of before) assert.deepEqual(await fs.readFile(join(fixture.directory, name)), bytes);
  assert.deepEqual(await fs.readFile(fixture.progressPath), progress);
  const result = { realTimeIdleWaitMs, minimumIdleWaitMs: idleWaitMs,
    automaticRequestsDuringIdle: 0, privateViewRetainedUntilRead: true, actualServer401: true,
    distinctExpiredNotice: true, privateAttemptCleared: true, restartNotInferred: true,
    explicitExpiryReadRequests: 1, automaticFollowupRequests: 0, followupObservationMs: 3000,
    workflowMutations: 0, initialSessionExchanges: 1, storageEntries: 0,
    workflowBytesUnchanged: true, progressBytesUnchanged: true };
  await fs.writeFile(join(evidenceDirectory, 'idle-wait.json'), JSON.stringify({ status: 'qualified', ...result }) + '\n');
  return { result, requests: tab.requests };
}
