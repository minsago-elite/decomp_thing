import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';

/** Same-origin restart of the owned packaged server, using only inert retained fixtures. */
export async function qualifyServerRestart({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin, stopServer, startServer }) {
  const tab = await makeTarget();
  const path = `/nested/jobs/${fixture.jobId}/runs/run_fixture_3`;
  const rows = `Array.from(document.querySelectorAll('ol[aria-label="Activity observations"] li span')).map(node => node.textContent)`;
  const click = text => evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === ${JSON.stringify(text)}).click()`);
  let streams = 0;
  cdp.on('Network.requestWillBeSent', event => {
    if (event.request.url.includes('/events') && Object.entries(event.request.headers).some(([name, value]) => name.toLowerCase() === 'accept' && value === 'text/event-stream')) streams++;
  }, tab.sessionId);
  await cdp.call('Page.navigate', { url: browserOrigin + path }, tab.sessionId);
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  await ready(tab, `document.querySelector('section[aria-label="Progress retention"]') !== null`, 'restart fixture attempt');
  const facts = await evaluate(tab, `document.querySelector('dl.job-facts').innerText`);
  const before = new Map();
  for (const name of ['workflow-state.json', 'job.json', 'input.elf']) before.set(name, await fs.readFile(join(fixture.directory, name)));
  const progress = await fs.readFile(fixture.progressPath);
  await click('Follow activity');
  await ready(tab, `(${rows}).length === 200`, 'restart activity first page');
  await click('Continue activity on next page');
  await ready(tab, `(${rows}).length === 5`, 'restart activity continuation');
  const deadline = Date.now() + 10000;
  while (!streams) {
    assert.ok(Date.now() < deadline, 'Restart fixture did not open an activity stream');
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  await stopServer();
  await ready(tab, `document.body.innerText.includes('Reconnecting activity:')`, 'stopped server has distinct reconnect status');
  assert.deepEqual(await evaluate(tab, rows), Array.from({ length: 5 }, (_, index) => `Sequence ${index + 200}`));
  await click('Pause activity');
  await ready(tab, `document.body.innerText.includes('Activity paused.')`, 'pause observation during server outage');
  const handoff = await startServer();
  await click('Resume activity');
  await ready(tab, `document.body.innerText.includes('To access private work, open the sign-in link')`, 'restarted server rejects prior session');
  assert.equal(await evaluate(tab, `document.querySelector('section[aria-label="Progress retention"]') === null`), true);
  const rejectedRequests = tab.requests.length;
  await new Promise(resolve => setTimeout(resolve, 3000));
  assert.equal(tab.requests.length, rejectedRequests, 'Session rejection must stop automatic observation retries');
  const documents = tab.requests.filter(request => request.type === 'Document').length;
  // A fresh explicit operator link is consumed by the existing page's hash handler.
  await evaluate(tab, `location.hash = ${JSON.stringify(new URL(handoff).hash)}`);
  await ready(tab, `document.body.innerText.includes('The server instance changed since this tab last connected.') && document.querySelector('section[aria-label="Progress retention"]') !== null`, 'authenticated server-change notice and refreshed attempt');
  assert.equal(await evaluate(tab, 'location.hash'), '');
  assert.equal(await evaluate(tab, 'location.pathname'), path);
  assert.equal(tab.requests.filter(request => request.type === 'Document').length, documents, 'Fresh sign-in should preserve the running tab');
  assert.equal(await evaluate(tab, `document.querySelector('dl.job-facts').innerText`), facts);
  await click('Follow activity');
  await ready(tab, `(${rows}).length === 200`, 'restarted retained activity first page');
  assert.deepEqual(await evaluate(tab, rows), Array.from({ length: 200 }, (_, index) => `Sequence ${index}`));
  await click('Continue activity on next page');
  await ready(tab, `(${rows}).length === 5`, 'restarted retained activity continuation');
  assert.deepEqual(await evaluate(tab, rows), Array.from({ length: 5 }, (_, index) => `Sequence ${index + 200}`));
  await click('Pause activity');
  for (const [name, bytes] of before) assert.deepEqual(await fs.readFile(join(fixture.directory, name)), bytes);
  assert.deepEqual(await fs.readFile(fixture.progressPath), progress);
  const mutations = tab.requests.filter(request => !['GET', 'HEAD'].includes(request.method));
  assert.equal(mutations.length, 1);
  assert.equal(mutations[0].method, 'POST');
  assert.equal(mutations[0].url, browserOrigin + '/nested/api/v1/session');
  assert.equal(await evaluate(tab, 'localStorage.length + sessionStorage.length'), 0);
  assert.deepEqual(tab.exceptions, []);
  return { stoppedDuringStream: true, reconnectingPreservesRows: true, explicitPauseDuringOutage: true,
    priorSessionRejected: true, automaticRequestsAfterRejection: 0, freshExplicitSignIn: true,
    changedInstanceNotice: true, documentReloadsDuringSignIn: 0, attemptFactsPreserved: true,
    retainedPages: [200, 5], workflowBytesUnchanged: true, progressBytesUnchanged: true,
    workflowMutations: 0, sessionExchangeRequests: 1, storageEntries: 0 };
}
