import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';

/** Terminal inert attempt only. The initial recovery intent is explicitly test-seeded. */
export async function qualifyCancellationReplay({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin }) {
  const tab = await makeTarget();
  const path = `/nested/jobs/${fixture.jobId}/runs/run_fixture_3`;
  const endpoint = `/nested/api/v1/jobs/${fixture.jobId}/runs/run_fixture_3/cancellation`;
  const click = text => evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === ${JSON.stringify(text)}).click()`);
  await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
    const original = window.fetch;
    const retained = JSON.parse(sessionStorage.getItem('decomp.cancellation.v1:/nested') ?? 'null');
    let drop = false; let requests = 0; let sameKey = true; let replayed = false;
    Object.defineProperty(window, '__dropCancellation', { value: () => { drop = true; } });
    Object.defineProperty(window, '__cancellationProof', { value: () => ({ requests, sameKey, replayed }) });
    window.fetch = async function(input, options) {
      if (options?.method === 'PUT' && String(input).endsWith(${JSON.stringify(endpoint)})) {
        requests++;
        const headers = new Headers(options.headers);
        sameKey = sameKey && headers.get('Idempotency-Key') === retained?.key && headers.get('If-Match') === '"' + retained?.expectedVersion + '"';
        const response = await original.apply(this, arguments);
        replayed = response.headers.get('Idempotency-Replayed') === 'true';
        if (drop && response.ok) { drop = false; await response.text(); throw new TypeError('Test-only lost cancellation acknowledgement'); }
        return response;
      }
      return original.apply(this, arguments);
    };
  })();` }, tab.sessionId);
  await cdp.call('Page.navigate', { url: browserOrigin + path }, tab.sessionId);
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  await ready(tab, `document.querySelector('section[aria-label="Attempt cancellation"]') !== null`, 'cancellation controls in packaged UI');
  const before = await fs.readFile(join(fixture.directory, 'workflow-state.json'));
  const progress = await fs.readFile(fixture.progressPath);
  await click('Read cancellation status');
  await ready(tab, `document.body.innerText.includes('This attempt has ended. No new cancellation is needed.')`, 'terminal cancellation eligibility');
  assert.equal(await evaluate(tab, `[...document.querySelectorAll('button')].some(button => button.textContent === 'Request cancellation')`), false);
  assert.deepEqual(await fs.readFile(join(fixture.directory, 'workflow-state.json')), before);
  // Seed only the bounded metadata that an earlier unconfirmed UI command would retain.
  const run = JSON.parse(before).attempts.find(attempt => attempt.runId === 'run_fixture_3');
  const ticket = { jobId: fixture.jobId, runId: run.runId, expectedVersion: run.version, key: 'packaged_terminal_cancellation_fixture' };
  await evaluate(tab, `sessionStorage.setItem('decomp.cancellation.v1:/nested', ${JSON.stringify(JSON.stringify(ticket))})`);
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('A cancellation intent is retained in this tab.')`, 'seeded intent after reload');
  assert.deepEqual(await evaluate(tab, '__cancellationProof()'), { requests: 0, sameKey: true, replayed: false });
  assert.equal(await evaluate(tab, `[...document.querySelectorAll('button')].some(button => button.textContent === 'Retry retained cancellation request')`), false);
  await click('Read cancellation status');
  await ready(tab, `document.body.innerText.includes('Cancellation status read.')`, 'explicit recovery read');
  await evaluate(tab, '__dropCancellation()');
  await click('Retry retained cancellation request');
  await ready(tab, `document.body.innerText.includes('Cancellation could not be confirmed.')`, 'real response loss after server receipt');
  const published = await fs.readFile(join(fixture.directory, 'workflow-state.json'));
  const state = JSON.parse(published);
  assert.equal(state.cancellationReceipts.entries.length, 1);
  assert.deepEqual(state.attempts, JSON.parse(before).attempts);
  assert.deepEqual(state.acceptedRevision, JSON.parse(before).acceptedRevision);
  assert.deepEqual(await evaluate(tab, '__cancellationProof()'), { requests: 1, sameKey: true, replayed: false });
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('A cancellation intent is retained in this tab.')`, 'lost acknowledgement intent restored');
  assert.deepEqual(await evaluate(tab, '__cancellationProof()'), { requests: 0, sameKey: true, replayed: false });
  await click('Read cancellation status');
  await ready(tab, `document.body.innerText.includes('Cancellation status read.')`, 'fresh read before receipt replay');
  await click('Retry retained cancellation request');
  await ready(tab, `document.body.innerText.includes('Request acknowledged as completed. Server-reported attempt state: completed.')`, 'terminal receipt replay acknowledgement');
  assert.deepEqual(await evaluate(tab, '__cancellationProof()'), { requests: 1, sameKey: true, replayed: true });
  assert.deepEqual(await fs.readFile(join(fixture.directory, 'workflow-state.json')), published);
  assert.deepEqual(await fs.readFile(fixture.progressPath), progress);
  for (const name of ['input.elf', 'job.json']) assert.deepEqual(await fs.readFile(join(fixture.directory, name)), Buffer.from(fixture.retained[name]));
  assert.equal(await evaluate(tab, 'sessionStorage.length + localStorage.length'), 0);
  assert.ok(await evaluate(tab, `document.body.innerText.includes('revision_fixture_3') && document.body.innerText.includes('not-evaluated')`));
  const mutations = tab.requests.filter(request => !['GET', 'HEAD'].includes(request.method));
  assert.equal(mutations.length, 2);
  assert.ok(mutations.every(request => request.method === 'PUT' && new URL(request.url).pathname === endpoint));
  assert.deepEqual(tab.exceptions, []);
  return { initialIntentTestSeeded: true, terminalAttemptOnly: true, actualReceiptPublication: true, responseDeliberatelyLost: true,
    explicitReplayAfterReload: true, sameKeyAndVersion: true, replayHeader: true, automaticMutations: 0,
    terminalAcknowledgement: 'completed', attemptRecordsUnchanged: true, acceptedReferenceUnchanged: true,
    diagnosticsUnchanged: true, replayPreservesDurableBytes: true, browserStorageEntries: 0, workflowExecution: false };
}
