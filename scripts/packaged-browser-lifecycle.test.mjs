import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';
import { LISTING_BUSY_RETRY_DELAYS_MS, deletedNotice, deletionVerdict, readListingMembership } from './packaged-browser-lifecycle.mjs';

const { JSDOM } = createRequire(new URL('../frontend/package.json', import.meta.url))('jsdom');
// Independent reviewed UI text fixtures: compare displayed values, not TypeScript formatting.
const reviewedCopy = {
  headline: 'This job was deleted from the library and cannot be recovered. Its deletion record is kept for at least 24 hours.',
  running: 'File cleanup is still running and resumes after a restart if interrupted. Its files are not yet confirmed removed.',
  finished: 'File cleanup finished: its files were removed.',
  unknown: 'This page has not observed whether file cleanup finished.',
  attemptHeadline: 'This attempt’s job was deleted from the library and cannot be recovered. This page has not observed whether file cleanup finished.',
  historyHeadline: 'This job was deleted from the library. Its attempt history cannot be recovered.',
  expiredWindow: 'The requested activity window is no longer retained. No fresh history was substituted.',
};
function page(t, { operation = null, cleanup = reviewedCopy.unknown, headline = reviewedCopy.headline } = {}) {
  const dom = new JSDOM('<main><a href="/nested/runtime">Runtime</a><section aria-labelledby="job-title"><h1 id="job-title">Job overview</h1><a href="/nested/">Return to jobs</a><div role="alert"></div></section></main>', { url: 'http://fixture.invalid/nested/jobs/' + 'a'.repeat(32), runScripts: 'outside-only' });
  t.after(() => dom.window.close());
  const alert = dom.window.document.querySelector('[role="alert"]');
  for (const text of [headline, ...(operation ? [operation.message] : []), cleanup]) {
    const p = dom.window.document.createElement('p'); p.textContent = text; alert.append(p);
  }
  const link = dom.window.document.createElement('a'); link.href = '/nested/'; link.textContent = 'Return to jobs'; alert.append(link);
  return { dom, alert, check: (operation, reference) => dom.window.eval(deletionVerdict(operation, reference)), eval: text => dom.window.eval(text) };
}
const running = { state: 'running', recoveryRequired: false, message: 'The recorded deletion acknowledgement is still running.' };
const completed = { state: 'completed', recoveryRequired: false, message: 'The recorded deletion acknowledgement completed.' };

test('job driver predicates match the reviewed headline and cleanup copy', t => {
  for (const [operation, cleanup] of [[null, reviewedCopy.unknown], [running, reviewedCopy.running], [completed, reviewedCopy.finished]]) {
    const fixture = page(t, { operation, cleanup });
    assert.equal(fixture.eval(deletedNotice), true);
    assert.equal(fixture.check(operation), true);
    fixture.alert.children[fixture.alert.children.length - 2].textContent = cleanup.slice(0, -1);
    assert.equal(fixture.check(operation), false, 'Cleanup copy must remain exact');
  }
  assert.equal(page(t, { headline: reviewedCopy.headline + ' Unreviewed claim.' }).eval(deletedNotice), false);
});

test('a tombstone matches exactly the reference from its own job GET', t => {
  const reference = '9ea205a7-2652-4da6-9a84-47bef7611978';
  const other = 'de106c03-ec46-404f-aa8c-64fd7508c227';
  const correct = page(t, { headline: reviewedCopy.headline + ' Reference ID: ' + reference + '.' });
  assert.equal(correct.check(null, reference), true);
  assert.equal(correct.check(null, other), false);
  assert.equal(correct.check(), false);
  assert.equal(page(t).check(null, reference), false);
  assert.equal(page(t, { headline: reviewedCopy.headline + ' Reference ID: ' + reference + '. More.' }).check(null, reference), false);
});

test('recorded running and completed acknowledgements and tombstones have distinct verdicts', t => {
  assert.equal(page(t, { operation: running, cleanup: reviewedCopy.running }).check(running), true);
  assert.equal(page(t, { operation: completed, cleanup: reviewedCopy.finished }).check(completed), true);
  assert.equal(page(t).check(), true);
  const incomplete = { ...completed, recoveryRequired: true };
  assert.equal(page(t, { operation: incomplete, cleanup: 'File cleanup did not finish (completed). Some files may remain until recovery completes.' }).check(incomplete), true);
});

test('a completed independent status read cannot promote a recorded running acknowledgement', t => {
  const fixture = page(t, { operation: running, cleanup: reviewedCopy.running });
  assert.equal(fixture.check(running), true);
  assert.equal(fixture.check(completed), false);
  fixture.alert.children[2].textContent = reviewedCopy.finished;
  assert.equal(fixture.check(running), false);
});

test('tombstone-only views cannot claim cleanup completion or borrow a recorded acknowledgement', t => {
  assert.equal(page(t, { cleanup: reviewedCopy.finished }).check(), false);
  assert.equal(page(t, { operation: completed, cleanup: reviewedCopy.unknown }).check(), false);
  assert.equal(page(t, { operation: running, cleanup: reviewedCopy.unknown }).check(running), false);
  assert.equal(page(t, { operation: completed, cleanup: reviewedCopy.running }).check(completed), false);
});

test('recorded acknowledgement text must remain exact and present', t => {
  assert.equal(page(t, { operation: { ...running, message: running.message.slice(0, -1) }, cleanup: reviewedCopy.running }).check(running), false);
  assert.equal(page(t, { cleanup: reviewedCopy.running }).check(running), false);
});

test('a deleted route rejects disabled stale controls and links while allowing recovery links', t => {
  for (const html of ['<button disabled>Refresh job</button>', '<input type="hidden">', '<form></form>', '<select></select>', '<textarea></textarea>', '<a href="/nested/jobs/old/runs">Attempt history</a>', '<span role="button">Run</span>', '<span role="link">Evidence</span>']) {
    const fixture = page(t);
    fixture.alert.insertAdjacentHTML('afterend', html);
    assert.equal(fixture.check(), false, html);
  }
  assert.equal(page(t).check(), true, 'Global Runtime navigation and the job recovery links remain permitted');
});

test('old overclaiming copy and unrelated attempt/history alerts do not satisfy the job verdict', t => {
  for (const headline of ['This job was deleted. Its files were removed and cannot be recovered.', reviewedCopy.attemptHeadline, reviewedCopy.historyHeadline]) {
    const fixture = page(t, { headline });
    assert.equal(fixture.eval(deletedNotice), false);
    assert.equal(fixture.check(), false);
  }
});

test('saved-window EVENT_GAP copy remains an expired window, not a deletion notice', t => {
  const fixture = page(t, { headline: reviewedCopy.expiredWindow });
  assert.equal(fixture.eval(deletedNotice), false);
  assert.equal(fixture.check(), false);
  fixture.dom.window.document.querySelector('section').setAttribute('aria-labelledby', 'attempt-title');
  assert.equal(fixture.eval(deletedNotice), false);
});

const jobId = 'c'.repeat(32);

// Listing membership reads: only a bound 503 LISTING_BUSY admission refusal is transient.
const member = 'e'.repeat(32);
const listing = (ids, nextCursor = null) => ({ status: 200, requestId: null,
  body: JSON.stringify({ data: { items: ids.map(jobId => ({ jobId })), page: { limit: 100, nextCursor } } }) });
const refusal = (code, requestId = 'req-' + code, overrides = {}) => ({ status: 503, requestId,
  body: JSON.stringify({ apiVersion: 1, kind: 'error', requestId, error: { code, message: code + ' fixture', retryable: false,
    details: [], retryAfterMs: null }, ...overrides }) });
function scripted(replies) {
  const calls = { reads: 0, sleeps: [] };
  const read = async () => {
    const reply = replies[calls.reads++];
    if (!reply) throw new Error('unexpected extra listing read ' + calls.reads);
    return reply;
  };
  return { calls, read, options: { delays: [5, 10, 20], sleep: async ms => { calls.sleeps.push(ms); } } };
}

test('stable 200 listing reports exact membership with no retry', async () => {
  for (const [ids, expected] of [[[member, jobId], true], [[jobId], false], [[], false]]) {
    const { calls, read, options } = scripted([listing(ids)]);
    const result = await readListingMembership(read, member, options);
    assert.deepEqual(result, { listed: expected, busy: [] });
    assert.deepEqual(calls, { reads: 1, sleeps: [] });
  }
});

test('membership succeeds after a transient bound LISTING_BUSY refusal', async () => {
  const { calls, read, options } = scripted([refusal('LISTING_BUSY', 'busy-1'), refusal('LISTING_BUSY', 'busy-2'), listing([member])]);
  const result = await readListingMembership(read, member, options);
  assert.equal(result.listed, true);
  assert.deepEqual(result.busy.map(entry => entry.requestId), ['busy-1', 'busy-2']);
  assert.deepEqual(calls, { reads: 3, sleeps: [5, 10] });
});

test('persistent LISTING_BUSY stops at the bound with attempt diagnostics', async () => {
  const replies = [1, 2, 3, 4].map(index => refusal('LISTING_BUSY', 'busy-' + index));
  const { calls, read, options } = scripted([...replies, listing([member])]);
  await assert.rejects(readListingMembership(read, member, options), error => {
    assert.match(error.message, /LISTING_BUSY persisted for 4 reads/);
    for (const index of [1, 2, 3, 4]) assert.match(error.message, new RegExp('busy-' + index));
    assert.equal(error.busy.length, 4);
    return true;
  });
  assert.deepEqual(calls, { reads: 4, sleeps: [5, 10, 20] });
});

for (const [label, reply] of Object.entries({
  'another 503 code': refusal('LISTING_LIMIT'),
  'a 503 JOB_STORAGE_UNAVAILABLE': refusal('JOB_STORAGE_UNAVAILABLE'),
  'a 503 without a request id header': refusal('LISTING_BUSY', null),
  'a 503 bound to a different request id': { ...refusal('LISTING_BUSY', 'header-id'), body: refusal('LISTING_BUSY', 'body-id').body },
  'a 503 that is not an error envelope': refusal('LISTING_BUSY', 'req', { kind: 'data' }),
  'a 503 with an unknown API version': refusal('LISTING_BUSY', 'req', { apiVersion: 2 }),
  'a 503 with a non-JSON body': { status: 503, requestId: 'req', body: 'Service Unavailable' },
  'a 503 with an empty body': { status: 503, requestId: 'req', body: '' },
  'a 500 LISTING_BUSY body': { ...refusal('LISTING_BUSY'), status: 500 },
  'a 401 refusal': { ...refusal('SESSION_REQUIRED'), status: 401 },
  'a malformed 200 body': { status: 200, requestId: null, body: '{"data":' },
  'a 200 without items': { status: 200, requestId: null, body: JSON.stringify({ data: { page: { nextCursor: null } } }) },
  'a 200 with an unidentified row': { status: 200, requestId: null, body: JSON.stringify({ data: { items: [{}], page: { nextCursor: null } } }) },
  'a 200 with a further page': listing([jobId], 'next'),
})) {
  test('fails immediately without retry on ' + label, async () => {
    const { calls, read, options } = scripted([reply, listing([member])]);
    await assert.rejects(readListingMembership(read, member, options), /job listing/);
    assert.deepEqual(calls, { reads: 1, sleeps: [] });
  });
}

test('a failed read transport is honoured, not retried', async () => {
  const { calls, options } = scripted([]);
  const read = async () => { calls.reads++; throw new Error('Browser expression failed: network'); };
  await assert.rejects(readListingMembership(read, member, options), /network/);
  assert.deepEqual(calls, { reads: 1, sleeps: [] });
});

test('the default retry bound is small and finite', () => {
  assert.ok(LISTING_BUSY_RETRY_DELAYS_MS.length > 0 && LISTING_BUSY_RETRY_DELAYS_MS.length <= 6);
  assert.ok(LISTING_BUSY_RETRY_DELAYS_MS.reduce((total, delay) => total + delay, 0) <= 8_000);
  assert.ok(Object.isFrozen(LISTING_BUSY_RETRY_DELAYS_MS));
});
