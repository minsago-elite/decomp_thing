import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';
import { deletedNotice, deletionVerdict } from './packaged-browser-lifecycle.mjs';

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
  return { dom, alert, check: operation => dom.window.eval(deletionVerdict(operation)), eval: text => dom.window.eval(text) };
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
