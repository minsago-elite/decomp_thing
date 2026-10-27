import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { seedHistory } from './packaged-browser-history.mjs';

const canary = 'synthetic-log-credential-0123456789';
const count = 20_000;
function recording(generation) {
  const text = Array.from({ length: count }, (_, index) =>
    `generation-${generation} line-${index + 1} api_key=${canary} /home/log-canary/private.txt <script>window.logExecuted=true</script> \u001b[31m ${'x'.repeat(80)}`).join('\n') + '\n';
  // Invalid UTF-8 and a display-truncated line are part of the source, not a mocked response.
  return Buffer.concat([Buffer.from(text), Buffer.from('z'.repeat(5000) + '\n'), Buffer.from([0xff, 0x0a])]);
}
export async function seedLogs(root) {
  const fixture = await seedHistory(root);
  const log = join(fixture.directory, 'reports/runs/run_fixture_3/source-tree/reports/build.log');
  await fs.mkdir(join(log, '..'), { recursive: true, mode: 0o700 });
  const bytes = recording(0);
  await fs.writeFile(log, bytes, { flag: 'wx', mode: 0o600 });
  return { ...fixture, log, bytes };
}

/** Real packaged HTTP/SPA, real recordings, real GC/DOM measurements; no response or timer mocks. */
export async function qualifyLogs({ fixture, makeTarget, cdp, evaluate, ready, waitFor, browserOrigin }) {
  const tab = await makeTarget();
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  const route = `/nested/jobs/${fixture.jobId}/runs/run_fixture_3/logs`;
  const api = `/nested/api/v1/jobs/${fixture.jobId}/runs/run_fixture_3/logs/build`;
  const rows = `document.querySelectorAll('.log-row').length`;
  const loaded = `document.querySelector('.log-viewport') !== null`;
  const button = text => `[...document.querySelectorAll('button')].find(b => b.textContent === ${JSON.stringify(text)}).click()`;
  const digest = bytes => createHash('sha256').update(bytes).digest('hex');
  await cdp.call('Page.navigate', { url: browserOrigin + route }, tab.sessionId);
  await ready(tab, loaded, 'direct packaged build-log route');
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, loaded, 'direct build-log reload');
  assert.equal(await evaluate(tab, 'location.pathname'), route);
  assert.ok(await evaluate(tab, `${rows} > 0 && ${rows} < 60`));
  assert.ok(await evaluate(tab, `document.querySelector('.log-viewport').innerText.includes('[cut at 4096 characters]') && document.querySelector('.log-viewport').innerText.includes('[invalid text replaced]')`));
  // Fill beyond the 2,000-line retention bound through actual backward pages.
  for (let page = 0; page < 5; page++) {
    await evaluate(tab, button('Load earlier lines'));
    const first = count + 2 - 200 + 1 - (page + 1) * 500;
    await ready(tab, `document.body.innerText.includes('Showing lines ${first}–')`, 'completed backward log capture');
  }
  assert.ok(await evaluate(tab, `document.body.innerText.includes('released from memory')`));
  const retainedHeight = await evaluate(tab, `document.querySelector('.log-viewport > div').getBoundingClientRect().height`);
  assert.ok(retainedHeight <= 2000 * 20, 'retained virtual height exceeds the production buffer limit');
  await evaluate(tab, `(() => { const v = document.querySelector('.log-viewport'); v.scrollTop = 30000; v.dispatchEvent(new Event('scroll')); })()`);
  await ready(tab, `document.querySelector('.log-viewport').scrollTop > 10000`, 'real deep scrolling');
  await evaluate(tab, `(() => { const i = [...document.querySelectorAll('label')].find(l => l.textContent.includes('Find in loaded lines')).querySelector('input'); i.value = 'line-18001 '; i.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await ready(tab, `document.querySelector('.log-viewport').scrollTop === 0 && ${rows} === 1`, 'deep-scroll filtering keeps match visible');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Lines that are not loaded were not searched.')`));
  assert.equal(await evaluate(tab, 'window.logExecuted === true'), false);
  assert.equal(await evaluate(tab, `document.querySelector('.log-viewport script') !== null`), false);
  assert.equal(await evaluate(tab, `document.querySelector('.log-viewport').innerText.includes(${JSON.stringify(canary)})`), false);
  const projection = await evaluate(tab, `(async () => {
    const range = (await (await fetch('${api}?fromLine=1&limit=2')).json()).data;
    const search = (await (await fetch('${api}?search=${canary}')).json()).data.search;
    const download = await (await fetch('${api}/content')).text();
    return { state: range.state, redacted: range.lines.every(l => l.redacted), matchCount: search.matchCount,
      absent: !download.includes('${canary}') && !download.includes('/home/log-canary'),
      parity: range.lines.every(l => download.includes(l.text)), provenance: download.includes(range.sourceSha256) };
  })()`);
  assert.deepEqual(projection, { state: 'available', redacted: true, matchCount: '0', absent: true, parity: true, provenance: true });

  await evaluate(tab, `(() => { const form = document.querySelector('.log-search form'); const i = form.querySelector('input'); i.value = 'line-18001 '; i.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await evaluate(tab, `document.querySelector('.log-search form').requestSubmit()`);
  await ready(tab, `document.querySelector('.log-matches button')?.textContent === 'Go to line 18001'`, 'literal whole-log UI search');
  await evaluate(tab, `document.querySelector('.log-matches button').click()`);
  await ready(tab, `document.querySelector('.log-viewport').innerText.includes('line-18001 ')`, 'source-bound whole-log match jump');

  // Replace while mounted too: the digest must replace the retained buffer, not mix recordings.
  const replacement = recording(1);
  await fs.writeFile(fixture.log + '.next', replacement, { flag: 'wx', mode: 0o600 });
  await fs.rename(fixture.log + '.next', fixture.log);
  await evaluate(tab, `(() => { const i = [...document.querySelectorAll('label')].find(l => l.textContent.includes('Find in loaded lines')).querySelector('input'); i.value = ''; i.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await evaluate(tab, button('Go to the newest lines'));
  await ready(tab, `document.body.innerText.includes('${digest(replacement)}') && ${rows} > 0`, 'mounted recording replacement');
  assert.equal(await evaluate(tab, `document.querySelector('.log-viewport').innerText.includes('generation-0 ')`), false);
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Loaded lines were replaced')`));

  // Warm the lazy route, then measure repeated large atomic publication/read/unmount cycles.
  // SPA navigation (not Page.navigate) is essential: a document reload would hide retained buffers.
  const leave = async () => {
    await evaluate(tab, `document.querySelector('a[href="/nested/"]').click()`);
    await ready(tab, `document.querySelector('.log-viewport') === null && document.querySelector('h1')?.textContent === 'Your work, with its evidence'`, 'log SPA teardown');
  };
  const enter = async () => {
    await evaluate(tab, `(() => { const a = document.createElement('a'); a.href = '${route}'; document.body.append(a); a.click(); a.remove(); })()`);
    await ready(tab, loaded, 'log SPA remount');
  };
  const measure = async () => {
    await cdp.call('HeapProfiler.collectGarbage', {}, tab.sessionId);
    const heap = await cdp.call('Runtime.getHeapUsage', {}, tab.sessionId);
    const dom = await cdp.call('Memory.getDOMCounters', {}, tab.sessionId);
    return { usedSize: heap.usedSize, nodes: dom.nodes, documents: dom.documents, listeners: dom.jsEventListeners };
  };
  await leave();
  const baseline = await measure();
  const samples = [];
  for (let generation = 2; generation <= 13; generation++) {
    const bytes = recording(generation);
    const next = fixture.log + '.next';
    await fs.writeFile(next, bytes, { flag: 'wx', mode: 0o600 });
    await fs.rename(next, fixture.log);
    await enter();
    await ready(tab, `document.body.innerText.includes('${digest(bytes)}')`, 'source-bound replacement digest');
    assert.ok(await evaluate(tab, `${rows} > 0 && ${rows} < 60`));
    assert.equal(await evaluate(tab, `document.querySelector('.log-viewport').innerText.includes('generation-${generation - 1} ')`), false);
    await leave();
    samples.push(await measure());
  }
  const final = samples.at(-1);
  assert.ok(final.usedSize <= baseline.usedSize + 8 * 1024 * 1024, 'log teardown retained more than 8 MiB above warm baseline');
  assert.ok(final.nodes <= baseline.nodes + 200, 'log teardown retained DOM rows');
  assert.ok(final.listeners <= baseline.listeners + 20, 'log teardown retained listeners');
  // Observe longer than the real follow interval; never change production timers.
  const logRequests = () => tab.requests.filter(r => new URL(r.url).pathname.startsWith(api)).length;
  const afterLeave = logRequests();
  const until = Date.now() + 3500;
  await waitFor(() => Date.now() >= until, 'post-teardown real-timer observation');
  assert.equal(logRequests(), afterLeave, 'log reads continued after unmount');
  assert.deepEqual(tab.exceptions, []);
  assert.ok(tab.requests.every(r => ['GET', 'HEAD'].includes(r.method)));
  return { realBackend: true, sourceLines: count + 2, sourceBytes: fixture.bytes.length,
    directNestedRouteAndReload: true, virtualRowLimit: 60, retainedLineLimit: 2000,
    deepScrollFilter: true, redactionRangeSearchDownload: projection, mountedReplacement: true, atomicReplacementCycles: samples.length,
    memory: { baseline, samples, final, retainedHeapBudgetBytes: 8 * 1024 * 1024 },
    teardownNoFurtherReads: true, terminalRecordingFixture: true,
    limitation: 'Terminal inert attempt: sustained atomic recordings are qualified; live-worker follow qualification remains with progress integration.' };
}
