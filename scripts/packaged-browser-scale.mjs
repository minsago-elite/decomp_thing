import { qualifyFilterContrast } from './packaged-browser-contrast.mjs';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

// Private test data only, created before the application acquires storage ownership.
export async function seedScale(root) {
  await fs.mkdir(root, { mode: 0o700 });
  const count = 10000;
  const ids = [];
  const input = Buffer.alloc(64);
  input.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  input.writeUInt16LE(2, 16); input.writeUInt16LE(62, 18); input.writeUInt32LE(1, 20); input.writeUInt16LE(64, 52);
  for (let index = 0; index < count; index++) {
    const id = createHash('sha256').update(`job:${index}`).digest('hex').slice(0, 32);
    ids.push(id);
    const directory = join(root, id);
    await fs.mkdir(directory, { mode: 0o700 });
    const at = new Date(Date.parse('2026-01-01T00:00:00.000Z') + index * 10).toISOString();
    const job = { id, filename: `synthetic-project-${String(index).padStart(5, '0')}.elf`, status: 'uploaded',
      created_at: at, updated_at: at, size_bytes: 64, binary_path: join(directory, 'input.elf'),
      metadata: { format: 'ELF64', endianness: 'little', elf_version: 1, os_abi: 'System V', object_type: 'EXEC',
        machine: 'x86-64', entry_point: 0, elf_header_size: 64, program_header_count: 0, section_header_count: 0, section_name_table_index: 0 } };
    await fs.writeFile(join(directory, 'input.elf'), input, { flag: 'wx', mode: 0o600 });
    await fs.writeFile(join(directory, 'job.json'), JSON.stringify(job), { flag: 'wx', mode: 0o600 });
  }
  return { count, ids };
}

export async function qualifyScale({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin }) {
  const tab = await makeTarget();
  const rows = `Array.from(document.querySelectorAll('ul[aria-label="Uploaded jobs"] li h4 a')).map(a => a.getAttribute('href'))`;
  const timings = [];
  let peakBrowserHeapBytes = 0;
  await cdp.call('Performance.enable', {}, tab.sessionId);
  let start = performance.now();
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/?limit=200' }, tab.sessionId);
  for (let page = 0; page < 50; page++) {
    const expected = fixture.ids.slice(10000 - (page + 1) * 200, 10000 - page * 200).reverse().map(id => '/nested/jobs/' + id);
    await ready(tab, `(${rows})[0] === ${JSON.stringify(expected[0])} && (${rows}).length === 200`, `scale dashboard page ${page + 1}`);
    timings.push(performance.now() - start);
    assert.deepEqual(await evaluate(tab, rows), expected);
    if (page) assert.equal(await evaluate(tab, 'document.activeElement.textContent'), 'Job results');
    const metrics = (await cdp.call('Performance.getMetrics', {}, tab.sessionId)).metrics;
    peakBrowserHeapBytes = Math.max(peakBrowserHeapBytes, metrics.find(m => m.name === 'JSHeapUsedSize').value);
    if (page < 49) {
      // Exercise the native keyboard activation path, including focus handoff after rendering.
      await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Next page').focus()`);
      start = performance.now();
      await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
      await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
    }
  }
  assert.ok(await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Next page').disabled`));
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/?search=synthetic-project-00042.elf' }, tab.sessionId);
  await ready(tab, `(${rows}).length === 1`, 'exact filename search across 10000 persisted jobs');
  assert.deepEqual(await evaluate(tab, rows), ['/nested/jobs/' + fixture.ids[42]]);
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `(${rows}).length === 1`, 'scale search after reload');
  assert.deepEqual(await evaluate(tab, rows), ['/nested/jobs/' + fixture.ids[42]]);
  const filters = { search: 'synthetic-project-0004', status: 'uploaded', limit: '100',
    createdAfter: '2026-01-01T00:00:00.420000000Z', createdBefore: '2026-01-01T09:00:00.420000001+09:00' };
  await evaluate(tab, `(() => {
    const values = ${JSON.stringify(filters)};
    const fields = { search: 'Filename search', status: 'Workflow state', limit: 'Jobs per page', createdAfter: 'Created at or after', createdBefore: 'Created before' };
    for (const [key, label] of Object.entries(fields)) {
      const field = [...document.querySelectorAll('label')].find(item => item.textContent.startsWith(label)).querySelector('input, select');
      field.value = values[key]; field.dispatchEvent(new Event(field.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
    }
  })()`);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Apply filters').click()`);
  await ready(tab, `location.search.includes('createdBefore') && (${rows}).length === 1 && document.activeElement.textContent === 'Job results'`, 'combined nanosecond filters');
  assert.deepEqual(await evaluate(tab, rows), ['/nested/jobs/' + fixture.ids[42]]);
  assert.deepEqual(await evaluate(tab, 'Object.fromEntries(new URLSearchParams(location.search))'), filters);
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `(${rows}).length === 1`, 'combined filters restored after reload');
  assert.deepEqual(await evaluate(tab, rows), ['/nested/jobs/' + fixture.ids[42]]);
  assert.deepEqual(await evaluate(tab, 'Object.fromEntries(new URLSearchParams(location.search))'), filters);
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/?sort=oldest&limit=200' }, tab.sessionId);
  const oldest = fixture.ids.slice(0, 200).map(id => '/nested/jobs/' + id);
  await ready(tab, `(${rows})[0] === ${JSON.stringify(oldest[0])} && (${rows}).length === 200`, 'oldest-first library');
  assert.deepEqual(await evaluate(tab, rows), oldest);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Next page').click()`);
  await ready(tab, `(${rows})[0] === ${JSON.stringify('/nested/jobs/' + fixture.ids[200])}`, 'oldest-first continuation');
  assert.deepEqual(await evaluate(tab, rows), fixture.ids.slice(200, 400).map(id => '/nested/jobs/' + id));
  const readsBeforePrevious = tab.requests.filter(request => request.url.endsWith('/api/v1/jobs')).length;
  assert.ok(readsBeforePrevious > 0, 'Collection request counter must observe actual reads');
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Previous page').click()`);
  await ready(tab, `(${rows})[0] === ${JSON.stringify(oldest[0])} && document.activeElement.textContent === 'Job results'`, 'retained first snapshot page');
  assert.deepEqual(await evaluate(tab, rows), oldest);
  assert.equal(tab.requests.filter(request => request.url.endsWith('/api/v1/jobs')).length, readsBeforePrevious);

  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `(${rows})[0] === ${JSON.stringify(oldest[0])}`, 'oldest-first restored after reload');
  assert.deepEqual(await evaluate(tab, rows), oldest);
  assert.equal(await evaluate(tab, `[...document.querySelectorAll('label')].find(label => label.textContent.startsWith('Sort by')).querySelector('select').value`), 'oldest');
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Reset filters').click()`);
  await ready(tab, `(${rows})[0] === ${JSON.stringify('/nested/jobs/' + fixture.ids[9999])} && (${rows}).length === 50`, 'reset oldest-first preference');
  assert.equal(await evaluate(tab, 'location.search'), '');
  const reflow = [];
  for (const width of [390, 320]) {
    await cdp.call('Emulation.setDeviceMetricsOverride', { width, height: 844, deviceScaleFactor: 1, mobile: false }, tab.sessionId);
    const dimensions = await evaluate(tab, `({ viewport: innerWidth, available: document.documentElement.clientWidth, document: document.documentElement.scrollWidth, body: document.body.scrollWidth })`);
    assert.ok(dimensions.document <= dimensions.available && dimensions.body <= dimensions.available, `Dashboard horizontal overflow at ${width}px: ${JSON.stringify(dimensions)}`);
    reflow.push(dimensions);
  }
  const ax = (await cdp.call('Accessibility.getFullAXTree', {}, tab.sessionId)).nodes.filter(node => !node.ignored);
  const named = (role, name) => ax.filter(node => node.role?.value === role && node.name?.value === name);
  assert.equal(ax.filter(node => node.role?.value === 'main').length, 1);
  for (const name of ['Filename search', 'Created at or after', 'Created before']) assert.equal(named('textbox', name).length, 1);
  for (const name of ['Workflow state', 'Sort by', 'Jobs per page']) assert.equal(named('combobox', name).length, 1);
  for (const name of ['Apply filters', 'Reset filters', 'Refresh jobs', 'Previous page', 'Next page']) assert.equal(named('button', name).length, 1);
  assert.equal(named('list', 'Uploaded jobs').length, 1);
  const readsBeforeInvalid = tab.requests.filter(request => request.url.endsWith('/api/v1/jobs')).length;
  await evaluate(tab, `(() => { const field = document.querySelector('[name="createdAfter"]'); field.value = '2026-02-29T00:00:00Z'; field.dispatchEvent(new Event('input', { bubbles: true })); })()`);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Apply filters').click()`);
  await ready(tab, `document.activeElement.name === 'createdAfter' && document.activeElement.getAttribute('aria-invalid') === 'true'`, 'invalid date field focus');
  const invalidTree = (await cdp.call('Accessibility.getFullAXTree', {}, tab.sessionId)).nodes;
  const invalidField = invalidTree.find(node => !node.ignored && node.role?.value === 'textbox' && node.name?.value === 'Created at or after');
  assert.ok(invalidField.description?.value.includes('valid calendar date'));
  assert.equal(tab.requests.filter(request => request.url.endsWith('/api/v1/jobs')).length, readsBeforeInvalid);
  assert.equal((await evaluate(tab, rows)).length, 50);
  assert.equal(await evaluate(tab, 'location.search'), '');
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Reset filters').click()`);
  await ready(tab, `!document.querySelector('#job-filter-error') && document.activeElement.textContent === 'Job results'`, 'invalid date reset recovery');
  const filterContrast = await qualifyFilterContrast({ tab, cdp, evaluate });
  assert.deepEqual(tab.exceptions, []);
  assert.ok(tab.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
  return { persistedJobs: fixture.count, pages: 50, rowsPerPage: 200, reachableJobs: 10000,
    exactOrder: true, keyboardPaginationFocus: true, searchReload: true, combinedNanosecondFiltersReload: true, oldestFirstPagesReloadReset: true, previousFirstPageRetained: true, narrowReflow: reflow, accessibleFilterNames: true, invalidDateDescriptionFocusRecovery: true, filterContrast, mutationRequests: 0,
    peakBrowserHeapBytes, pageLatencyMs: timings.map(ms => Math.round(ms)), executionStarted: false };
}
