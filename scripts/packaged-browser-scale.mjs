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
  assert.deepEqual(tab.exceptions, []);
  assert.ok(tab.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
  return { persistedJobs: fixture.count, pages: 50, rowsPerPage: 200, reachableJobs: 10000,
    exactOrder: true, keyboardPaginationFocus: true, searchReload: true, mutationRequests: 0,
    peakBrowserHeapBytes, pageLatencyMs: timings.map(ms => Math.round(ms)), executionStarted: false };
}
