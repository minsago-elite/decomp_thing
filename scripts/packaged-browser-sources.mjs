import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { dirname, join } from 'node:path';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
// Deliberately pinned to GeneratedCMakeReconstructionProfile, like the legacy fixture. A profile change must
// update this packaged fixture instead of silently weakening manifest validation.
const PROFILE = { id: 'generated-c-make-v1', sha256: 'a448a139a09f28ad9f2e08bfcebcb9d85765a0a557ebb11db6d7634bc145f28f' };
const ROLES = {
  build: ['archive-payload', 'build-definition', 'build-input', 'editable', 'viewable'],
  header: ['archive-payload', 'build-input', 'editable', 'public-interface', 'viewable'],
  module: ['archive-payload', 'build-input', 'editable', 'module-implementation', 'viewable'],
  evidence: ['archive-payload', 'evidence', 'viewable'],
};
const role = (path) => path === 'Makefile' ? 'build' : path.startsWith('include/') ? 'header'
  : path.startsWith('src/modules/') ? 'module' : 'evidence';

const core = (changed) => Array.from({ length: 30 }, (_, index) => {
  if (index === 1) return '/* </pre><script>globalThis.__sourceExecuted = true</script> <img src=x onerror="globalThis.__sourceExecuted = true"> */';
  if (index === 4) return 'int core(void) { return DECOMP_VALUE; }';
  if (index === 19) return changed ? 'int changed_line(void) { return 2; }' : 'int original_line(void) { return 1; }';
  return `/* line ${index + 1} */`;
}).join('\n') + '\n';

/** Two retained candidates of one job with real descriptors and digests; written before server ownership. */
export async function seedSources(root) {
  await fs.mkdir(root, { mode: 0o700 });
  const jobId = 'e'.repeat(32);
  const directory = join(root, jobId);
  await fs.mkdir(directory, { mode: 0o700 });
  const input = Buffer.alloc(64);
  input.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  input.writeUInt16LE(2, 16); input.writeUInt16LE(62, 18); input.writeUInt32LE(1, 20); input.writeUInt16LE(64, 52);
  const at = new Date(Date.now() - 300_000).toISOString();
  const job = { id: jobId, filename: 'synthetic-sources.elf', status: 'uploaded', created_at: at, updated_at: at,
    size_bytes: 64, binary_path: join(directory, 'input.elf'), metadata: { format: 'ELF64', endianness: 'little',
      elf_version: 1, os_abi: 'System V', object_type: 'executable', machine: 'x86-64', entry_point: 0,
      elf_header_size: 64, program_header_count: 0, section_header_count: 0, section_name_table_index: 0 } };
  const jobBytes = JSON.stringify(job);
  const header = '#pragma once\n#define DECOMP_VALUE 1\n';
  const trees = {
    run_source_a: {
      'Makefile': 'all:\n\tcc -Iinclude -o program src/modules/core.c src/modules/old.c\n',
      'include/decomp_types.h': header,
      'src/modules/core.c': core(false),
      'src/modules/old.c': 'int old(void) { return 0; }\n',
      'src/modules/bytes.c': Buffer.from([0x69, 0x6e, 0x74, 0x20, 0xff, 0x0a]),
      'reports/confidence.json': '{"score":0.5,"note":"<img src=x onerror=alert(1)>"}\n',
      'UNRESOLVED.md': '# Unresolved\n\n- fn_2000: [details](javascript:globalThis.__sourceExecuted=true)\n',
    },
    run_source_b: {
      'Makefile': 'all:\n\tcc -Iinclude -o program src/modules/core.c src/modules/fresh.c\n',
      'include/decomp_types.h': header,
      'src/modules/core.c': core(true),
      'src/modules/fresh.c': 'int fresh(void) { return 3; }\n',
      'src/modules/bytes.c': Buffer.from([0x69, 0x6e, 0x74, 0x20, 0xff, 0x0a]),
      'reports/confidence.json': '{"score":0.75,"note":"<img src=x onerror=alert(1)>"}\n',
      'UNRESOLVED.md': '# Unresolved\n\n- fn_2000: [details](javascript:globalThis.__sourceExecuted=true)\n',
    },
  };
  const candidates = {};
  for (const [runId, files] of Object.entries(trees)) {
    const tree = join(directory, 'reports', 'runs', runId, 'source-tree');
    const paths = Object.keys(files).sort();
    const records = paths.map((path) => {
      const bytes = Buffer.from(files[path]);
      return { path, bytes, sha256: sha256(bytes) };
    });
    for (const record of records) {
      await fs.mkdir(dirname(join(tree, record.path)), { recursive: true, mode: 0o700 });
      await fs.writeFile(join(tree, record.path), record.bytes, { flag: 'wx', mode: 0o600 });
    }
    const inputs = records.filter((record) => ROLES[role(record.path)].includes('build-input'));
    const sourceSha256 = sha256(inputs.map((record) => `${record.path.length}:${record.path}:${record.bytes.length}:${record.sha256}\n`).join(''));
    const manifest = { schemaVersion: 3, profileId: PROFILE.id, profileSha256: PROFILE.sha256, inputSha256: sha256(input),
      files: records.map((record) => ({ path: record.path, sha256: record.sha256, generator: 'packaged-browser-fixture', promptSha256: null,
        acceptedImplementation: role(record.path) === 'module' ? false : null, contentKind: 'utf8-text', roles: ROLES[role(record.path)],
        entityIds: role(record.path) === 'module' ? [`fn_${record.path.split('/').pop().split('.')[0]}`] : [] })),
      unresolvedEntityIds: [], unresolvedImplementationIds: [] };
    await fs.writeFile(join(tree, 'source_tree_manifest.json'), JSON.stringify(manifest), { flag: 'wx', mode: 0o600 });
    const contract = { schemaVersion: 3, sourceRevisionSha256: sourceSha256,
      sourceInputs: inputs.map((record) => ({ path: record.path, bytes: record.bytes.length, sha256: record.sha256 })) };
    await fs.mkdir(join(tree, 'reports'), { recursive: true, mode: 0o700 });
    await fs.writeFile(join(tree, 'reports', 'build_contract.json'), JSON.stringify(contract), { flag: 'wx', mode: 0o600 });
    candidates[runId] = { revisionId: runId.replace('run_', 'revision_'), sourceSha256 };
  }
  const attempts = Object.keys(trees).map((runId, index) => {
    const time = new Date(Date.parse(at) + index * 2000).toISOString();
    return { runId, jobId, workflow: 'reconstruct', state: 'completed', version: `version_${runId}`,
      createdAt: time, startedAt: time, endedAt: new Date(Date.parse(time) + 1000).toISOString(),
      previousRunId: index ? 'run_source_a' : null, inputRevisionId: null, harnessCapabilityId: null,
      limits: { wallClockMs: '60000', idleMs: '15000', maxOutputBytes: '1048576', maxToolCalls: '16' },
      terminalReason: 'COMPLETED', usage: null, candidate: candidates[runId], acceptedRevision: null };
  });
  // The web service requires a canonical stored workflow version once attempts exist.
  const state = { schemaVersion: 1, jobId, version: `version_${'5'.repeat(32)}`,
    legacy: { originalJobSha256: sha256(jobBytes), status: 'uploaded', recoveredInterrupted: false },
    attempts, acceptedRevision: null };
  for (const [name, bytes] of Object.entries({ 'input.elf': input, 'job.json': jobBytes, 'workflow-state.json': JSON.stringify(state) })) {
    await fs.writeFile(join(directory, name), bytes, { flag: 'wx', mode: 0o600 });
  }
  return { jobId, directory, trees, candidates };
}

async function press(cdp, tab, key = 'Enter') {
  const codes = { Enter: [13, '\r'], Tab: [9, undefined] };
  const [code, text] = codes[key];
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', key, code: key, windowsVirtualKeyCode: code, ...(text ? { text } : {}) }, tab.sessionId);
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key, code: key, windowsVirtualKeyCode: code }, tab.sessionId);
}

/** Focus a control by its accessible text, then activate it with the real keyboard. */
async function activate(cdp, ready, tab, selector, text) {
  await ready(tab, `(() => {
    const element = [...document.querySelectorAll(${JSON.stringify(selector)})].find(node =>
      (node.getAttribute('aria-label') ?? node.textContent).trim() === ${JSON.stringify(text)} && !node.disabled);
    if (!element) return false;
    element.focus(); return document.activeElement === element;
  })()`, `keyboard target ${text}`);
  await press(cdp, tab);
}

export async function qualifySources({ fixture, makeTarget, cdp, evaluate, ready, waitFor, browserOrigin, manifest }) {
  const tab = await makeTarget();
  const workers = { attached: [], detached: [] };
  cdp.on('Target.attachedToTarget', (event) => {
    if (event.targetInfo.type === 'worker') workers.attached.push({ sessionId: event.sessionId, url: event.targetInfo.url, waiting: event.waitingForDebugger });
  }, tab.sessionId);
  cdp.on('Target.detachedFromTarget', (event) => { workers.detached.push(event.sessionId); }, tab.sessionId);
  await cdp.call('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }, tab.sessionId);
  const job = `/nested/jobs/${fixture.jobId}`;
  const head = `${job}/runs/run_source_b/revisions/revision_source_b`;
  const listing = `[...document.querySelectorAll('ul[aria-label="Recorded source inputs"] > li > a')].map(link => link.textContent)`;
  await cdp.call('Page.navigate', { url: `${browserOrigin}${head}/sources/root` }, tab.sessionId);
  await ready(tab, `(${listing}).length === 5`, 'packaged source root directory');
  assert.deepEqual(await evaluate(tab, listing), ['include', 'reports', 'src', 'Makefile', 'UNRESOLVED.md']);
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Empty physical directories are not recorded in this input inventory.')`));
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Manifest entry, size not recorded')`));
  // Real keyboard navigation through opaque directory links; focus lands on the new directory heading.
  await activate(cdp, ready, tab, 'ul[aria-label="Recorded source inputs"] a', 'src');
  // The shell moves focus to the page heading after route changes, so keyboard users start at the new directory.
  await ready(tab, `document.querySelector('main h2')?.textContent === 'src' && ['H1', 'H2'].includes(document.activeElement?.tagName)`, 'keyboard directory navigation');
  await activate(cdp, ready, tab, 'ul[aria-label="Recorded source inputs"] a', 'modules');
  await ready(tab, `(${listing}).join() === 'bytes.c,core.c,fresh.c'`, 'nested module directory');
  await activate(cdp, ready, tab, 'ul[aria-label="Recorded source inputs"] a', 'core.c');
  await ready(tab, `!!document.querySelector('h2 bdi') && document.querySelector('h2 bdi').textContent === 'src/modules/core.c'`, 'file metadata view');
  const fileUrl = await evaluate(tab, 'location.pathname');
  assert.match(fileUrl, /\/source-files\/file_\d+_[a-f0-9]{64}$/);
  await activate(cdp, ready, tab, 'button', 'Open source preview');
  await ready(tab, `!!document.querySelector('[role="region"][aria-label="Source range content"]')`, 'bounded preview');
  assert.equal(await evaluate(tab, 'globalThis.__sourceExecuted === true'), false, 'Markup in source must stay inert text');
  assert.ok(await evaluate(tab, `document.querySelector('[aria-label="Source range content"]').textContent.includes('<script>globalThis.__sourceExecuted')`));
  assert.equal(await evaluate(tab, `document.querySelectorAll('.source-preview script, .source-preview img').length`), 0);
  // A keyboard-activated line link names the exact revision line and keeps focus inside the viewer.
  await activate(cdp, ready, tab, 'a.source-position', 'Open revision line 20 at byte ' + Buffer.byteLength(fixture.trees.run_source_b['src/modules/core.c'].split('\n').slice(0, 19).join('\n') + '\n'));
  await ready(tab, `location.search.endsWith('&line=20') && document.activeElement?.id === 'source-preview-title'`, 'keyboard line link');
  const lineUrl = await evaluate(tab, 'location.pathname + location.search');
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `!!document.querySelector('[aria-label="Source range content"]') && document.querySelector('.source-row a')?.textContent === '20'`, 'reloaded exact line link');
  assert.equal(await evaluate(tab, 'location.pathname + location.search'), lineUrl);

  // Local highlighting uses the bundled worker asset and that worker exits after its single answer.
  await activate(cdp, ready, tab, 'button', 'Highlight displayed rows locally');
  await ready(tab, `document.body.innerText.includes('Local colors applied.') && document.querySelectorAll('.source-token-keyword').length > 0`, 'local highlighting');
  await waitFor(() => workers.attached.length === 1 && workers.detached.includes(workers.attached[0].sessionId), 'highlight worker exit');
  const workerAsset = manifest.files.find((entry) => /^assets\/highlight\.worker-[A-Za-z0-9_-]+\.js$/.test(entry.path));
  assert.ok(workerAsset, 'The package must contain the highlight worker asset');
  assert.equal(workers.attached[0].url, `${browserOrigin}/nested/assets/ui/${workerAsset.path}`);
  assert.equal(await evaluate(tab, 'globalThis.__sourceExecuted === true'), false);
  // Leaving the viewer while a worker is still pending terminates it.
  await cdp.call('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, tab.sessionId);
  await activate(cdp, ready, tab, 'button', 'Refresh this byte range');
  await ready(tab, `[...document.querySelectorAll('button')].some(b => b.textContent === 'Highlight displayed rows locally' && !b.disabled)`, 'refreshed range');
  await activate(cdp, ready, tab, 'button', 'Highlight displayed rows locally');
  await waitFor(() => workers.attached.length === 2 && workers.attached[1].waiting, 'paused second highlight worker');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Formatting displayed rows locally')`));
  await activate(cdp, ready, tab, 'a', 'Return to source directory');
  await ready(tab, `(${listing}).join() === 'bytes.c,core.c,fresh.c'`, 'left the viewer');
  await waitFor(() => workers.detached.includes(workers.attached[1].sessionId), 'worker termination after leaving the viewer');
  await cdp.call('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }, tab.sessionId);

  // Invalid UTF-8 stays inspectable through the named hexadecimal fallback.
  await activate(cdp, ready, tab, 'ul[aria-label="Recorded source inputs"] a', 'bytes.c');
  await activate(cdp, ready, tab, 'button', 'Open source preview');
  await ready(tab, `document.body.innerText.includes('This input is not valid UTF-8. Hexadecimal byte values preserve the original data.')`, 'hex fallback');
  assert.ok(await evaluate(tab, `document.querySelector('[aria-label="Source range content"]').textContent.includes('69 6e 74 20 ff 0a')`));
  // JSON reports and Markdown notes are manifest-only entries: reachable, digest-bound, plain text.
  for (const [name, highlight] of [['reports/confidence.json', true], ['UNRESOLVED.md', false]]) {
    await cdp.call('Page.navigate', { url: `${browserOrigin}${head}/sources/root` }, tab.sessionId);
    await ready(tab, `(${listing}).length === 5`, 'root for manifest entries');
    if (name.startsWith('reports/')) {
      await activate(cdp, ready, tab, 'ul[aria-label="Recorded source inputs"] a', 'reports');
      await ready(tab, `(${listing}).join() === 'confidence.json'`, 'reports directory');
    }
    await activate(cdp, ready, tab, 'ul[aria-label="Recorded source inputs"] a', name.split('/').pop());
    await ready(tab, `document.body.innerText.includes('Size not recorded') && document.body.innerText.includes('Recorded manifest entry')`, `${name} metadata`);
    await activate(cdp, ready, tab, 'button', 'Open source preview');
    await ready(tab, `!!document.querySelector('[aria-label="Source range content"]')`, `${name} preview`);
    assert.ok(await evaluate(tab, `document.querySelector('[aria-label="Source range content"]').textContent.includes(${JSON.stringify(fixture.trees.run_source_b[name].split('\n')[0])})`));
    assert.equal(await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Highlight displayed rows locally').disabled`), !highlight);
    assert.equal(await evaluate(tab, `document.querySelectorAll('.source-preview a[href^="javascript"], .source-preview img').length`), 0);
  }

  // Compare with the recorded parent attempt from the source browser.
  await cdp.call('Page.navigate', { url: `${browserOrigin}${head}/sources/root` }, tab.sessionId);
  await ready(tab, `(${listing}).length === 5`, 'root before comparison');
  await activate(cdp, ready, tab, 'a', 'Compare with another revision');
  await ready(tab, `document.querySelector('main select')?.value === 'run_source_a/revision_source_a'`, 'parent revision suggestion');
  await activate(cdp, ready, tab, 'button', 'Compare revisions');
  const entries = `[...document.querySelectorAll('ul.source-diff-entries > li')].map(entry => entry.dataset.diffStatus + ':' + entry.querySelector('bdi:last-of-type').textContent)`;
  await ready(tab, `(${entries}).length === 5`, 'changed file list');
  assert.deepEqual(await evaluate(tab, entries), ['modified:Makefile', 'modified:reports/confidence.json', 'modified:src/modules/core.c',
    'added:src/modules/fresh.c', 'removed:src/modules/old.c']);
  assert.ok(await evaluate(tab, `document.body.innerText.includes('5 changed files: 1 added, 1 removed, 3 modified, 0 renamed. 3 unchanged files are not listed.')`));
  assert.equal(await evaluate(tab, 'location.search'), '?baseRunId=run_source_a&baseRevisionId=revision_source_a');
  await activate(cdp, ready, tab, 'a', 'Compare src/modules/core.c');
  await ready(tab, `document.querySelectorAll('.source-diff-row').length > 0`, 'file hunks');
  assert.deepEqual(await evaluate(tab, `[...document.querySelectorAll('.source-diff-removed pre, .source-diff-added pre')].map(row => row.textContent.trim())`),
    ['removed int original_line(void) { return 1; }', 'added int changed_line(void) { return 2; }']);
  assert.ok(await evaluate(tab, `document.body.innerText.includes('16 unchanged lines omitted.') && document.body.innerText.includes('7 unchanged lines omitted at the end of the file.')`));
  const patchHref = await evaluate(tab, `[...document.querySelectorAll('a[download]')].find(a => a.textContent === 'Download the complete unified diff').getAttribute('href')`);
  const patch = await evaluate(tab, `fetch(${JSON.stringify(patchHref)}, { headers: { Accept: 'application/octet-stream' } }).then(async r => ({ status: r.status, type: r.headers.get('content-type'), disposition: r.headers.get('content-disposition'), text: await r.text() }))`);
  assert.equal(patch.status, 200);
  assert.equal(patch.type, 'application/octet-stream');
  assert.match(patch.disposition, /^attachment;/);
  assert.ok(patch.text.startsWith('--- a/src/modules/core.c\t\n+++ b/src/modules/core.c\t\n@@ -17,7 +17,7 @@\n'), patch.text.slice(0, 120));
  await cdp.call('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false }, tab.sessionId);
  assert.ok(await evaluate(tab, `document.documentElement.scrollWidth <= document.documentElement.clientWidth`), 'File comparison must fit 320 px');
  await cdp.call('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false }, tab.sessionId);
  // The base side opens the exact historical file, pinned to the compared commitments.
  await activate(cdp, ready, tab, 'a', 'Open the base file');
  await ready(tab, `!!document.querySelector('h2 bdi') && document.querySelector('h2 bdi').textContent === 'src/modules/core.c'`, 'historical base file');
  assert.match(await evaluate(tab, 'location.pathname + location.search'), new RegExp(`/runs/run_source_a/revisions/revision_source_a/source-files/file_\\d+_[a-f0-9]{64}\\?sourceSha256=${fixture.candidates.run_source_a.sourceSha256}&metadataVersion=[a-f0-9]{64}$`));
  await activate(cdp, ready, tab, 'button', 'Open source preview');
  await ready(tab, `!!document.querySelector('[aria-label="Source range content"]')`, 'historical preview');
  assert.ok(await evaluate(tab, `document.querySelector('[aria-label="Source range content"]').textContent.includes('original_line')`));
  assert.ok(tab.requests.every((request) => ['GET', 'HEAD'].includes(request.method)), 'Source browsing must not mutate');
  assert.deepEqual(tab.exceptions, []);
  return { directoryKeyboardNavigation: true, opaqueLinks: true, manifestOnlyEntries: ['reports/confidence.json', 'UNRESOLVED.md'],
    emptyDirectoriesExplained: true, markupInert: true, lineLinkReload: true, hexFallback: 'invalid-utf8',
    workerAsset: workerAsset.path, workerExitedAfterAnswer: true, workerTerminatedOnLeave: true,
    diff: { statuses: 5, parentSuggested: true, patchDownload: true, narrowViewport: 320, historicalBase: true }, mutationRequests: 0 };
}
