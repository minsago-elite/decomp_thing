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

const CRC = Array.from({ length: 256 }, (_, n) => {
  let value = n;
  for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});
function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) value = CRC[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}
/** One stored entry: a well-formed ZIP whose payload is not this tree, so the real verifier must refuse it. */
function storedZip(name, content) {
  const fileName = Buffer.from(name); const data = Buffer.from(content); const crc = crc32(data);
  const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(fileName.length, 26);
  const central = Buffer.alloc(46); central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6);
  central.writeUInt32LE(crc, 16); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(fileName.length, 28);
  const centralOffset = local.length + fileName.length + data.length;
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10);
  end.writeUInt32LE(central.length + fileName.length, 12); end.writeUInt32LE(centralOffset, 16);
  return Buffer.concat([local, fileName, data, central, fileName, end]);
}

const UNICODE_LINE = '/* Ünïcode: café Café CAFÉ 日本語 */';
// One more marker than the 50-result page limit, so one search stops at result-limit and needs one continuation.
const PAGE_MARKER = 'Qx7';
const PAGE_LINE = `/* ${Array(51).fill(PAGE_MARKER).join(' ')} */`;
const core = (changed) => Array.from({ length: 30 }, (_, index) => {
  if (index === 1) return '/* </pre><script>globalThis.__sourceExecuted = true</script> <img src=x onerror="globalThis.__sourceExecuted = true"> */';
  if (index === 4) return 'int core(void) { return DECOMP_VALUE; }';
  // Identical in both trees, so revision comparison is unchanged; the search fixture truth for Unicode text.
  if (index === 9) return UNICODE_LINE;
  if (index === 11) return PAGE_LINE;
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
  // An incomplete archive for the head attempt: present, digest-identified, and never verifiable.
  const archive = storedZip('Makefile', trees.run_source_b.Makefile);
  await fs.writeFile(join(directory, 'reports', 'runs', 'run_source_b', 'source-tree.zip'), archive, { flag: 'wx', mode: 0o600 });
  return { jobId, directory, trees, candidates, archiveSha256: sha256(archive) };
}

async function press(cdp, tab, key = 'Enter') {
  const codes = { Enter: [13, '\r', 'Enter'], Tab: [9, undefined, 'Tab'], ' ': [32, ' ', 'Space'] };
  const [code, text, name] = codes[key];
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', key, code: name, windowsVirtualKeyCode: code, ...(text ? { text } : {}) }, tab.sessionId);
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key, code: name, windowsVirtualKeyCode: code }, tab.sessionId);
}

/**
 * Independent fixture truth for the server search: committed build inputs that decode as UTF-8, matched per line with
 * per-code-point upper-then-lower folding and identifier boundaries for symbols. Returns [path, line, column, match].
 */
export function expectedSearch(files, { q, match = 'text', caseSensitive = true, path = null }) {
  const fold = (value) => [...value].map((c) => c.toUpperCase().length === 1 ? c.toUpperCase().toLowerCase() : c).join('');
  const word = (c) => c !== undefined && /[A-Za-z0-9_]/u.test(c);
  const needle = [...(caseSensitive ? q : fold(q))];
  const results = []; let unsearchable = 0; let searchable = 0;
  for (const name of Object.keys(files).sort()) {
    if (!ROLES[role(name)].includes('build-input')) continue;
    if (path !== null && !(caseSensitive ? name : fold(name)).includes(caseSensitive ? path : fold(path))) continue;
    searchable++;
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(files[name])); } catch { unsearchable++; continue; }
    text.split('\n').forEach((line, index) => {
      const points = [...line];
      for (let start = 0; start + needle.length <= points.length;) {
        const window = points.slice(start, start + needle.length);
        const hit = window.every((c, i) => (caseSensitive ? c : fold(c)) === needle[i])
          && (match === 'text' || (!word(points[start - 1]) && !word(points[start + needle.length])));
        if (hit) { results.push([name, index + 1, start + 1, window.join('')]); start += needle.length; } else start++;
      }
    });
  }
  return { results, searchable, unsearchable };
}

const SEARCH_CAPTURE_LIMIT = 4;
const decodeBody = (response) => response.base64Encoded ? Buffer.from(response.body, 'base64').toString('utf8') : response.body;

/**
 * Response-stage capture of the source-search route for one submitted search on one target (#1977). The page
 * consumes the search page and Chrome may evict the body afterwards, so it is read while paused at response stage.
 * Every paused response is continued unchanged exactly once; the handler never fulfils, fails, retries or
 * refetches. Only an exact same-origin Fetch/XHR GET of the route with a 200 response is eligible. Events that
 * arrive after release begins are still continued but never captured.
 */
export function searchCapture(cdp, sessionId, browserOrigin, searchPath) {
  const origin = new URL(browserOrigin).origin;
  const captures = new Map();
  const inflight = new Set();
  let state = 'capturing', overflow = false, late = 0;
  cdp.on('Fetch.requestPaused', (event) => {
    if (state === 'released') return;
    const capturing = state === 'capturing';
    const handled = (async () => {
      let value = null;
      try {
        if (!capturing) { late++; return; }
        let url = null;
        try { url = new URL(event.request.url); } catch { url = null; }
        if (url === null || url.origin !== origin || url.pathname !== searchPath) return;
        const networkId = event.networkId;
        if (typeof networkId !== 'string' || captures.has(networkId)) {
          if (typeof networkId === 'string') captures.get(networkId).duplicate = true;
          else overflow = true;
          return;
        }
        if (captures.size >= SEARCH_CAPTURE_LIMIT) { overflow = true; return; }
        value = { url, eligible: event.request.method === 'GET' && ['Fetch', 'XHR'].includes(event.resourceType)
          && event.responseStatusCode === 200 && event.responseErrorReason === undefined,
        body: null, text: null, continued: false, duplicate: false };
        captures.set(networkId, value);
        if (!value.eligible) return;
        try { value.body = cdp.call('Fetch.getResponseBody', { requestId: event.requestId }, sessionId); }
        catch (error) { value.body = Promise.reject(error); }
        value.body.catch(() => {});
        value.text = decodeBody(await value.body);
      } catch { /* The bound read keeps its original error in value.body. */ }
      finally {
        try { await cdp.call('Fetch.continueResponse', { requestId: event.requestId }, sessionId); if (value) value.continued = true; }
        catch { /* A failed continuation leaves the capture ineligible. */ }
      }
    })();
    inflight.add(handled);
  }, sessionId);
  return {
    /** Stops capturing, continues every paused response and stops interception, including after a failure. */
    async release() {
      if (state === 'released') return;
      state = 'closing';
      try {
        await Promise.allSettled(inflight);
        await cdp.call('Fetch.disable', {}, sessionId);
      } finally {
        await Promise.allSettled(inflight);
        state = 'released';
      }
    },
    /**
     * Returns the decoded envelope of the one selected search response. The capture must be the only one in the
     * window, bound to the selecting response's network id, and its URL must carry exactly the expected query.
     */
    async bodyFor(networkId, expectedQuery) {
      assert.equal(state, 'released', 'Search capture must be released before it is read');
      assert.ok(!overflow, 'Source search capture overflowed');
      assert.equal(late, 0, 'A search response paused after capture closed');
      const bound = captures.get(networkId);
      assert.ok(bound, 'Missing response-stage capture of the selected source search response');
      assert.equal(captures.size, 1, 'Ambiguous source search captures: the submission produced more than one response');
      assert.ok(bound.eligible && !bound.duplicate, 'Selected source search capture is not one exact Fetch/XHR GET 200 response');
      await bound.body;
      assert.ok(bound.continued && typeof bound.text === 'string', 'Selected source search response was not continued unchanged');
      const actual = [...bound.url.searchParams].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
      const expected = Object.entries(expectedQuery).filter(([, v]) => v !== null && v !== undefined).map(([k, v]) => [k, String(v)])
        .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
      assert.deepEqual(actual, expected, 'Captured search request query differs from the submitted search');
      const envelope = JSON.parse(bound.text);
      return envelope.data ?? envelope;
    },
  };
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

  // Search the retained head revision from its normal Sources entry point, compared with independent fixture truth.
  const workersBeforeSearch = workers.attached.length;
  const requestsBeforeSearch = tab.requests.length;
  const searchRoute = `/nested/api/v1/jobs/${fixture.jobId}/runs/run_source_b/revisions/revision_source_b/source-search`;
  const searchState = `document.querySelector('.source-search-status')`;
  const searches = [];
  // The shared request log drops query strings; keep full search URLs to prove continuation cursor linkage.
  const searchUrls = new Map();
  cdp.on('Network.requestWillBeSent', (event) => {
    if (event.request.url.split('?')[0].endsWith(searchRoute)) searchUrls.set(event.requestId, new URL(event.request.url));
  }, tab.sessionId);
  // #1977: Chrome can evict a consumed search body before Network.getResponseBody, so each submission's one
  // original response is read at Fetch response stage. Interception spans only that submission.
  const submitCaptured = async (submit) => {
    const capture = searchCapture(cdp, tab.sessionId, browserOrigin, searchRoute);
    let submitted = false;
    try {
      await cdp.call('Fetch.enable', { patterns: ['Fetch', 'XHR'].map((resourceType) =>
        ({ urlPattern: `${new URL(browserOrigin).origin}${searchRoute}*`, resourceType, requestStage: 'Response' })) }, tab.sessionId);
      await submit();
      submitted = true;
    } finally {
      // Release never replaces an earlier failure.
      await capture.release().catch((error) => { if (submitted) throw error; });
    }
    return capture;
  };
  const shownSearch = () => evaluate(tab, `({ state: ${searchState}.dataset.searchState, complete: ${searchState}.classList.contains('source-search-status-complete'),
    text: document.querySelector('#source-search-results')?.closest('section')?.innerText ?? ${searchState}.innerText, status: ${searchState}.innerText,
    links: [...document.querySelectorAll('ol.source-search-results > li > a')].map(a => [a.getAttribute('aria-label'), a.getAttribute('href')]),
    marks: [...document.querySelectorAll('ol.source-search-results mark')].map(m => m.textContent),
    buttons: Object.fromEntries([...document.querySelectorAll('nav[aria-label="Search results"] button')].map(b => [b.textContent.trim(), b.disabled])) })`);
  const runSearch = async ({ q, match = 'text', caseSensitive = true, path = null }, label, expectStatus = 'complete') => {
    await ready(tab, `!!document.querySelector('form[role="search"] input[name="q"]') && !document.querySelector('form[role="search"] button[type="submit"]').disabled`, `${label} form`);
    // Start from the defaults (text, exact case, no path) so every option below is set by the keyboard.
    assert.deepEqual(await evaluate(tab, `(() => { const f = document.querySelector('form[role="search"]');
      return [f.q.value, f.querySelector('input[name="match"]:checked').parentElement.textContent.trim(), f.case.checked, f.path.value]; })()`),
    ['', 'Literal text anywhere in a line', true, ''], `${label} starts from the default form`);
    const focus = async (selector) => ready(tab, `(() => { const e = document.querySelector(${JSON.stringify(selector)}); e.focus(); return document.activeElement === e; })()`, `${label} ${selector}`);
    if (match === 'symbol') { await focus('form[role="search"] input[name="match"]:not(:checked)'); await press(cdp, tab, ' '); }
    if (!caseSensitive) { await focus('form[role="search"] input[name="case"]'); await press(cdp, tab, ' '); }
    if (path !== null) { await focus('form[role="search"] input[name="path"]'); await cdp.call('Input.insertText', { text: path }, tab.sessionId); }
    await focus('form[role="search"] input[name="q"]');
    await cdp.call('Input.insertText', { text: q }, tab.sessionId);
    const before = tab.responses.length;
    const capture = await submitCaptured(async () => {
      await press(cdp, tab);
      await ready(tab, `!!${searchState} && document.activeElement?.id === 'source-search-results'`, `${label} results`);
    });
    const query = new URLSearchParams(await evaluate(tab, 'location.search'));
    assert.deepEqual([query.get('q'), query.get('match') ?? 'text', query.get('case') ?? 'sensitive', query.get('path')],
      [q, match, caseSensitive ? 'sensitive' : 'insensitive', path], `${label} canonical document query`);
    const responses = tab.responses.slice(before).filter((response) => response.url.endsWith(searchRoute));
    assert.equal(responses.length, 1, `${label} must read exactly one retained search page`);
    assert.equal(responses[0].status, 200);
    const api = await capture.bodyFor(responses[0].requestId, { q, match: match === 'text' ? null : match,
      case: caseSensitive ? null : 'insensitive', path, limit: 50 });
    const truth = expectedSearch(fixture.trees.run_source_b, { q, match, caseSensitive, path });
    assert.deepEqual([api.binding.runId, api.binding.revisionId, api.sourceSha256], ['run_source_b', 'revision_source_b', fixture.candidates.run_source_b.sourceSha256]);
    assert.deepEqual([api.query.text, api.query.match, api.query.caseSensitive, api.query.path], [q, match, caseSensitive, path]);
    assert.equal(api.status, expectStatus, `${label} page status`);
    assert.equal(api.page.nextCursor === null, expectStatus === 'complete');
    // A partial first page must be the exact leading run of fixture truth; the continuation checks the rest.
    const expected = expectStatus === 'complete' ? truth.results : truth.results.slice(0, api.items.length);
    assert.deepEqual(api.items.map((item) => [item.displayName, Number(item.line), Number(item.column), item.match]), expected, `${label} fixture truth`);
    assert.deepEqual([api.scope.searchableFiles, api.coverageGaps.unsearchableText, api.coverageGaps.unavailableFiles], [truth.searchable, truth.unsearchable, 0]);
    for (const item of api.items) assert.equal(item.sha256, sha256(Buffer.from(fixture.trees.run_source_b[item.displayName])));
    const shown = await shownSearch();
    shown.text = shown.status;
    assert.deepEqual(shown.links.map(([name]) => name), expected.map(([file, line]) => `Open ${file} at line ${line}`));
    assert.deepEqual(shown.marks, expected.map((result) => result[3]));
    assert.ok(shown.links.every(([, href]) => href.startsWith(`${head}/source-files/`) && href.includes(`sourceSha256=${api.sourceSha256}`)
      && href.includes(`metadataVersion=${api.metadataVersion}`)), `${label} result links stay on the searched revision`);
    searches.push({ label, query: { q, match, caseSensitive, path }, matches: api.items.length, state: shown.state, coverageComplete: shown.complete,
      stopReason: api.stopReason, searchableFiles: api.scope.searchableFiles, unsearchableText: api.coverageGaps.unsearchableText, scannedBytes: Number(api.progress.scannedBytes) });
    return { api, shown, truth, requestId: responses[0].requestId };
  };
  await cdp.call('Page.navigate', { url: `${browserOrigin}${head}/sources/root` }, tab.sessionId);
  await ready(tab, `(${listing}).length === 5`, 'root before search');
  await activate(cdp, ready, tab, 'a', 'Search these recorded inputs');
  await ready(tab, `location.pathname === ${JSON.stringify(`${head}/source-search`)}`, 'search entry point');
  const bareSearch = async (label) => {
    await cdp.call('Page.navigate', { url: `${browserOrigin}${head}/source-search` }, tab.sessionId);
    await ready(tab, `!!document.querySelector('form[role="search"]')`, `${label} entry`);
  };
  // Unicode text, letter case folded: all three spellings in core.c, while the invalid UTF-8 input is a named coverage gap.
  let result = await runSearch({ q: 'café', caseSensitive: false }, 'unicode-insensitive');
  assert.equal(result.api.items.length, 3);
  assert.equal(result.shown.state, 'complete');
  assert.equal(result.shown.complete, false, 'An unreadable file must keep the status visibly incomplete');
  assert.ok(result.shown.text.includes('Showing 3 matches on this page.') && result.shown.text.includes('Coverage is incomplete: 1 files in scope were not searched.'), result.shown.text);
  // Exact case and a path filter narrow to one exact spelling with full coverage.
  await bareSearch('unicode-exact');
  result = await runSearch({ q: 'café', path: 'core' }, 'unicode-exact-path');
  assert.equal(result.api.items.length, 1);
  assert.deepEqual([result.shown.state, result.shown.complete], ['complete', true]);
  // The path filter follows the same case rule: CORE finds nothing case-sensitively and core.c when folded.
  await bareSearch('path-case-sensitive');
  result = await runSearch({ q: '日本語', path: 'CORE' }, 'path-case-sensitive');
  assert.deepEqual([result.api.items.length, result.api.scope.searchableFiles, result.shown.state], [0, 0, 'no-matches']);
  assert.ok(result.shown.text.includes('No file in this scope can be searched.'), result.shown.text);
  await bareSearch('path-case-insensitive');
  result = await runSearch({ q: '日本語', caseSensitive: false, path: 'CORE' }, 'path-case-insensitive');
  assert.equal(result.api.items.length, 1);
  // Symbol mode matches whole identifiers only; the text literal also matches the identifier prefix.
  await bareSearch('symbol');
  result = await runSearch({ q: 'DECOMP_VALUE', match: 'symbol' }, 'symbol');
  assert.deepEqual(result.api.items.map((item) => item.displayName), ['include/decomp_types.h', 'src/modules/core.c']);
  await bareSearch('symbol-prefix');
  result = await runSearch({ q: 'DECOMP', match: 'symbol' }, 'symbol-prefix-gap');
  // No matches with a coverage gap stays visibly distinct from a fully covered no-match.
  assert.deepEqual([result.api.items.length, result.shown.state, result.shown.complete], [0, 'no-matches', false]);
  assert.ok(result.shown.text.includes(`No matches in the ${result.truth.searchable - result.truth.unsearchable} files that could be searched.`) && result.shown.text.includes('Coverage is incomplete'), result.shown.text);
  await bareSearch('symbol-prefix-covered');
  result = await runSearch({ q: 'DECOMP', match: 'symbol', path: 'core.c' }, 'symbol-prefix-covered');
  assert.deepEqual([result.api.items.length, result.shown.state, result.shown.complete], [0, 'no-matches', true]);
  assert.ok(result.shown.text.includes('No matches in the 1 searchable files in scope.'), result.shown.text);
  await bareSearch('text-prefix');
  result = await runSearch({ q: 'DECOMP', path: 'core.c' }, 'text-prefix');
  assert.equal(result.api.items.length, 1);
  // Result limit: 51 markers on one line stop the first page at 50; Continue search (keyboard) reads exactly the last one.
  await bareSearch('result-limit');
  result = await runSearch({ q: PAGE_MARKER, path: 'core.c' }, 'result-limit', 'partial');
  const first = result.api;
  assert.equal(result.truth.results.length, 51);
  assert.deepEqual([first.stopReason, first.items.length, first.limits.maxResults, first.page.limit], ['result-limit', 50, 50, 50]);
  assert.equal(searchUrls.get(result.requestId).searchParams.get('cursor'), null, 'The first page carries no cursor');
  assert.equal(result.shown.state, 'partial');
  assert.ok(result.shown.text.includes('It reached the result limit for this page.') && result.shown.text.includes('more matches may exist'), result.shown.text);
  assert.deepEqual(result.shown.buttons, { 'Start search over': true, 'Continue search': false });
  const beforeContinue = tab.responses.length;
  const continueCapture = await submitCaptured(async () => {
    await activate(cdp, ready, tab, 'nav[aria-label="Search results"] button', 'Continue search');
    await ready(tab, `new URLSearchParams(location.search).get('cursor') === ${JSON.stringify(first.page.nextCursor)} && ${searchState}?.dataset.searchState === 'complete'`, 'continued page');
  });
  const continued = tab.responses.slice(beforeContinue).filter((response) => response.url.endsWith(searchRoute));
  assert.equal(continued.length, 1, 'Continue search must read exactly one further page');
  assert.equal(continued[0].status, 200);
  const continuedUrl = searchUrls.get(continued[0].requestId);
  assert.deepEqual([continuedUrl.searchParams.get('cursor'), continuedUrl.searchParams.get('q'), continuedUrl.searchParams.get('path')],
    [first.page.nextCursor, PAGE_MARKER, 'core.c'], 'The continuation request carries the first page cursor and the same query');
  const second = await continueCapture.bodyFor(continued[0].requestId, { ...Object.fromEntries(searchUrls.get(result.requestId).searchParams),
    cursor: first.page.nextCursor });
  assert.deepEqual([second.binding.revisionId, second.sourceSha256, second.metadataVersion, second.query.text, second.query.path],
    ['revision_source_b', first.sourceSha256, first.metadataVersion, PAGE_MARKER, 'core.c']);
  assert.deepEqual([second.status, second.stopReason, second.page.nextCursor, second.items.length], ['complete', null, null, 1]);
  assert.ok(second.page.currentCursor === undefined || second.page.currentCursor === first.page.nextCursor, "The continued page reports the cursor it was read with");
  const pages = [...first.items, ...second.items];
  assert.deepEqual(pages.map((item) => [item.displayName, Number(item.line), Number(item.column), item.match]), result.truth.results,
    'Both pages reconstruct fixture truth exactly');
  assert.equal(new Set(pages.map((item) => `${item.fileId}/${item.offsetBytes}`)).size, 51, 'No match repeats across pages');
  const pageShown = await shownSearch();
  assert.equal(pageShown.state, 'complete');
  assert.ok(pageShown.status.includes('Showing 1 matches on this page.') && pageShown.text.includes('This is a continued search page.'), pageShown.text);
  assert.deepEqual(pageShown.marks, [PAGE_MARKER]);
  assert.deepEqual(pageShown.links.map(([name]) => name), ['Open src/modules/core.c at line 12']);
  assert.deepEqual(pageShown.buttons, { 'Start search over': false, 'Continue search': true });
  const continuation = { firstPage: 50, stopReason: first.stopReason, continuedPage: second.items.length, terminal: pageShown.state,
    cursorLinked: true, reconstructed: pages.length, duplicates: 0 };
  // The selected result opens the same revision, file and line, and that line holds the matched Unicode text.
  await bareSearch('open-result');
  result = await runSearch({ q: 'CAFÉ', path: 'core' }, 'open-result');
  const [selectedItem] = result.api.items;
  assert.deepEqual([selectedItem.displayName, selectedItem.line, selectedItem.column], ['src/modules/core.c', '10', String([...UNICODE_LINE.slice(0, UNICODE_LINE.indexOf('CAFÉ'))].length + 1)]);
  await activate(cdp, ready, tab, 'ol.source-search-results a', 'Open src/modules/core.c at line 10');
  await ready(tab, `!!document.querySelector('[aria-label="Source range content"]') && document.querySelector('.source-row a')?.textContent === '10'`, 'search result line');
  const opened = new URL(await evaluate(tab, 'location.href'));
  assert.equal(opened.pathname, `${head}/source-files/${selectedItem.fileId}`);
  assert.deepEqual([opened.searchParams.get('sourceSha256'), opened.searchParams.get('metadataVersion'), opened.searchParams.get('line'), opened.searchParams.get('byte')],
    [result.api.sourceSha256, result.api.metadataVersion, '10', selectedItem.lineOffsetBytes]);
  assert.equal(Number(selectedItem.lineOffsetBytes), Buffer.byteLength(fixture.trees.run_source_b['src/modules/core.c'].split('\n').slice(0, 9).join('\n') + '\n'));
  assert.equal(await evaluate(tab, `document.querySelector('h2 bdi').textContent`), 'src/modules/core.c');
  assert.ok(await evaluate(tab, `document.querySelector('[aria-label="Source range content"]').textContent.includes(${JSON.stringify(UNICODE_LINE)})`));
  const searchRequests = tab.requests.slice(requestsBeforeSearch);
  assert.ok(searchRequests.every((request) => ['GET', 'HEAD'].includes(request.method)), 'Source search must not mutate');
  const searchApiPaths = [...new Set(searchRequests.filter((request) => request.url.includes('/nested/api/')).map((request) => new URL(request.url).pathname))];
  assert.deepEqual(searchApiPaths.filter((path) => /agent|worker|execut|attempt|patch|archive-verif/i.test(path)), [], 'Source search must not reach execution routes');
  assert.equal(workers.attached.length, workersBeforeSearch, 'Source search must not start a worker');

  // The archive panel identifies the archive before download and only an explicit operation can label it.
  await cdp.call('Page.navigate', { url: `${browserOrigin}${head}/sources/root` }, tab.sessionId);
  await ready(tab, `(${listing}).length === 5`, 'root before archive status');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('It is not the application JAR that runs this workbench.')`));
  assert.equal(tab.requests.filter((request) => request.url.endsWith('/source-archive')).length, 0, 'Archive status must wait for an explicit action');
  await activate(cdp, ready, tab, 'button', 'Show source archive status');
  await ready(tab, `document.querySelector('[data-archive-state]')?.dataset.archiveState === 'not-verified'`, 'unverified archive status');
  assert.ok(await evaluate(tab, `document.querySelector('[aria-label="Source archive identity"]').textContent.includes(${JSON.stringify(fixture.archiveSha256)})`));
  assert.ok(await evaluate(tab, `[...document.querySelectorAll('a[download]')].some(a => a.textContent === 'Download the source archive (ZIP, not verified)')`));
  await activate(cdp, ready, tab, 'button', 'Verify archive integrity');
  await ready(tab, `document.querySelector('[data-archive-state]')?.dataset.archiveState === 'failed'`, 'refused archive verification', 40_000);
  assert.ok(await evaluate(tab, `document.activeElement?.dataset.archiveState === 'failed'`), 'Focus must move to the new verification result');
  assert.equal(await evaluate(tab, `[...document.querySelectorAll('a[download]')].some(a => a.textContent.startsWith('Download the verified'))`), false);
  const mutations = tab.requests.filter((request) => !['GET', 'HEAD'].includes(request.method));
  assert.deepEqual(mutations.map((request) => [request.method, new URL(request.url).pathname]),
    [['POST', `/nested/api/v1/jobs/${fixture.jobId}/runs/run_source_b/revisions/revision_source_b/archive-verifications`]]);
  assert.deepEqual(tab.exceptions, []);
  return { directoryKeyboardNavigation: true, opaqueLinks: true, manifestOnlyEntries: ['reports/confidence.json', 'UNRESOLVED.md'],
    emptyDirectoriesExplained: true, markupInert: true, lineLinkReload: true, hexFallback: 'invalid-utf8',
    workerAsset: workerAsset.path, workerExitedAfterAnswer: true, workerTerminatedOnLeave: true,
    diff: { statuses: 5, parentSuggested: true, patchDownload: true, narrowViewport: 320, historicalBase: true },
    archive: { explicitStatusRead: true, digestShown: true, verification: 'failed', verifiedLabelWithheld: true }, mutationRequests: 1,
    search: { entryPoint: 'Search these recorded inputs', searches, apiPaths: searchApiPaths, resultLink: { fileId: selectedItem.fileId, line: 10, sameRevision: true }, continuation, workersStarted: 0, mutations: 0 } };
}
