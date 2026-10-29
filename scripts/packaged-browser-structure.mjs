import assert from 'node:assert/strict';
import { promises as fs, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

// Kept current by WebProgramStructureTest; the seed writes manifests without the JVM profile registry.
const pins = JSON.parse(readFileSync(new URL('./packaged-browser-structure-profile.json', import.meta.url), 'utf8'));
const FUNCTIONS = 100000;
const PER_MODULE = 24;
const OWNED = FUNCTIONS - 1; // The last function is deliberately owned by no module.
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hex = (value) => value.toString(16);
const functionAddress = (index) => 0x400000 + index * 16;
const functionId = (index) => `fn_${hex(functionAddress(index)).padStart(16, '0')}`;
const moduleId = (index) => `module_${String(index).padStart(4, '0')}`;
const globalId = (index) => `global_${hex(0x600000 + index * 8).padStart(16, '0')}`;
const typeId = (index) => `type_${sha(`synthetic-type:${index}`)}`;
const roles = (path) => {
  const template = path.replace(/^src\/modules\/[^/]+\.c$/, 'src/modules/{module}.c').replace(/^include\/modules\/[^/]+\.h$/, 'include/modules/{module}.h');
  const value = pins.declarations[template];
  assert.ok(value, `No pinned profile declaration for ${path}`);
  return value;
};

/** The exact canonical module-plan bytes of ModulePlan.toJson for plain ASCII identities. */
function canonicalPlan(modules) {
  const list = (values) => values.map((value) => JSON.stringify(value)).join(', ');
  const blocks = modules.map((module) => [
    '    {',
    `      "id": ${JSON.stringify(module.id)},`,
    `      "sourcePath": ${JSON.stringify(module.sourcePath)},`,
    `      "headerPath": ${JSON.stringify(module.headerPath)},`,
    `      "functionIds": [${list(module.functionIds)}],`,
    `      "globalIds": [${list(module.globalIds)}],`,
    `      "typeIds": [${list(module.typeIds)}],`,
    `      "boundaryEvidence": [${list(module.boundaryEvidence)}]`,
    '    }'].join('\n'));
  return `{\n  "schemaVersion": 2,\n  "modules": [${blocks.join(',')}\n  ],\n  "dependencyCycles": []\n}\n`;
}

/** Test-only persisted revision written before server ownership; no workflow, compiler or model runs. */
export async function seedStructure(root) {
  await fs.mkdir(root, { mode: 0o700 });
  const jobId = 'f'.repeat(32), runId = 'run_structure_scale', revisionId = 'revision_structure_scale';
  const directory = join(root, jobId);
  await fs.mkdir(directory, { mode: 0o700 });
  const input = Buffer.alloc(64);
  input.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  input.writeUInt16LE(2, 16); input.writeUInt16LE(62, 18); input.writeUInt32LE(1, 20); input.writeUInt16LE(64, 52);
  const at = new Date(Date.now() - 300_000).toISOString();
  const job = { id: jobId, filename: 'synthetic-structure.elf', status: 'uploaded', created_at: at, updated_at: at,
    size_bytes: 64, binary_path: join(directory, 'input.elf'), metadata: { format: 'ELF64', endianness: 'little',
      elf_version: 1, os_abi: 'System V', object_type: 'executable', machine: 'x86-64', entry_point: 0,
      elf_header_size: 64, program_header_count: 0, section_header_count: 0, section_name_table_index: 0 } };
  const jobBytes = JSON.stringify(job);

  const functions = Array.from({ length: FUNCTIONS }, (_, index) => JSON.stringify({
    id: functionId(index), name: `synthetic_function_${index}`, address: `0x${hex(functionAddress(index))}`,
    prototype: `void synthetic_function_${index}(void)`,
    extractionStatus: index % 101 === 0 ? 'failed' : index % 17 === 0 ? 'partial' : 'recovered', recoveryAssessment: 'unassessed',
    calls: [functionId((index + 1) % FUNCTIONS)], referencedGlobals: index % 1000 === 0 ? [globalId(index / 1000 % 100)] : [],
    strings: [], decompiledC: index % 1000 === 0 ? `void synthetic_function_${index}(void) {\n${'  /* synthetic */\n'.repeat(400)}}` : null,
  }));
  const globals = Array.from({ length: 100 }, (_, index) => JSON.stringify({
    id: globalId(index), name: index === 0 ? 'synthetic_function_0' : `synthetic_global_${index}`, address: `0x${hex(0x600000 + index * 8)}`,
    type: 'int', initializer: null, extractionStatus: 'recovered', recoveryAssessment: 'unassessed' }));
  const types = Array.from({ length: 10 }, (_, index) => JSON.stringify({
    id: typeId(index), declaration: `struct synthetic_${index} { int value; };`, sourceAddress: null,
    extractionStatus: 'recovered', recoveryAssessment: 'unassessed' }));
  const model = `{"schemaVersion":2,"inputSha256":"${sha(input)}","functions":[${functions.join(',')}],"globals":[${globals.join(',')}],"types":[${types.join(',')}]}`;
  const modules = Array.from({ length: Math.ceil(OWNED / PER_MODULE) }, (_, index) => ({
    id: moduleId(index), sourcePath: `src/modules/${moduleId(index)}.c`, headerPath: `include/modules/${moduleId(index)}.h`,
    functionIds: Array.from({ length: Math.min(PER_MODULE, OWNED - index * PER_MODULE) }, (_, offset) => functionId(index * PER_MODULE + offset)),
    globalIds: index === 0 ? Array.from({ length: 100 }, (_, offset) => globalId(offset)) : [],
    typeIds: index === 0 ? Array.from({ length: 10 }, (_, offset) => typeId(offset)).sort() : [],
    boundaryEvidence: [],
  }));
  const files = new Map([
    ['Makefile', 'all:\n\t@true\n'],
    ['include/decomp_types.h', '#pragma once\n'],
    ['reports/program_model.json', model],
    ['reports/module_plan.json', canonicalPlan(modules)],
  ]);
  for (const module of modules) {
    files.set(module.sourcePath, `/* ${module.id}: synthetic recorded source */\n#include "../../include/modules/${module.id}.h"\n`);
    files.set(module.headerPath, `#pragma once\n/* ${module.id} */\n`);
  }
  const entries = [...files.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([path, text]) => ({ path, bytes: Buffer.from(text), roles: roles(path) }));
  const manifest = { schemaVersion: 3, profileId: pins.profileId, profileSha256: pins.profileSha256, inputSha256: sha(input),
    files: entries.map(({ path, bytes, roles: declared }) => ({ path, sha256: sha(bytes), generator: 'synthetic-structure-seed',
      promptSha256: null, acceptedImplementation: declared.includes('module-implementation') ? path.endsWith('0.c') : null,
      contentKind: 'utf8-text', roles: declared, entityIds: [] })),
    unresolvedEntityIds: [], unresolvedImplementationIds: [functionId(1)] };
  const inputs = entries.filter((entry) => entry.roles.includes('build-input'));
  const sourceSha256 = sha(inputs.map(({ path, bytes }) => `${path.length}:${path}:${bytes.length}:${sha(bytes)}\n`).join(''));
  const contract = { schemaVersion: 3, sourceRevisionSha256: sourceSha256,
    sourceInputs: inputs.map(({ path, bytes }) => ({ path, bytes: bytes.length, sha256: sha(bytes) })) };
  const time = new Date(Date.parse(at) + 1000).toISOString();
  const state = { schemaVersion: 1, jobId, version: `version_${'a'.repeat(32)}`,
    legacy: { originalJobSha256: sha(jobBytes), status: 'uploaded', recoveredInterrupted: false },
    attempts: [{ runId, jobId, workflow: 'reconstruct', state: 'completed', version: `version_${'b'.repeat(32)}`,
      createdAt: time, startedAt: time, endedAt: new Date(Date.parse(time) + 1000).toISOString(),
      previousRunId: null, inputRevisionId: null, harnessCapabilityId: null,
      limits: { wallClockMs: '60000', idleMs: '15000', maxOutputBytes: '1048576', maxToolCalls: '16' },
      terminalReason: 'COMPLETED', usage: null, candidate: { revisionId, sourceSha256 }, acceptedRevision: null }],
    acceptedRevision: null };
  for (const [name, bytes] of Object.entries({ 'input.elf': input, 'job.json': jobBytes, 'workflow-state.json': JSON.stringify(state) })) {
    await fs.writeFile(join(directory, name), bytes, { flag: 'wx', mode: 0o600 });
  }
  const tree = join(directory, 'reports', 'runs', runId, 'source-tree');
  const written = [...entries.map(({ path, bytes }) => [path, bytes]),
    ['source_tree_manifest.json', Buffer.from(JSON.stringify(manifest))], ['reports/build_contract.json', Buffer.from(JSON.stringify(contract))]];
  for (const [path, bytes] of written) {
    await fs.mkdir(dirname(join(tree, path)), { recursive: true, mode: 0o700 });
    await fs.writeFile(join(tree, path), bytes, { flag: 'wx', mode: 0o600 });
  }
  return { jobId, runId, revisionId, functions: FUNCTIONS, modules: modules.length, modelBytes: Buffer.byteLength(model),
    functionAddress, functionId, moduleId };
}

const ROWS = `[...document.querySelectorAll('table[aria-label], table')].filter(table => table.querySelector('caption')?.textContent === 'Recovered functions')
  .flatMap(table => [...table.querySelectorAll('tbody tr')]).map(row => row.querySelector('td code')?.textContent)`;

/** Compare with the originating module response, never with pins read back from the link itself. */
export function assertStructureSourceLink(href, { revision, browserOrigin, snapshot }) {
  assert.equal(typeof href, 'string', 'Missing module implementation link');
  assert.match(snapshot.sourceSha256, /^[a-f0-9]{64}$/);
  assert.match(snapshot.metadataVersion, /^[a-f0-9]{64}$/);
  assert.match(snapshot.module.implementationFileId, /^file_[0-9]+_[a-f0-9]{64}$/);
  const url = new URL(href, browserOrigin);
  assert.equal(url.origin, new URL(browserOrigin).origin);
  assert.equal(url.username, '');
  assert.equal(url.password, '');
  assert.equal(url.hash, '');
  assert.equal(url.pathname, `${revision}/source-files/${snapshot.module.implementationFileId}`);
  assert.deepEqual([...url.searchParams].sort(([a], [b]) => a.localeCompare(b)), [
    ['metadataVersion', snapshot.metadataVersion], ['sourceSha256', snapshot.sourceSha256],
  ], 'Source link must carry exactly the originating source and metadata pins');
}

export async function qualifyStructure({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin }) {
  const tab = await makeTarget();
  await cdp.call('Performance.enable', {}, tab.sessionId);
  const inventoryReads = [];
  const moduleResponses = new Map();
  cdp.on('Network.responseReceived', (event) => {
    const url = new URL(event.response.url);
    if (url.origin === new URL(browserOrigin).origin && event.response.status === 200
      && /\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/modules\/[^/]+$/.test(url.pathname)) {
      moduleResponses.set(url.pathname, event.requestId);
    }
  }, tab.sessionId);
  cdp.on('Network.requestWillBeSent', (event) => {
    const url = new URL(event.request.url);
    if (/\/api\/v1\/jobs\/[^/]+\/runs\/[^/]+\/revisions\/[^/]+\/functions$/.test(url.pathname)) inventoryReads.push(url.searchParams.get('limit'));
  }, tab.sessionId);
  let peakBrowserHeapBytes = 0;
  const heap = async () => {
    const metrics = (await cdp.call('Performance.getMetrics', {}, tab.sessionId)).metrics;
    peakBrowserHeapBytes = Math.max(peakBrowserHeapBytes, metrics.find((metric) => metric.name === 'JSHeapUsedSize').value);
  };
  const enter = async () => {
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
  };
  const run = `/nested/jobs/${fixture.jobId}/runs/${fixture.runId}`;
  const revision = `${run}/revisions/${fixture.revisionId}`;
  const address = (index) => `0x${fixture.functionAddress(index).toString(16)}`;
  await cdp.call('Page.navigate', { url: browserOrigin + run }, tab.sessionId);
  await ready(tab, `[...document.querySelectorAll('a')].some(a => a.textContent === 'Browse recovered functions')`, 'structure links on the result revision');
  let started = performance.now();
  await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'Browse recovered functions').click()`);
  await ready(tab, `(${ROWS}).length === 100 && document.body.innerText.includes('of 100000 matching functions (100000 recorded)')`, 'first page of 100000 recorded functions');
  const firstPageMs = performance.now() - started;
  assert.equal(await evaluate(tab, 'location.pathname'), `${revision}/functions`);
  assert.deepEqual(await evaluate(tab, ROWS), Array.from({ length: 100 }, (_, index) => address(index)));
  await heap();
  const pageMs = [];
  for (let page = 1; page <= 20; page++) {
    await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Next page').focus()`);
    started = performance.now();
    await enter();
    await ready(tab, `(${ROWS})[0] === ${JSON.stringify(address(page * 100))} && document.activeElement?.textContent === 'Function results'`, `function page ${page + 1}`);
    pageMs.push(performance.now() - started);
    assert.equal((await evaluate(tab, ROWS)).length, 100);
    assert.ok(await evaluate(tab, `document.querySelectorAll('tr').length`) <= 500, 'Mounted table rows exceed the D0 DOM budget');
    await heap();
  }
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Showing 2001–2100 of 100000 matching functions')`));
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `(${ROWS})[0] === ${JSON.stringify(address(2000))}`, 'function cursor restored after reload');

  started = performance.now();
  await evaluate(tab, `(() => {
    const field = document.querySelector('input[name="search"]');
    field.value = 'synthetic_function_99999'; field.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Apply filters').click()`);
  await ready(tab, `(${ROWS}).length === 1 && document.body.innerText.includes('Showing 1–1 of 1 matching functions (100000 recorded)')`, 'exact function search across 100000 records');
  const searchMs = performance.now() - started;
  assert.equal(await evaluate(tab, 'location.search'), '?search=synthetic_function_99999');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('No owning module') && document.body.innerText.includes('Excluded')`));
  await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'synthetic_function_99999').click()`);
  await ready(tab, `document.querySelector('main h2')?.textContent === 'synthetic_function_99999' && document.body.innerText.includes('Excluded: the recorded module plan assigns this entity to no module.')`, 'excluded function facts');
  assert.match(await evaluate(tab, 'location.search'), /^\?structureVersion=[a-f0-9]{64}$/);
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Recovery assessment: unassessed')`));
  await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'synthetic_function_99998').click()`);
  await ready(tab, `document.querySelector('main h2')?.textContent === 'synthetic_function_99998'`, 'caller cross-link within the pinned structure version');
  const module = fixture.moduleId(Math.floor(99998 / 24));
  await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === ${JSON.stringify(module)}).click()`);
  await ready(tab, `document.querySelector('main h2')?.textContent === ${JSON.stringify(module)} && document.querySelector('table caption')?.textContent === 'Functions'`, 'owning module detail');
  const owned = Math.min(24, OWNED - Math.floor(99998 / 24) * 24);
  assert.equal(await evaluate(tab, `document.querySelectorAll('table tbody tr').length`), owned);
  const implementation = await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'src/modules/${module}.c')?.getAttribute('href')`);
  const requestId = moduleResponses.get(`/nested/api/v1/jobs/${fixture.jobId}/runs/${fixture.runId}/revisions/${fixture.revisionId}/modules/${module}`);
  assert.ok(requestId, 'Missing originating module detail response');
  // Rendering has completed, so the response body consumed by the UI is available without another API read.
  const response = await cdp.call('Network.getResponseBody', { requestId }, tab.sessionId);
  const snapshot = JSON.parse(response.base64Encoded ? Buffer.from(response.body, 'base64').toString('utf8') : response.body).data;
  assert.equal(snapshot.module.moduleId, module);
  assertStructureSourceLink(implementation, { revision, browserOrigin, snapshot });
  await cdp.call('Page.navigate', { url: browserOrigin + `${revision}/modules` }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Showing 1–100 of ${fixture.modules} modules.') && document.querySelector('table caption')?.textContent === 'Recorded totals'`, 'module inventory with recorded totals');
  assert.ok(await evaluate(tab, `[...document.querySelectorAll('dt')].find(dt => dt.textContent === 'Names shared by several functions or globals')?.nextElementSibling.textContent === '1'`));
  await heap();
  for (const width of [390, 320]) {
    await cdp.call('Emulation.setDeviceMetricsOverride', { width, height: 844, deviceScaleFactor: 1, mobile: false }, tab.sessionId);
    const dimensions = await evaluate(tab, `({ available: document.documentElement.clientWidth, document: document.documentElement.scrollWidth })`);
    assert.ok(dimensions.document <= dimensions.available, `Structure view overflows at ${width}px: ${JSON.stringify(dimensions)}`);
  }
  assert.ok(inventoryReads.length >= 22 && inventoryReads.every((limit) => limit === '100'), 'Every inventory read must request one bounded page');
  assert.deepEqual(tab.exceptions, []);
  assert.ok(tab.requests.every((request) => ['GET', 'HEAD'].includes(request.method)));
  assert.ok(peakBrowserHeapBytes <= 128 * 1024 * 1024, `Browser heap ${peakBrowserHeapBytes} exceeds the D0 budget`);
  pageMs.sort((a, b) => a - b);
  return { recordedFunctions: fixture.functions, modules: fixture.modules, modelBytes: fixture.modelBytes, rowsPerPage: 100,
    pagesVisited: 21, maximumMountedRows: 100, firstPageMs: Math.round(firstPageMs), pageMsP50: Math.round(pageMs[10]),
    pageMsP95: Math.round(pageMs[18]), searchMs: Math.round(searchMs), peakBrowserHeapBytes, cursorReload: true,
    pinnedCrossLinks: true, moduleSourceLink: true, narrowReflow: true, boundedInventoryReads: inventoryReads.length, mutationRequests: 0 };
}
