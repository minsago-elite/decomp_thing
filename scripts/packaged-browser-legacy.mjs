import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join, dirname } from 'node:path';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

export async function seedLegacy(root) {
  await fs.mkdir(root, { mode: 0o700 });
  const id = 'c'.repeat(32);
  const directory = join(root, id);
  const reports = join(directory, 'reports');
  await fs.mkdir(reports, { recursive: true, mode: 0o700 });
  const input = Buffer.alloc(64);
  input.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  await fs.writeFile(join(directory, 'input.elf'), input);
  const job = { id, filename: 'legacy-browser.elf', status: 'uploaded', created_at: '2026-09-05T00:00:00Z',
    updated_at: '2026-09-05T00:00:00Z', status_message: 'PRIVATE_LEGACY_DIAGNOSTIC', size_bytes: 64,
    binary_path: join(directory, 'input.elf'), metadata: { format: 'ELF64', endianness: 'little', elf_version: 1,
      os_abi: 'System V', object_type: 'EXEC', machine: 'x86-64', entry_point: 0, elf_header_size: 64,
      program_header_count: 0, section_header_count: 0, section_name_table_index: 0 } };
  const jobPath = join(directory, 'job.json');
  await fs.writeFile(jobPath, JSON.stringify(job));
  const journalPath = join(reports, 'agent-progress.json');
  const journal = JSON.stringify({ schemaVersion: 1, displayOnly: true, nextSequence: 1, queueDropped: 0,
    historyDropped: 0, truncated: false, events: [{ sequence: 0, kind: 'message', role: 'thought',
      text: 'PRIVATE_LEGACY_PROSE', path: '/PRIVATE_LEGACY_HOST/input', inputTokens: '18446744073709551615' }] });
  await fs.writeFile(journalPath, journal);
  const artifactPath = join(reports, 'fixture.txt');
  await fs.writeFile(artifactPath, 'ordinary artifact');
  const sourceRelative = 'src/modules/fixture.c';
  const source = 'int fixture(void) { return 7; }\n/* </code><script>globalThis.__sourceEscaped = true</script> */\n';
  const sourceTree = join(reports, 'source-tree');
  const sourcePath = join(sourceTree, sourceRelative);
  await fs.mkdir(dirname(sourcePath), { recursive: true, mode: 0o700 });
  await fs.writeFile(sourcePath, source);
  // Deliberately pinned to GeneratedCMakeReconstructionProfile. A profile change
  // must update this packaged fixture instead of silently weakening validation.
  const manifest = { schemaVersion: 3, profileId: 'generated-c-make-v1',
    profileSha256: 'a448a139a09f28ad9f2e08bfcebcb9d85765a0a557ebb11db6d7634bc145f28f',
    inputSha256: sha256(input), files: [{ path: sourceRelative, sha256: sha256(source),
      generator: 'packaged-browser-fixture', promptSha256: null, acceptedImplementation: true,
      contentKind: 'utf8-text', roles: ['archive-payload', 'build-input', 'editable', 'module-implementation', 'viewable'],
      entityIds: ['fn_fixture'] }], unresolvedEntityIds: [], unresolvedImplementationIds: [] };
  const manifestPath = join(sourceTree, 'source_tree_manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify(manifest));
  return { id, directory, reports, input, job, jobPath, journalPath, journal, artifactPath,
    sourceRelative, source, sourcePath, manifestPath };
}

export async function qualifyLegacy({ fixture, origin, bootstrapUrl, tab, cdp, evaluate, ready, makeTarget }) {
  await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
    const original = window.fetch;
    window.fetch = function(input, options) {
      if (String(input) === '/api/v1/session' && options?.method === 'POST' && location.hash) throw new Error('Bootstrap fragment was not cleared');
      return original.apply(this, arguments);
    };
  })();` }, tab.sessionId);
  await cdp.call('Page.navigate', { url: `${origin}/jobs/${fixture.id}` }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Open a local session')`, 'legacy unauthenticated page');
  assert.ok(!await evaluate(tab, `document.body.innerText.includes('legacy-browser.elf')`));
  assert.equal(await evaluate(tab, `fetch('/api/jobs/${fixture.id}').then(r => r.status)`), 401);
  await cdp.call('Page.navigate', { url: bootstrapUrl }, tab.sessionId);
  await ready(tab, `location.pathname === '/' && !!document.querySelector('#binary')`, 'legacy local session');
  assert.equal(await evaluate(tab, 'location.hash'), '');
  assert.equal(await evaluate(tab, 'localStorage.length + sessionStorage.length'), 0);
  // Test-owned state only: emulate an in-progress legacy observation after startup recovery.
  // No workflow is admitted or executed. These fixture writes are not application mutations.
  const activeJob = JSON.stringify({ ...fixture.job, status: 'analyzing' });
  await fs.writeFile(fixture.jobPath, activeJob);
  await cdp.call('Page.navigate', { url: `${origin}/jobs/${fixture.id}` }, tab.sessionId);
  await ready(tab, `document.querySelector('#agent-event-list')?.innerText.includes('18446744073709551615')`, 'legacy initial progress');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Stored diagnostic details are withheld')`));
  assert.ok(await evaluate(tab, `document.body.innerText.includes('fixture.txt')`));
  assert.ok(!await evaluate(tab, `document.body.innerText.includes('PRIVATE_LEGACY_')`));
  const sourceRoute = `/jobs/${fixture.id}/source/${fixture.sourceRelative}`;
  await ready(tab, `[...document.querySelectorAll('a')].some(link => new URL(link.href).pathname === '${sourceRoute}')`, 'legacy source-tree link');
  await cdp.call('Page.navigate', { url: origin + sourceRoute }, tab.sessionId);
  await ready(tab, `location.pathname === '${sourceRoute}' && !!document.querySelector('.source-view code')`, 'legacy source page');
  assert.equal(await evaluate(tab, `document.querySelector('.source-view code').textContent`), fixture.source);
  assert.ok(await evaluate(tab, `document.querySelector('.source-view code').textContent.includes('<script>')`));
  assert.ok(await evaluate(tab, `typeof globalThis.__sourceEscaped === 'undefined'`));
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `document.querySelector('.source-view code')?.textContent.includes('int fixture')`, 'legacy source reload');
  assert.equal(await evaluate(tab, `document.querySelector('.source-view code').textContent`), fixture.source);
  assert.ok(await evaluate(tab, `typeof globalThis.__sourceEscaped === 'undefined'`));
  await cdp.call('Page.navigate', { url: `${origin}/jobs/${fixture.id}` }, tab.sessionId);
  await ready(tab, `document.querySelector('#agent-event-list')?.innerText.includes('18446744073709551615')`, 'legacy job after source');
  const endpoint = `/api/jobs/${fixture.id}/events`;
  await ready(tab, `performance.getEntriesByType('resource').some(e => new URL(e.name).pathname === '${endpoint}')`, 'legacy automatic poll');
  const response = await evaluate(tab, `fetch('${endpoint}').then(r => r.json())`);
  assert.ok(!JSON.stringify(response).includes('PRIVATE_LEGACY_'));
  assert.equal(response.events[0].presentationOmittedFields, 2);
  assert.equal(response.events[0].textOmitted, true);
  const beforeRows = await evaluate(tab, `document.querySelector('#agent-event-list').innerText`);
  await fs.unlink(fixture.journalPath);
  await ready(tab, `document.querySelector('#agent-event-gap').innerText.includes('Retained progress is unavailable')`, 'legacy missing journal poll');
  assert.equal(await evaluate(tab, `document.querySelector('#agent-event-list').innerText`), beforeRows);
  const empty = JSON.stringify({ schemaVersion: 1, displayOnly: true, nextSequence: 0, queueDropped: 0,
    historyDropped: 0, truncated: false, events: [] });
  await fs.writeFile(fixture.journalPath, empty);
  await ready(tab, `document.querySelector('#agent-event-gap').innerText.includes('currently contains no events') && document.querySelector('#agent-event-list').children.length === 0`, 'legacy valid empty poll');
  await fs.writeFile(fixture.journalPath, fixture.journal);
  await ready(tab, `document.querySelector('#agent-event-list').innerText.includes('18446744073709551615')`, 'legacy restored poll');
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `document.querySelector('#agent-event-list')?.innerText.includes('18446744073709551615')`, 'legacy reload');
  assert.ok(!await evaluate(tab, `document.body.innerText.includes('PRIVATE_LEGACY_')`));
  assert.deepEqual(tab.exceptions, []);
  assert.equal(await evaluate(tab, `fetch('/jobs/${fixture.id}/artifacts/reports/fixture.txt').then(r => r.text())`), 'ordinary artifact');
  await cdp.call('Page.navigate', { url: origin + '/' }, tab.sessionId);
  await ready(tab, `document.readyState === 'complete' && !!document.querySelector('#binary')`, 'legacy upload dashboard');
  await evaluate(tab, `(() => {
    const bytes = new Uint8Array(64); bytes.set([127, 69, 76, 70, 2, 1, 1]);
    const view = new DataView(bytes.buffer); view.setUint16(16, 2, true); view.setUint16(18, 62, true);
    view.setUint32(20, 1, true); view.setUint16(52, 64, true);
    const transfer = new DataTransfer(); transfer.items.add(new File([bytes], 'inert-legacy-upload.elf'));
    document.querySelector('#binary').files = transfer.files;
    document.querySelector('form').requestSubmit();
  })()`);
  await ready(tab, `location.pathname.startsWith('/jobs/') && document.body.innerText.includes('inert-legacy-upload.elf')`, 'legacy authenticated form upload');
  const uploadId = await evaluate(tab, `location.pathname.split('/')[2]`);
  const uploaded = JSON.parse(await fs.readFile(join(dirname(fixture.directory), uploadId, 'job.json'), 'utf8'));
  assert.equal(uploaded.status, 'uploaded');
  assert.equal(await evaluate(tab, 'localStorage.length + sessionStorage.length'), 0);
  await ready(tab, `document.readyState === 'complete' && [...document.querySelectorAll('button')].some(button => button.textContent === 'End session')`, 'legacy session controls');
  const idlePeer = await makeTarget();
  await cdp.call('Page.navigate', { url: `${origin}/jobs/${uploadId}` }, idlePeer.sessionId);
  await ready(idlePeer, `document.readyState === 'complete' && window.legacySession?.isActive() && document.body.innerText.includes('inert-legacy-upload.elf')`, 'legacy idle peer');
  const pollingPeer = await makeTarget();
  await cdp.call('Page.addScriptToEvaluateOnNewDocument', { source: `Object.defineProperty(window, 'BroadcastChannel', { value: undefined });` }, pollingPeer.sessionId);
  await cdp.call('Page.navigate', { url: `${origin}/jobs/${fixture.id}` }, pollingPeer.sessionId);
  await ready(pollingPeer, `document.readyState === 'complete' && window.legacySession?.isActive() && !!document.querySelector('#agent-event-list')`, 'legacy peer without broadcast');
  await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'End session').click()`);
  await ready(tab, `location.pathname === '/login' && document.body.innerText.includes('Open a local session')`, 'legacy logout');
  for (const peer of [idlePeer, pollingPeer]) {
    await ready(peer, `location.pathname === '/login' && document.body.innerText.includes('Open a local session')`, 'legacy peer invalidation');
    assert.ok(!await evaluate(peer, `document.body.innerText.includes('legacy-browser.elf') || document.body.innerText.includes('inert-legacy-upload.elf')`));
    assert.deepEqual(peer.exceptions, []);
    assert.ok(peer.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
  }
  assert.ok(pollingPeer.responses.some(response => response.status === 401 && new URL(response.url).pathname.startsWith('/api/jobs/')));
  assert.equal(await evaluate(tab, `fetch('/api/jobs/${fixture.id}').then(r => r.status)`), 401);
  assert.equal(await evaluate(tab, `fetch('/jobs/${fixture.id}/artifacts/reports/fixture.txt').then(r => r.status)`), 401);
  assert.deepEqual(tab.exceptions, []);
  const mutations = tab.requests.filter(request => !['GET', 'HEAD'].includes(request.method));
  assert.deepEqual(mutations.map(request => [request.method, new URL(request.url).pathname]),
    [['POST', '/api/v1/session'], ['POST', '/jobs'], ['DELETE', '/api/v1/session']]);
  assert.equal(await fs.readFile(fixture.jobPath, 'utf8'), activeJob);
  assert.equal(await fs.readFile(fixture.journalPath, 'utf8'), fixture.journal);
  assert.equal(await fs.readFile(fixture.artifactPath, 'utf8'), 'ordinary artifact');
  assert.equal(await fs.readFile(fixture.sourcePath, 'utf8'), fixture.source);
  assert.deepEqual(await fs.readFile(join(fixture.directory, 'input.elf')), fixture.input);
  return { initialHtml: true, pollingExecuted: true, privateDiagnosticsWithheld: true, privateEventFieldsWithheld: true,
    exactUsage: true, omissionCount: 2, missingJournalPreservesRows: true, validEmptyClearsRows: true,
    restoredJournalRecovers: true, reload: true, sourceRenderedUnderCsp: true, sourceReload: true,
    sourceActiveContentInert: true, artifactMetadata: true, pageExceptions: 0, mutationRequests: 3,
    unauthenticatedReadsDenied: true, fragmentClearedBeforeExchange: true, authenticatedDownload: true,
    authenticatedFormUpload: true, uploadedJobRemainsUnexecuted: true, browserStorageEmpty: true,
    logoutRevokesReadsAndDownloads: true, idlePeerClearedByNotification: true,
    pollingPeerWithoutBroadcastClearedOn401: true, peerMutationRequests: 0,
    idlePeerRequests: idlePeer.requests, pollingPeerRequests: pollingPeer.requests, testOnlyFetchGuard: 'reject session POST if fragment remains',
    workflowAdmitted: false, testOwnedFixtureEdits: ['status set to analyzing after startup', 'journal removed, emptied and restored'],
    finalJobInputArtifactBytesUnchanged: true, finalJournalMatchesOriginal: true };
}
