import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { createWebGitFixture } from './web-git-fixtures.mjs';

const SUBJECT = 'Packaged journey: add notes';

/**
 * A disposable admitted repository (#584). Its pre-commit hook always fails, so a successful
 * commit also proves hooks stay inert. The job itself is uploaded through the UI, so no job
 * record is authored by the test. Nothing here invokes a workflow or reaches the network.
 */
export async function seedGit(scratchParent) {
  // The fixture helper creates its root under os.tmpdir(); keep it inside the owned scratch parent.
  const scratch = await fs.mkdtemp(join(scratchParent, 'packaged-git-'));
  const previous = process.env.TMPDIR;
  process.env.TMPDIR = scratch;
  let repository;
  try { repository = await createWebGitFixture({ poisonHooks: true, historyLength: 1001 }); }
  catch (error) { await fs.rm(scratch, { recursive: true, force: true }); throw error; }
  finally { if (previous === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = previous; }
  return { repository, importRoot: repository.paths.root, scratch,
    async dispose() { await repository.dispose(); await fs.rm(scratch, { recursive: true, force: true }); } };
}

/** STORED ZIP entry names, read from local headers (the export never compresses). */
function zipNames(bytes) {
  const names = [];
  let offset = 0;
  while (offset + 30 <= bytes.length && bytes.readUInt32LE(offset) === 0x04034b50) {
    const method = bytes.readUInt16LE(offset + 8);
    assert.equal(method, 0, 'Source export entries must be STORED');
    const size = bytes.readUInt32LE(offset + 18);
    const nameLength = bytes.readUInt16LE(offset + 26), extraLength = bytes.readUInt16LE(offset + 28);
    names.push(bytes.subarray(offset + 30, offset + 30 + nameLength).toString('utf8'));
    offset += 30 + nameLength + extraLength + size;
  }
  return names;
}

async function key(cdp, target, keyName, code, keyCode, text) {
  for (const type of ['keyDown', 'keyUp']) {
    await cdp.call('Input.dispatchKeyEvent', { type, key: keyName, code, windowsVirtualKeyCode: keyCode, ...(type === 'keyDown' && text ? { text } : {}) }, target.sessionId);
  }
}

const button = (label) => `[...document.querySelectorAll('button')].find(button => button.textContent === ${JSON.stringify(label)})`;
const group = (legend) => `[...document.querySelectorAll('fieldset')].find(set => set.querySelector('legend')?.textContent === ${JSON.stringify(legend)})`;

async function setField(evaluate, target, selector, value) {
  await evaluate(target, `(() => {
    const field = ${selector};
    field.focus(); field.value = ${JSON.stringify(value)}; field.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
}

async function managedWorktree(data, jobId) {
  const repositories = join(data, jobId, 'git', 'repositories');
  const [repositoryId, ...others] = await fs.readdir(repositories);
  assert.equal(others.length, 0, 'Expected exactly one managed repository');
  return join(repositories, repositoryId, 'worktree');
}

/**
 * Keyboard-driven Git journey against the packaged JVM: import an admitted repository by name,
 * observe an external work-tree edit, stage and commit through the UI, and verify the commit's
 * deterministic source export against its displayed provenance.
 */
export async function qualifyGit({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin, data }) {
  const tab = await makeTarget();
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/' }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Local session connected.') && document.querySelector('#binary-file') !== null`, 'Git journey session');
  await evaluate(tab, `(() => {
    const bytes = new Uint8Array(64); bytes.set([127, 69, 76, 70, 2, 1, 1]);
    const view = new DataView(bytes.buffer); view.setUint16(16, 2, true); view.setUint16(18, 62, true);
    view.setUint32(20, 1, true); view.setUint16(52, 64, true);
    const transfer = new DataTransfer(); transfer.items.add(new File([bytes], 'synthetic-git.elf'));
    const picker = document.querySelector('#binary-file'); picker.focus(); picker.files = transfer.files;
    picker.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);
  await evaluate(tab, `${button('Upload binary')}.focus()`);
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
  await ready(tab, `/^\\/nested\\/jobs\\/[0-9a-f]{32}$/.test(location.pathname) && document.body.innerText.includes('synthetic-git.elf')`, 'uploaded Git journey job');
  fixture.jobId = (await evaluate(tab, 'location.pathname')).split('/').pop();
  const path = `/nested/jobs/${fixture.jobId}/git`;
  await ready(tab, `[...document.querySelectorAll('a')].some(link => link.textContent === 'Open the repository workspace')`, 'job repository panel link');
  assert.equal(await evaluate(tab, `[...document.querySelectorAll('a')].find(link => link.textContent === 'Open the repository workspace').getAttribute('href')`), path);
  const beforeView = tab.requests.length;
  await evaluate(tab, `[...document.querySelectorAll('a')].find(link => link.textContent === 'Open the repository workspace').click()`);
  await ready(tab, `document.querySelector('h1')?.textContent === 'Source repository' && document.title === 'Source repository · Decomp Workbench'
    && document.body.innerText.includes('This job has no managed repository yet.')`, 'Git workspace without a repository');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Git on this server: supported')`));
  const viewRequests = tab.requests.slice(beforeView);
  assert.ok(viewRequests.every(request => ['GET', 'HEAD'].includes(request.method)), 'Opening the Git view sent a mutation');

  await setField(evaluate, tab, `[...document.querySelectorAll('label')].find(label => label.textContent.startsWith('Repository name')).querySelector('input')`, 'local');
  await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
  await ready(tab, `document.body.innerText.includes('Branch main') && document.body.innerText.includes('fixture: history 1000')`, 'imported repository status and history');
  const historyRows = `document.querySelectorAll('ol[aria-label="History"] li')`;
  assert.equal(await evaluate(tab, `${historyRows}.length`), 20, 'History must start with one bounded page');
  const historyStart = tab.requests.length;
  let historyPages = 1;
  for (let count = 20; count < fixture.repository.historyLength; count += 20) {
    await evaluate(tab, `${button('Older commits')}.focus()`);
    await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
    await ready(tab, `${historyRows}.length === ${Math.min(count + 20, fixture.repository.historyLength)}`, 'next anchored history page');
    historyPages++;
  }
  const historyIds = await evaluate(tab, `[...${historyRows}].map(row => row.querySelector('code').title)`);
  assert.equal(new Set(historyIds).size, fixture.repository.historyLength, 'History repeats a commit');
  assert.deepEqual(historyIds, fixture.repository.git('local', ['rev-list', 'main']).stdout.trim().split('\n'),
    'Every displayed history page must match the admitted repository, in order');
  assert.equal(historyIds[0], fixture.repository.commits.local);
  assert.equal(historyIds.at(-1), fixture.repository.commits.base);
  assert.equal(await evaluate(tab, `!!${button('Older commits')}`), false, 'Exhausted history must not offer another page');
  assert.ok(tab.requests.slice(historyStart).every(request => ['GET', 'HEAD'].includes(request.method)), 'History pagination sent a mutation');
  assert.equal(tab.requests.slice(historyStart).filter(request => request.hasHistoryCursor).length, historyPages - 1);
  assert.ok(await evaluate(tab, `document.body.innerText.includes('fixture: baseline') && document.body.innerText.includes('Not mapped to a reconstruction revision')`));
  assert.equal(fixture.repository.git('local', ['rev-parse', 'main']).stdout.trim(), fixture.repository.commits.local, 'Import changed the admitted repository');

  const worktree = await managedWorktree(data, fixture.jobId);
  assert.equal(await fs.stat(join(worktree, '.git')).then(stat => stat.isDirectory(), () => false), false, 'Managed work tree must not hold its own .git directory');
  await fs.writeFile(join(worktree, 'notes.txt'), 'Recorded by the packaged Git journey.\n');
  await fs.writeFile(join(worktree, 'shared.txt'), 'edited outside the browser\n');
  await fs.writeFile(join(worktree, 'helper.o'), Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
  await evaluate(tab, `${button('Refresh repository')}.click()`);
  await ready(tab, `${group('Untracked')}?.innerText.includes('notes.txt') && ${group('Not staged')}?.innerText.includes('shared.txt')`, 'external work-tree edits');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('1 ignored by the source-only policy') && !document.body.innerText.includes('helper.o')`),
    'The source-only policy must count, not list, excluded build output');

  // Keyboard only: Space selects the untracked file and Enter activates the native button.
  await evaluate(tab, `document.querySelector('input[aria-label="Select notes.txt (Untracked)"]').focus()`);
  await key(cdp, tab, ' ', 'Space', 32, ' ');
  await ready(tab, `document.querySelector('input[aria-label="Select notes.txt (Untracked)"]').checked && !${button('Stage selected')}.disabled`, 'keyboard file selection');
  await evaluate(tab, `${button('Stage selected')}.focus()`);
  await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
  await ready(tab, `${group('Staged')}?.innerText.includes('notes.txt') && document.body.innerText.includes('Stage selected:')`, 'staged selection');
  const review = await evaluate(tab, `[...document.querySelectorAll('ul[aria-label="Exactly these staged files will be committed:"] li')].map(item => item.textContent)`);
  assert.deepEqual(review, ['notes.txt added'], 'The commit review must list exactly the staged file');
  assert.ok(await evaluate(tab, `${group('Not staged')}.innerText.includes('shared.txt')`), 'An unselected change must stay unstaged');

  await setField(evaluate, tab, `document.querySelector('#git-commit-message')`, SUBJECT);
  await evaluate(tab, `${button('Commit staged files')}.focus()`);
  await key(cdp, tab, 'Enter', 'Enter', 13, '\r');
  await ready(tab, `document.querySelector('ol[aria-label="History"]')?.innerText.includes(${JSON.stringify(SUBJECT)})`, 'committed history entry');
  const objectId = await evaluate(tab, `document.querySelector('ol[aria-label="History"] li code').title`);
  assert.match(objectId, /^[0-9a-f]{40}$/);
  assert.ok(await evaluate(tab, `${group('Not staged')}.innerText.includes('shared.txt') && !document.body.innerText.includes('Untracked')`));

  await evaluate(tab, `${button(`Inspect ${objectId.slice(0, 12)}`)}.click()`);
  await ready(tab, `document.body.innerText.includes('Export verified against the commit tree’s blob IDs.')`, 'commit provenance');
  const shown = await evaluate(tab, `document.body.innerText.match(/Source export SHA-256: ([0-9a-f]{64})/)[1]`);
  const exported = await evaluate(tab, `(async () => {
    const link = [...document.querySelectorAll('a')].find(link => link.textContent === 'Download source export');
    const response = await fetch(link.href, { credentials: 'same-origin' });
    const bytes = new Uint8Array(await response.arrayBuffer());
    return { href: link.getAttribute('href'), status: response.status, type: response.headers.get('content-type'), bytes: Array.from(bytes) };
  })()`);
  assert.equal(exported.status, 200);
  assert.equal(exported.href, `/nested/api/v1/jobs/${fixture.jobId}/repositories/${(await fs.readdir(join(data, fixture.jobId, 'git', 'repositories')))[0]}/exports/${objectId}`);
  const archive = Buffer.from(exported.bytes);
  assert.equal(createHash('sha256').update(archive).digest('hex'), shown, 'The downloaded export must match its displayed provenance digest');
  const names = zipNames(archive);
  assert.ok(names.includes('notes.txt') && names.includes('README.md'), `Unexpected export entries: ${names.join(', ')}`);
  assert.ok(names.every(name => !name.split('/').includes('.git') && name !== 'helper.o'), 'The export must exclude .git and policy-excluded files');
  assert.deepEqual(names, [...names].sort(), 'Export entries must be in deterministic order');
  assert.equal(fixture.repository.git('local', ['rev-parse', 'main']).stdout.trim(), fixture.repository.commits.local, 'Committing changed the admitted repository');
  assert.deepEqual(tab.exceptions, []);
  assert.equal(await evaluate(tab, 'localStorage.length + sessionStorage.length'), 0);
  const mutations = tab.requests.slice(beforeView).filter(request => !['GET', 'HEAD'].includes(request.method));
  assert.equal(mutations.length, 3, 'Expected exactly the import, stage and commit requests');
  return { path, objectId, exportSha256: shown, exportEntries: names, viewReadRequests: viewRequests.length, mutationRequests: mutations.length,
    historyCommits: historyIds.length, historyPages, historyKeyboardPagination: true,
    keyboardSelection: true, keyboardActivation: true, hooksInert: true, sourceRepositoryUnchanged: true, policyExcludedCounted: 1 };
}

/** After a JVM restart the commit, its provenance and the unselected work-tree change remain. */
export async function qualifyGitRestart({ fixture, objectId, exportSha256, bootstrapUrl, makeTarget, cdp, evaluate, ready, browserOrigin }) {
  const tab = await makeTarget();
  await cdp.call('Page.navigate', { url: bootstrapUrl }, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('Local session connected.')`, 'session after restart');
  await cdp.call('Page.navigate', { url: `${browserOrigin}/nested/jobs/${fixture.jobId}/git` }, tab.sessionId);
  await ready(tab, `document.querySelector('ol[aria-label="History"]')?.innerText.includes(${JSON.stringify(SUBJECT)})`, 'durable history after restart');
  assert.equal(await evaluate(tab, `document.querySelector('ol[aria-label="History"] li code').title`), objectId);
  assert.ok(await evaluate(tab, `${group('Not staged')}?.innerText.includes('shared.txt') ?? false`), 'The unstaged change must survive restart');
  await evaluate(tab, `${button(`Inspect ${objectId.slice(0, 12)}`)}.click()`);
  await ready(tab, `document.body.innerText.includes(${JSON.stringify(`Source export SHA-256: ${exportSha256}`)})`, 'stable export digest after restart');
  assert.ok(tab.requests.filter(request => !request.url.endsWith('/api/v1/session')).every(request => ['GET', 'HEAD'].includes(request.method)));
  assert.deepEqual(tab.exceptions, []);
  return { durableHistory: true, durableWorktree: true, stableExportDigest: true, mutationRequests: 0 };
}
