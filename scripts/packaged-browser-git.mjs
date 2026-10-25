import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { createWebGitFixture } from './web-git-fixtures.mjs';

const SUBJECT = 'Packaged journey: add notes';

/**
 * A disposable admitted repository (#584). Its pre-commit hook always fails, so a successful
 * commit also proves hooks stay inert. The job itself is uploaded through the UI, so no job
 * record is authored by the test. Nothing here invokes a workflow or reaches the network.
 */
/** Test-only raw Git in a fixture repository: fixed identity, no hooks, no user configuration, file transport only. */
function fixtureGit(cwd, args) {
  const result = spawnSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgSign=false', ...args], { cwd, encoding: 'utf8', timeout: 15_000,
    env: { PATH: process.env.PATH ?? '/usr/bin:/bin', LC_ALL: 'C', TZ: 'UTC', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_TERMINAL_PROMPT: '0', GIT_ALLOW_PROTOCOL: 'file', GIT_AUTHOR_NAME: 'Web Fixture Author', GIT_AUTHOR_EMAIL: 'web-fixture@example.invalid',
      GIT_COMMITTER_NAME: 'Web Fixture Committer', GIT_COMMITTER_EMAIL: 'web-fixture@example.invalid' } });
  if (result.status !== 0) throw new Error(`fixture git ${args[0]} failed: ${result.stderr}`);
  return result.stdout.trim();
}

export async function seedGit(scratchParent) {
  // The fixture helper creates its root under os.tmpdir(); keep it inside the owned scratch parent.
  const scratch = await fs.mkdtemp(join(scratchParent, 'packaged-git-'));
  const previous = process.env.TMPDIR;
  process.env.TMPDIR = scratch;
  let repository;
  try { repository = await createWebGitFixture({ poisonHooks: true }); }
  catch (error) { await fs.rm(scratch, { recursive: true, force: true }); throw error; }
  finally { if (previous === undefined) delete process.env.TMPDIR; else process.env.TMPDIR = previous; }
  // Configuration isolation canaries (#610): a filter driver in the admitted repository's own
  // configuration and attributes that would run it. Neither may execute in the managed copy.
  const marker = join(scratch, 'filter-ran');
  await fs.writeFile(join(repository.paths.local, '.gitattributes'), '*.txt filter=canary\n');
  fixtureGit(repository.paths.local, ['add', '--', '.gitattributes']);
  fixtureGit(repository.paths.local, ['commit', '-q', '-m', 'fixture: filter attributes']);
  await fs.appendFile(join(repository.paths.local, '.git', 'config'), `[filter "canary"]\n\tclean = touch '${marker}'\n\tsmudge = touch '${marker}'\n`);
  const localTip = fixtureGit(repository.paths.local, ['rev-parse', 'main']);
  // Server-side credential canary for an allowlisted host that can never resolve (#586, #610).
  const canary = `canary-${createHash('sha256').update(scratch).digest('hex').slice(0, 24)}`;
  const tokenFile = join(scratch, 'canary-token');
  await fs.writeFile(tokenFile, `${canary}\n`, { mode: 0o600 });
  const credentials = join(scratch, 'git-credentials.json');
  await fs.writeFile(credentials, JSON.stringify({ https: [{ host: 'canary.invalid', username: 'canary-bot', passwordFile: tokenFile }] }), { mode: 0o600 });
  return { repository, importRoot: repository.paths.root, scratch, marker, localTip, canary, credentials,
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
  await ready(tab, `document.body.innerText.includes('Branch main') && document.body.innerText.includes('fixture: local branch')`, 'imported repository status and history');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('fixture: baseline') && document.body.innerText.includes('Not mapped to a reconstruction revision')`));
  assert.equal(fixture.repository.git('local', ['rev-parse', 'main']).stdout.trim(), fixture.localTip, 'Import changed the admitted repository');

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
  assert.equal(fixture.repository.git('local', ['rev-parse', 'main']).stdout.trim(), fixture.localTip, 'Committing changed the admitted repository');
  assert.deepEqual(tab.exceptions, []);
  assert.equal(await evaluate(tab, 'localStorage.length + sessionStorage.length'), 0);
  const mutations = tab.requests.slice(beforeView).filter(request => !['GET', 'HEAD'].includes(request.method));
  assert.equal(mutations.length, 3, 'Expected exactly the import, stage and commit requests');
  return { path, objectId, exportSha256: shown, exportEntries: names, viewReadRequests: viewRequests.length, mutationRequests: mutations.length,
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

/** Wait for an operation started from the workspace to report its outcome in the status region. */
async function outcome(ready, evaluate, tab, label, description, previous = '') {
  const texts = `[...document.querySelectorAll('[role="status"]')].map(node => node.textContent)`;
  await ready(tab, `${texts}.some(text => text !== ${JSON.stringify(previous)} && (text.startsWith(${JSON.stringify(label + ':')})
    || text.startsWith(${JSON.stringify(label + ' did not complete')}) || text.startsWith(${JSON.stringify('The server refused ' + label)})))`, description);
  const found = await evaluate(tab, `${texts}.find(text => text !== ${JSON.stringify(previous)} && text.includes(${JSON.stringify(label)}))`);
  console.log(`Git journey: ${found}`);
  return found;
}

async function select(evaluate, tab, label, optionText) {
  await evaluate(tab, `(() => {
    const field = [...document.querySelectorAll('label')].find(item => item.textContent.startsWith(${JSON.stringify(label)})).querySelector('select');
    const option = [...field.options].find(item => item.textContent === ${JSON.stringify(optionText)});
    field.value = option.value; field.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);
}

/**
 * Packaged synchronization journey (#608-#610) after the restart:
 * 1. Commit the change that survived the restart.
 * 2. Register the disposable remote, fetch it and review the divergence.
 * 3. Merge into a real conflict, resolve it and commit.
 * 4. Explicitly push to the remote.
 * Then check that provenance stays verifiable after branch changes and while the remote is
 * unavailable, that filters and hooks stayed inert, and that the credential canary appears in no
 * user-facing output or stored file.
 */
export async function qualifyGitSync({ fixture, objectId, exportSha256, makeTarget, cdp, evaluate, ready, browserOrigin, data }) {
  const tab = await makeTarget();
  await cdp.call('Page.navigate', { url: `${browserOrigin}/nested/jobs/${fixture.jobId}/git` }, tab.sessionId);
  await ready(tab, `${group('Not staged')}?.innerText.includes('shared.txt') ?? false`, 'workspace before synchronization');
  // 1. Commit the change that survived the restart.
  await evaluate(tab, `document.querySelector('input[aria-label="Select shared.txt (Not staged)"]').click()`);
  await press(ready, evaluate, tab, 'Stage selected');
  await outcome(ready, evaluate, tab, 'Stage selected', 'staged shared.txt');
  await ready(tab, `${group('Staged')}?.innerText.includes('shared.txt') ?? false`, 'shared.txt staged');
  await setField(evaluate, tab, `document.querySelector('#git-commit-message')`, 'Packaged journey: local shared edit');
  await press(ready, evaluate, tab, 'Commit staged files');
  await ready(tab, `document.querySelector('ol[aria-label="History"]')?.innerText.includes('Packaged journey: local shared edit') ?? false`, 'local shared commit');
  // The disposable remote receives a conflicting edit from its peer clone.
  await fs.writeFile(join(fixture.repository.paths.peer, 'shared.txt'), 'remote conflicting edit\n');
  fixtureGit(fixture.repository.paths.peer, ['commit', '-q', '-am', 'fixture: remote conflicting edit']);
  fixtureGit(fixture.repository.paths.peer, ['push', '-q', 'origin', 'main']);

  // 2. Register the remote by admitted name and fetch it.
  await setField(evaluate, tab, `[...document.querySelectorAll('label')].find(label => label.textContent.startsWith('Remote name')).querySelector('input')`, 'origin');
  await setField(evaluate, tab, `[...document.querySelectorAll('label')].find(label => label.textContent.startsWith('Remote URL')).querySelector('input')`, 'admitted:remote.git');
  await press(ready, evaluate, tab, 'Add remote');
  const registered = await outcome(ready, evaluate, tab, 'Add remote', 'registered remote');
  await ready(tab, `!!${button('Fetch origin')}`, 'remote listed');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('admitted:remote.git') && document.body.innerText.includes('Never fetched')`));
  await press(ready, evaluate, tab, 'Fetch origin');
  const fetched = await outcome(ready, evaluate, tab, 'Fetch origin', 'fetched remote');
  assert.match(fetched, /Fetch origin: Fetched origin: [0-9]+ remote-tracking ref/);
  await ready(tab, `!!document.querySelector('ul[aria-label="Remote-tracking refs of origin"]')`, 'tracking refs');
  // Divergence from fetched state only; rebase is never offered.
  await ready(tab, `!!${button('Review divergence')}`, 'integration panel');
  await select(evaluate, tab, 'Remote-tracking branch', 'refs/remotes/origin/main');
  await press(ready, evaluate, tab, 'Review divergence');
  await ready(tab, `document.body.innerText.includes('remote commit(s) not on your branch')`, 'divergence');
  assert.ok(await evaluate(tab, `${button('Rebase')}.disabled && ${button('Fast-forward to the remote commit')}.disabled`), 'Only a merge is offered for diverged history');

  // 3. Merge into a real conflict, resolve it explicitly and commit.
  await press(ready, evaluate, tab, 'Merge the remote commit');
  await outcome(ready, evaluate, tab, 'Merge the remote commit', 'merge started');
  await ready(tab, `document.body.innerText.includes('Merge conflicts') && !!${button('Review shared.txt')}`, 'conflict listed');
  await press(ready, evaluate, tab, 'Review shared.txt');
  await ready(tab, `document.body.innerText.includes('remote conflicting edit')`, 'conflict sides');
  await press(ready, evaluate, tab, 'Use the remote version');
  await outcome(ready, evaluate, tab, 'Save resolution', 'resolution saved');
  await ready(tab, `!document.querySelector('input[aria-label="Mark shared.txt reviewed"]').disabled`, 'reviewable resolution');
  await evaluate(tab, `document.querySelector('input[aria-label="Mark shared.txt reviewed"]').click()`);
  await press(ready, evaluate, tab, 'Stage reviewed resolutions');
  await outcome(ready, evaluate, tab, 'Stage reviewed resolutions', 'resolution staged');
  await ready(tab, `document.body.innerText.includes('Every conflict is resolved and staged')`, 'all conflicts resolved');
  await setField(evaluate, tab, `document.querySelector('#git-commit-message')`, 'Packaged journey: merge the remote edit');
  await press(ready, evaluate, tab, 'Commit staged files');
  await ready(tab, `document.querySelector('ol[aria-label="History"]')?.innerText.includes('Packaged journey: merge the remote edit') ?? false`, 'merge commit');
  const merged = await evaluate(tab, `document.querySelector('ol[aria-label="History"] li code').title`);
  assert.equal(await fs.readFile(join(data, fixture.jobId, 'git', 'repositories', (await fs.readdir(join(data, fixture.jobId, 'git', 'repositories')))[0], 'worktree', 'shared.txt'), 'utf8'),
    'remote conflicting edit\n');

  // 4. Publish explicitly; the remote receives exactly the reviewed merge commit.
  await press(ready, evaluate, tab, 'Preview push');
  await ready(tab, `[...document.querySelectorAll('button')].some(item => /^Push [0-9]+ commit\\(s\\) to main$/.test(item.textContent))`, 'push preview');
  const pushLabel = await evaluate(tab, `[...document.querySelectorAll('button')].map(item => item.textContent).find(text => /^Push [0-9]+ commit\\(s\\) to main$/.test(text))`);
  await press(ready, evaluate, tab, pushLabel);
  await outcome(ready, evaluate, tab, pushLabel, 'push');
  assert.equal(fixtureGit(fixture.repository.paths.remote, ['rev-parse', 'main']), merged, 'The remote must name the pushed merge commit');
  await ready(tab, `[...document.querySelectorAll('ol[aria-label="Remote audit history"] li')].some(item => item.textContent.includes('push · published'))`, 'push audit');

  // Provenance stays verifiable after branch changes and while the remote is unavailable.
  const offline = `${fixture.repository.paths.remote}.offline`;
  await fs.rename(fixture.repository.paths.remote, offline);
  try {
    await press(ready, evaluate, tab, 'Fetch origin');
    const unavailable = await outcome(ready, evaluate, tab, 'Fetch origin', 'fetch while the remote is unavailable', fetched);
    assert.ok(/did not complete|refused/.test(unavailable), unavailable);
    await press(ready, evaluate, tab, `Inspect ${objectId.slice(0, 12)}`);
    await ready(tab, `document.body.innerText.includes(${JSON.stringify(`Source export SHA-256: ${exportSha256}`)})`, 'export digest with the remote unavailable');
  } finally { await fs.rename(offline, fixture.repository.paths.remote); }

  // A credentialed remote on an allowlisted host that never resolves: the attempt fails safely.
  await setField(evaluate, tab, `[...document.querySelectorAll('label')].find(label => label.textContent.startsWith('Remote name')).querySelector('input')`, 'canary');
  await setField(evaluate, tab, `[...document.querySelectorAll('label')].find(label => label.textContent.startsWith('Remote URL')).querySelector('input')`, 'https://canary.invalid/team/project.git');
  await press(ready, evaluate, tab, 'Add remote');
  await outcome(ready, evaluate, tab, 'Add remote', 'credentialed remote registered', registered);
  await ready(tab, `!!${button('Fetch canary')} && document.body.innerText.includes('Credential configured on the server')`, 'credential state shown, not the credential');
  await press(ready, evaluate, tab, 'Fetch canary');
  const denied = await outcome(ready, evaluate, tab, 'Fetch canary', 'credentialed fetch');
  assert.ok(/did not complete/.test(denied), denied);

  // Isolation and redaction checks (#610).
  assert.equal(await fs.stat(fixture.marker).then(() => true, () => false), false, 'A repository filter driver ran');
  const surfaces = await evaluate(tab, `(async () => {
    const base = location.pathname.replace(/\\/git$/, '').replace('/nested/', '/nested/api/v1/') + '/repositories';
    const listing = await (await fetch(base)).json();
    const repository = listing.data.repositories[0].repositoryId;
    const reads = ['', '/' + repository, '/' + repository + '/remotes', '/' + repository + '/audit?limit=200', '/' + repository + '/status',
      '/' + repository + '/history', '/' + repository + '/refs'];
    const texts = [JSON.stringify(listing), document.body.innerText, await (await fetch('/nested/api/v1/bootstrap')).text()];
    for (const read of reads) texts.push(await (await fetch(base + read)).text());
    return texts;
  })()`);
  for (const text of surfaces) assert.equal(text.includes(fixture.canary), false, 'The credential canary reached a user-facing surface');
  async function walk(directory) {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile() && (await fs.stat(path)).size < 16 * 1024 * 1024) {
        assert.equal((await fs.readFile(path)).includes(fixture.canary), false, `The credential canary was stored in ${path}`);
      }
    }
  }
  await walk(data);
  assert.deepEqual(tab.exceptions, []);
  return { cloneFetchDivergence: true, conflictResolved: true, mergeCommit: merged, pushedToRemote: true, auditedPublication: true,
    exportDigestStable: true, remoteUnavailableHandled: true, filterInert: true, credentialCanaryAbsent: true };
}

/** Activate a native button once it is enabled; an operation that is still finishing keeps controls disabled. */
async function press(ready, evaluate, tab, label) {
  await ready(tab, `!!${button(label)} && !${button(label)}.disabled`, `enabled ${label}`);
  await evaluate(tab, `${button(label)}.click()`);
}
