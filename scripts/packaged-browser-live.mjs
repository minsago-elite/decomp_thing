import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

// Authored inert storage fixtures, never an analyzed or executable target.
function record(root, index) {
  const id = createHash('sha256').update(`live-dashboard:${index}`).digest('hex').slice(0, 32);
  const at = new Date(Date.parse('2026-01-01T00:00:00Z') + index * 1000).toISOString();
  return { id, filename: `live-dashboard-${index}.elf`, status: 'uploaded', created_at: at, updated_at: at,
    size_bytes: 64, binary_path: join(root, id, 'input.elf'),
    metadata: { format: 'ELF64', endianness: 'little', elf_version: 1, os_abi: 'System V', object_type: 'executable',
      machine: 'x86-64', entry_point: 0, elf_header_size: 64, program_header_count: 0, section_header_count: 0, section_name_table_index: 0 } };
}

async function publish(root, job, input) {
  // A live listing must never observe a half-written fixture job.
  const directory = join(root, '.live-job-' + job.id);
  await fs.mkdir(directory, { mode: 0o700 });
  await fs.writeFile(join(directory, 'input.elf'), input, { flag: 'wx', mode: 0o600 });
  await fs.writeFile(join(directory, 'job.json'), JSON.stringify(job), { flag: 'wx', mode: 0o600 });
  await fs.rename(directory, join(root, job.id));
}

export async function seedLive(root) {
  await fs.mkdir(root, { mode: 0o700 });
  const input = Buffer.alloc(64);
  input.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  input.writeUInt16LE(2, 16); input.writeUInt16LE(62, 18); input.writeUInt32LE(1, 20); input.writeUInt16LE(64, 52);
  const jobs = [record(root, 1), record(root, 2)];
  for (const job of jobs) await publish(root, job, input);
  return { root, jobs, input };
}

const ownerLocks = ['.web-owner.lock', '.workflow-owner.lock'];

// Session exchanges legitimately create the server-owned audit directory. Keep an
// exact root inventory; do not ignore dotfiles or relax the owner/job checks.
export async function assertLiveStorageInventory(root, jobs) {
  assert.deepEqual((await fs.readdir(root)).sort(),
    ['.web-audit', ...ownerLocks, ...jobs.map(job => job.id)].sort());
  const audit = await fs.lstat(join(root, '.web-audit'));
  assert.ok(audit.isDirectory() && !audit.isSymbolicLink(), 'Audit storage must be a real directory');
}

export async function qualifyLive({ fixture, makeTarget, cdp, evaluate, ready, waitFor, browserOrigin }) {
  const tab = await makeTarget();
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  await cdp.call('Page.navigate', { url: browserOrigin + '/nested/' }, tab.sessionId);
  const rows = `Array.from(document.querySelectorAll('ul[aria-label="Uploaded jobs"] li h4 a')).map(a => a.getAttribute('href'))`;
  const initial = fixture.jobs.slice().reverse().map(job => '/nested/jobs/' + job.id);
  await ready(tab, `document.visibilityState === 'visible' && (${rows}).length === 2`, 'visible live dashboard');
  assert.deepEqual(await evaluate(tab, rows), initial);
  // The running JVM owns these cooperative locks. Inspect metadata only and keep
  // both original files in place throughout the authored fixture updates.
  await assertLiveStorageInventory(fixture.root, fixture.jobs);
  const initialOwners = await Promise.all(ownerLocks.map(name => fs.lstat(join(fixture.root, name))));
  for (const owner of initialOwners) assert.ok(owner.isFile() && !owner.isSymbolicLink());
  const heldPath = '/nested/jobs/' + fixture.jobs[0].id;
  assert.equal(await evaluate(tab, `(() => {
    const link = document.querySelector('ul[aria-label="Uploaded jobs"] a[href="${heldPath}"]');
    Object.defineProperty(window, '__focusedJobLink', { value: link }); link.focus();
    return document.activeElement === link;
  })()`), true);

  // Only the test mutates fixture storage. Atomic publication avoids presenting a
  // partial JSON record to the real bounded listing endpoint.
  const changed = { ...fixture.jobs[0], status: 'failed', updated_at: '2026-01-01T00:00:10.000Z' };
  const temporary = join(fixture.root, changed.id, 'live-fixture-next.json');
  await fs.writeFile(temporary, JSON.stringify(changed), { flag: 'wx', mode: 0o600 });
  await fs.rename(temporary, join(fixture.root, changed.id, 'job.json'));
  await waitFor(() => evaluate(tab, `(() => {
    const row = window.__focusedJobLink.closest('li');
    return [...row.querySelectorAll('dt')].some(dt => dt.textContent === 'Workflow state' && dt.nextElementSibling.textContent === 'Failed');
  })()`), 'real background state update', 40_000);
  assert.deepEqual(await evaluate(tab, rows), initial);
  assert.equal(await evaluate(tab, 'document.activeElement === window.__focusedJobLink'), true);

  const added = record(fixture.root, 3);
  await publish(fixture.root, added, fixture.input);
  await waitFor(() => evaluate(tab, `document.body.innerText.includes('New or changed jobs are available.')`),
    'new job deferred while row focused', 40_000);
  assert.deepEqual(await evaluate(tab, rows), initial);
  assert.equal(await evaluate(tab, 'document.activeElement === window.__focusedJobLink'), true);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Refresh jobs').click()`);
  await ready(tab, `(${rows}).length === 3 && document.activeElement.textContent === 'Job results'`, 'explicit live snapshot refresh');
  assert.deepEqual(await evaluate(tab, rows), ['/nested/jobs/' + added.id, ...initial]);
  assert.equal(await evaluate(tab, `document.body.innerText.includes('New or changed jobs are available.')`), false);
  await evaluate(tab, `[...document.querySelectorAll('button')].find(button => button.textContent === 'Pause live updates').click()`);
  assert.equal(await evaluate(tab, `[...document.querySelectorAll('button')].some(button => button.textContent === 'Resume live updates' && button.getAttribute('aria-pressed') === 'true')`), true);

  const finalJobs = [changed, fixture.jobs[1], added];
  await assertLiveStorageInventory(fixture.root, finalJobs);
  for (const [index, name] of ownerLocks.entries()) {
    const finalOwner = await fs.lstat(join(fixture.root, name));
    assert.ok(finalOwner.isFile() && !finalOwner.isSymbolicLink());
    for (const field of ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs']) assert.equal(finalOwner[field], initialOwners[index][field],
      'Live dashboard checks changed the running JVM owner lock: ' + name + ' ' + field);
  }
  for (const job of finalJobs) {
    const directory = join(fixture.root, job.id);
    assert.deepEqual((await fs.readdir(directory)).sort(), ['input.elf', 'job.json']);
    assert.deepEqual(await fs.readFile(join(directory, 'input.elf')), fixture.input);
    assert.equal(await fs.readFile(join(directory, 'job.json'), 'utf8'), JSON.stringify(job));
  }
  assert.ok(tab.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
  assert.ok(tab.requests.filter(request => new URL(request.url).pathname === '/nested/api/v1/jobs').length >= 4);
  assert.deepEqual(tab.exceptions, []);
  return { initialJobs: 2, finalJobs: 3, realBackend: true, productionTimersUnmodified: true,
    stateUpdatePreservesRowAndFocus: true, newJobDeferredWithoutReorder: true,
    explicitRefreshAppliesCompleteSnapshot: true, pauseControlOperable: true,
    fixtureMutations: ['one atomic authored job status update', 'one authored inert job publication'],
    existingOwnerLockPreserved: true, existingWorkflowOwnerLockPreserved: true, jobStorageUnchangedExceptFixtureEdits: true,
    mutationRequests: 0, executionStarted: false };
}
