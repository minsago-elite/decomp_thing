import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { record, publish } from './packaged-browser-live.mjs';

// D3.6 (#173) packaged lifecycle: label, archive and deliberate deletion of one
// authored inert job against the real packaged JVM. No workflow is started.
const setInput = (selector, value) => `(() => {
  const input = document.querySelector(${JSON.stringify(selector)}); input.focus();
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${JSON.stringify(value)});
  input.dispatchEvent(new Event('input', { bubbles: true }));
})()`;
const click = (text) => `[...document.querySelectorAll('button')].find(button => button.textContent === ${JSON.stringify(text)}).click()`;
const status = (section) => `document.querySelector('section[aria-labelledby="${section}"] [role="status"]')?.textContent`;
const deletedNotice = `document.querySelector('[role="alert"]')?.textContent.includes('This job was deleted. Its files were removed and cannot be recovered')`;

async function listed(tab, evaluate, id, archived) {
  return evaluate(tab, `(async () => {
    const response = await fetch('/nested/api/v1/jobs?limit=100${archived ? '&archived=' + archived : ''}');
    if (response.status !== 200) throw new Error('job listing ' + response.status);
    return (await response.json()).data.items.some(job => job.jobId === '${id}');
  })()`);
}

export async function qualifyLifecycle({ fixture, makeTarget, cdp, evaluate, ready, waitFor, browserOrigin }) {
  const job = { ...record(fixture.root, 4), filename: 'lifecycle-fixture.elf' };
  await publish(fixture.root, job, fixture.input);
  const directory = join(fixture.root, job.id);
  const evidence = async () => ({ input: await fs.readFile(join(directory, 'input.elf')), record: await fs.readFile(join(directory, 'job.json'), 'utf8') });
  const original = await evidence();
  const jobUrl = browserOrigin + '/nested/jobs/' + job.id;

  const tab = await makeTarget();
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  await cdp.call('Page.navigate', { url: jobUrl }, tab.sessionId);
  await ready(tab, `document.querySelector('h2')?.textContent === 'lifecycle-fixture.elf' && document.querySelector('input[name="label"]:not(:disabled)') !== null`, 'lifecycle job route');
  assert.equal(await evaluate(tab, `document.body.innerText.includes('It does not export, compress or download a source archive, and removes nothing.')`), true);

  // 1. Display label: only organization.json changes; identity and evidence bytes stay exact.
  await evaluate(tab, setInput('input[name="label"]', 'Lifecycle label'));
  await evaluate(tab, click('Save organization'));
  await ready(tab, `${status('job-organize-title')} === 'Saved. The job was read again from the server.' && document.querySelector('h2')?.textContent === 'Lifecycle label'`, 'label saved and re-read');
  assert.equal(await evaluate(tab, `document.body.innerText.includes('File name: lifecycle-fixture.elf') && document.body.innerText.includes('${job.id}')`), true);
  assert.deepEqual(await evidence(), original, 'Label edit changed job evidence');
  assert.deepEqual(JSON.parse(await fs.readFile(join(directory, 'organization.json'), 'utf8')).label, 'Lifecycle label');

  // 2. Archive: hidden from default listing, present under archived=only; still no evidence change.
  await evaluate(tab, `document.querySelector('input[name="archived"]').click()`);
  await evaluate(tab, click('Save organization'));
  await ready(tab, `${status('job-organize-title')} === 'Saved. The job was read again from the server.' && document.querySelector('input[name="archived"]').checked`, 'archive saved and re-read');
  assert.deepEqual(await evidence(), original, 'Archive changed job evidence');
  assert.equal(JSON.parse(await fs.readFile(join(directory, 'organization.json'), 'utf8')).archived, true);
  assert.equal(await listed(tab, evaluate, job.id, ''), false, 'Archived job remained in the default listing');
  assert.equal(await listed(tab, evaluate, job.id, 'only'), true, 'Archived job missing from archived listing');
  assert.deepEqual((await fs.readdir(directory)).sort(), ['input.elf', 'job.json', 'organization.json']);

  // A second tab holds the same deep link while the first deletes it.
  const peer = await makeTarget();
  await cdp.call('Page.navigate', { url: jobUrl }, peer.sessionId);
  await ready(peer, `document.querySelector('h2')?.textContent === 'Lifecycle label'`, 'peer tab on lifecycle job');

  // 3. Deliberate deletion: reviewed preview, typed confirmation gate, one DELETE.
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  await evaluate(tab, click('Review what would be deleted'));
  await ready(tab, `document.body.innerText.includes('Job to delete') && document.body.innerText.includes('Retained after deletion: a deletion record') && document.querySelector('input[name="confirm"]') !== null`, 'deletion preview');
  const deleteDisabled = `[...document.querySelectorAll('button')].find(button => button.textContent === 'Delete permanently').disabled`;
  assert.equal(await evaluate(tab, deleteDisabled), true, 'Delete enabled before confirmation');
  await evaluate(tab, setInput('input[name="confirm"]', 'Lifecycle label'));
  assert.equal(await evaluate(tab, deleteDisabled), true, 'Delete accepted the label instead of the file name');
  await evaluate(tab, setInput('input[name="confirm"]', 'lifecycle-fixture.elf'));
  assert.equal(await evaluate(tab, deleteDisabled), false);
  const deletesBefore = tab.requests.filter(request => request.method === 'DELETE').length;
  await evaluate(tab, click('Delete permanently'));
  await ready(tab, deletedNotice, 'deleted notice in deleting tab');
  assert.equal(tab.requests.filter(request => request.method === 'DELETE').length - deletesBefore, 1);
  await waitFor(async () => !(await fs.readdir(fixture.root)).includes(job.id), 'job directory removed', 40_000);

  // 4. Recovery and consistency: truthful copy, peer tab, deep-link reload, API 410, focusable return.
  assert.equal(await evaluate(tab, `document.body.innerText.includes('cannot be recovered') && !/undo|restore|trash/i.test(document.querySelector('[role="alert"]').textContent)`), true);
  // Headless background targets may report hidden; bring the peer forward so its own re-read runs.
  await cdp.call('Page.bringToFront', {}, peer.sessionId);
  await ready(peer, deletedNotice, 'peer tab reconciles deletion');
  await cdp.call('Page.bringToFront', {}, tab.sessionId);
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, deletedNotice, 'deleted deep link after reload');
  assert.equal(await evaluate(tab, `fetch('/nested/api/v1/jobs/${job.id}').then(response => response.status)`), 410);
  assert.equal(await listed(tab, evaluate, job.id, 'all'), false, 'Deleted job still listed');
  await evaluate(tab, `(() => { const link = [...document.querySelectorAll('a')].find(a => a.textContent === 'Return to jobs'); link.focus(); return link; })()`);
  assert.equal(await evaluate(tab, `document.activeElement.textContent`), 'Return to jobs', 'Recovery link not keyboard focusable');
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', text: '\r', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
  await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 }, tab.sessionId);
  await ready(tab, `location.pathname === '/nested/' && document.querySelector('ul[aria-label="Uploaded jobs"]') !== null && !document.querySelector('a[href="/nested/jobs/${job.id}"]') && document.activeElement !== document.body`, 'keyboard return to dashboard with focus');
  const landingFocus = await evaluate(tab, `document.activeElement.tagName + ':' + document.activeElement.textContent.slice(0, 40)`);

  // Untouched live fixture jobs survive the lifecycle scenario.
  for (const other of fixture.jobs) assert.ok((await fs.readdir(fixture.root)).includes(other.id));
  const methods = tab.requests.map(request => request.method).filter(method => !['GET', 'HEAD'].includes(method));
  assert.deepEqual(methods.sort(), ['DELETE', 'PATCH', 'PATCH']);
  assert.ok(peer.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
  assert.deepEqual(tab.exceptions, []);
  assert.deepEqual(peer.exceptions, []);
  return { realBackend: true, labelEditedEvidenceUnchanged: true, archiveOrganizationOnly: true, archiveDistinctFromExport: true,
    defaultListingHidesArchived: true, typedConfirmationRequiresFileName: true, deleteRequests: 1, jobDirectoryRemoved: true,
    peerTabReconciled: true, deepLinkReloadShowsDeleted: true, apiGone: 410, noUndoPromised: true,
    keyboardReturnFocus: landingFocus, mutationRequests: methods.length, executionStarted: false };
}
