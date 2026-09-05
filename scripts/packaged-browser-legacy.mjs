import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';

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
  return { id, directory, reports, input, job, jobPath, journalPath, journal, artifactPath };
}

export async function qualifyLegacy({ fixture, origin, tab, cdp, evaluate, ready }) {
  // Test-owned state only: emulate an in-progress legacy observation after startup recovery.
  // No workflow is admitted or executed. These fixture writes are not application mutations.
  const activeJob = JSON.stringify({ ...fixture.job, status: 'analyzing' });
  await fs.writeFile(fixture.jobPath, activeJob);
  await cdp.call('Page.navigate', { url: `${origin}/jobs/${fixture.id}` }, tab.sessionId);
  await ready(tab, `document.querySelector('#agent-event-list')?.innerText.includes('18446744073709551615')`, 'legacy initial progress');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('Stored diagnostic details are withheld')`));
  assert.ok(await evaluate(tab, `document.body.innerText.includes('fixture.txt')`));
  assert.ok(!await evaluate(tab, `document.body.innerText.includes('PRIVATE_LEGACY_')`));
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
  assert.ok(tab.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
  assert.equal(await fs.readFile(fixture.jobPath, 'utf8'), activeJob);
  assert.equal(await fs.readFile(fixture.journalPath, 'utf8'), fixture.journal);
  assert.equal(await fs.readFile(fixture.artifactPath, 'utf8'), 'ordinary artifact');
  assert.deepEqual(await fs.readFile(join(fixture.directory, 'input.elf')), fixture.input);
  return { initialHtml: true, pollingExecuted: true, privateDiagnosticsWithheld: true, privateEventFieldsWithheld: true,
    exactUsage: true, omissionCount: 2, missingJournalPreservesRows: true, validEmptyClearsRows: true,
    restoredJournalRecovers: true, reload: true, artifactMetadata: true, pageExceptions: 0, mutationRequests: 0,
    workflowAdmitted: false, testOwnedFixtureEdits: ['status set to analyzing after startup', 'journal removed, emptied and restored'],
    finalJobInputArtifactBytesUnchanged: true, finalJournalMatchesOriginal: true };
}
