import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

/** Test-only persisted data, written before server ownership; never invokes a workflow. */
export async function seedHistory(root) {
  await fs.mkdir(root, { mode: 0o700 }); // Refuse any existing root, including links.
  const jobId = 'd'.repeat(32);
  const directory = join(root, jobId);
  await fs.mkdir(directory, { mode: 0o700 });
  const input = Buffer.alloc(64);
  input.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  input.writeUInt16LE(2, 16); input.writeUInt16LE(62, 18); input.writeUInt32LE(1, 20); input.writeUInt16LE(64, 52);
  const at = '2026-09-05T00:00:00Z';
  const job = { id: jobId, filename: 'synthetic-history.elf', status: 'uploaded', created_at: at, updated_at: at,
    size_bytes: 64, binary_path: join(directory, 'input.elf'), metadata: { format: 'ELF64', endianness: 'little',
      elf_version: 1, os_abi: 'System V', object_type: 'EXEC', machine: 'x86-64', entry_point: 0,
      elf_header_size: 64, program_header_count: 0, section_header_count: 0, section_name_table_index: 0 } };
  const jobBytes = JSON.stringify(job);
  const attempts = Array.from({ length: 55 }, (_, index) => {
    const state = ['completed', 'failed', 'interrupted'][index % 3];
    const time = new Date(Date.parse(at) + index * 2000).toISOString();
    return { runId: `run_fixture_${index}`, jobId, workflow: 'reconstruct', state, version: `version_fixture_${index}`,
      createdAt: time, startedAt: time, endedAt: new Date(Date.parse(time) + 1000).toISOString(),
      previousRunId: index ? `run_fixture_${index - 1}` : null, inputRevisionId: null, harnessCapabilityId: null,
      limits: { wallClockMs: '60000', idleMs: '15000', maxOutputBytes: '1048576', maxToolCalls: '16' },
      terminalReason: { completed: 'COMPLETED', failed: 'FAILED', interrupted: 'PROCESS_INTERRUPTED' }[state],
      usage: { inputTokens: '18446744073709551615', outputTokens: null, cachedInputTokens: null, toolCalls: '0', wallClockMs: '1000' },
      candidate: state === 'completed' ? { revisionId: `revision_fixture_${index}`, sourceSha256: 'e'.repeat(64) } : null,
      acceptedRevision: null };
  });
  const state = { schemaVersion: 1, jobId, version: 'version_fixture_history',
    legacy: { originalJobSha256: createHash('sha256').update(jobBytes).digest('hex'), status: 'uploaded', recoveredInterrupted: false },
    attempts, acceptedRevision: null };
  const retained = { 'input.elf': input, 'job.json': jobBytes, 'workflow-state.json': JSON.stringify(state) };
  for (const [name, bytes] of Object.entries(retained)) await fs.writeFile(join(directory, name), bytes, { flag: 'wx', mode: 0o600 });
  const reportDirectory = join(directory, 'reports', 'runs', 'run_fixture_3');
  await fs.mkdir(reportDirectory, { recursive: true, mode: 0o700 });
  const exploration = JSON.stringify({ candidateCount: 1, coverageIncreased: true, baselineOutputSignatures: 0,
    expandedOutputSignatures: 1, newOutputSignatures: ['synthetic'], angr: null,
    confidence: { score: 0.5, inputCount: 1, sourceCount: 1, outputSignatureCount: 1,
      newOutputSignatureCount: 1, sandboxed: true, networkIsolated: false }, candidates: [{}], observations: [] });
  const reportPath = join(reportDirectory, 'exploration.json');
  await fs.writeFile(reportPath, exploration, { flag: 'wx', mode: 0o600 });
  return { jobId, directory, retained, count: attempts.length, reportPath, exploration };
}

export async function qualifyHistory({ fixture, makeTarget, cdp, evaluate, ready, browserOrigin }) {
  const tab = await makeTarget();
  const path = `/nested/jobs/${fixture.jobId}/runs`;
  const rows = `Array.from(document.querySelectorAll('ul[aria-label="Recorded attempts"] a')).map(a => a.textContent)`;
  await cdp.call('Page.navigate', { url: browserOrigin + path }, tab.sessionId);
  await ready(tab, `(${rows}).length === 50`, 'first populated attempt page');
  assert.deepEqual(await evaluate(tab, rows), Array.from({ length: 50 }, (_, i) => `reconstruct: run_fixture_${54 - i}`));
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Next attempts').click()`);
  await ready(tab, `(${rows}).length === 5`, 'second populated attempt page');
  assert.deepEqual(await evaluate(tab, rows), Array.from({ length: 5 }, (_, i) => `reconstruct: run_fixture_${4 - i}`));
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `(${rows}).length === 5`, 'saved history cursor after reload');
  await evaluate(tab, `document.querySelector('a[href="${path}/run_fixture_3"]').click()`);
  await ready(tab, `document.querySelector('h1')?.textContent === 'Workflow attempt' && document.body.innerText.includes('18446744073709551615')`, 'earlier populated attempt');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('not-evaluated') && document.body.innerText.includes('revision_fixture_3') && document.body.innerText.includes('Not reported')`));
  assert.equal(await evaluate(tab, 'location.pathname'), `${path}/run_fixture_3`);
  await cdp.call('Page.reload', {}, tab.sessionId);
  await ready(tab, `document.body.innerText.includes('revision_fixture_3')`, 'pinned earlier attempt reload');
  await evaluate(tab, `[...document.querySelectorAll('button')].find(b => b.textContent === 'Read exploration evidence').click()`);
  await ready(tab, `document.body.innerText.includes('Report state: available. Authority: observations.') && document.body.innerText.includes('Producer confidence score')`, 'bound exploration summary');
  assert.ok(await evaluate(tab, `document.body.innerText.includes('not proof of equivalence')`));
  assert.equal(await fs.readFile(fixture.reportPath, 'utf8'), fixture.exploration);
  await evaluate(tab, `[...document.querySelectorAll('a')].find(a => a.textContent === 'Open previous attempt').click()`);
  await ready(tab, `document.body.innerText.includes('PROCESS_INTERRUPTED')`, 'previous interrupted attempt');
  assert.equal(await evaluate(tab, 'location.pathname'), `${path}/run_fixture_2`);
  assert.ok(tab.requests.every(request => ['GET', 'HEAD'].includes(request.method)));
  assert.deepEqual(tab.exceptions, []);
  for (const [name, bytes] of Object.entries(fixture.retained)) assert.deepEqual(await fs.readFile(join(fixture.directory, name)), Buffer.from(bytes));
  assert.deepEqual((await fs.readdir(fixture.directory)).sort(), [...Object.keys(fixture.retained), 'reports'].sort());
  return { fixtureAttempts: 55, firstPage: 50, secondPage: 5, exactOrder: true, cursorReload: true,
    earlierAttemptReload: true, previousInterruptedAttempt: true, exactUnsignedUsage: true,
    unacceptedCandidate: true, explorationSummary: true, reportBytesUnchanged: true, retainedBytesUnchanged: true, mutationRequests: 0, executionStarted: false };
}
