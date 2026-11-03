import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { assertGracefulShutdown, assertOnlyPinWrites, boundReport, findBootstrap, isProgressReadUrl, publishAtomically, scrubTokens, summarizeRequests } from './packaged-browser-restart.mjs';

const origin = 'http://127.0.0.1:4000';

test('finds only a well-formed same-origin bootstrap handoff', () => {
  assert.deepEqual(findBootstrap(`ready\n${origin}/nested/#bootstrap=abc_-9\n`, origin), { url: `${origin}/nested/#bootstrap=abc_-9`, token: 'abc_-9' });
  assert.equal(findBootstrap('http://127.0.0.1:5000/nested/#bootstrap=abc', origin), null);
  assert.equal(findBootstrap(`${origin}/nested/#bootstrap=a%20b`, origin), null);
  assert.equal(findBootstrap('', origin), null);
});

test('accepts only a lone SIGTERM and a graceful exit', () => {
  assert.equal(assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: 143, signalCode: null }).exitCode, 143);
  assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: 0, signalCode: null });
  assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: null, signalCode: 'SIGTERM' });
  assert.throws(() => assertGracefulShutdown({ signalsSent: ['SIGTERM', 'SIGKILL'], exitCode: null, signalCode: 'SIGKILL' }));
  assert.throws(() => assertGracefulShutdown({ signalsSent: [], exitCode: 0, signalCode: null }));
  assert.throws(() => assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: null, signalCode: 'SIGKILL' }));
  assert.throws(() => assertGracefulShutdown({ signalsSent: ['SIGTERM'], exitCode: 1, signalCode: null }));
});

test('scrubs bootstrap tokens recursively', () => {
  const scrubbed = scrubTokens({ a: ['x secret1 y'], b: { c: `${origin}/nested/#bootstrap=other` }, n: 3 }, ['secret1', '']);
  assert.deepEqual(scrubbed, { a: ['x [redacted] y'], b: { c: `${origin}/nested/#bootstrap=[redacted]` }, n: 3 });
});

test('bounds reports by replacing request lists with counts', () => {
  const small = { requests: { a: [1] } };
  assert.equal(boundReport(small, 1000), small);
  const big = { status: 'passed', requests: { a: Array.from({ length: 1000 }, () => ({ method: 'GET', url: 'x'.repeat(50) })) } };
  assert.deepEqual(boundReport(big, 2000).requests, { a: { count: 1000, truncated: true } });
  assert.throws(() => boundReport({ blob: 'x'.repeat(5000), requests: {} }, 1000));
  assert.throws(() => boundReport({ blob: 'é'.repeat(600), requests: {} }, 1000),
    'UTF-8 encoded report bytes must be bounded, not JavaScript code units');
});

test('only pin PUTs to the selected attempt are accepted mutations', () => {
  const pin = `${origin}/nested/api/v1/jobs/j/runs/run_fixture_3/progress-pin`;
  const session = `${origin}/nested/api/v1/session`;
  const get = { method: 'GET', url: pin };
  assertOnlyPinWrites([get, { method: 'PUT', url: pin }], pin, 1);
  assertOnlyPinWrites([get], pin, 0);
  assertOnlyPinWrites([{ method: 'POST', url: session }, { method: 'PUT', url: pin }], pin, 1, session, 1);
  assert.throws(() => assertOnlyPinWrites([{ method: 'PUT', url: pin }, { method: 'PUT', url: pin }], pin, 1));
  assert.throws(() => assertOnlyPinWrites([{ method: 'PUT', url: pin.replace('run_fixture_3', 'run_fixture_4') }], pin, 1));
  assert.throws(() => assertOnlyPinWrites([{ method: 'POST', url: pin }], pin, 1));
  assert.throws(() => assertOnlyPinWrites([{ method: 'POST', url: session }], pin, 0, session, 0));
  assert.throws(() => assertOnlyPinWrites([{ method: 'DELETE', url: pin }], pin, 0, session, 0));
  assert.deepEqual(summarizeRequests([get, { method: 'PUT', url: pin }]), { total: 2, methods: { GET: 1, PUT: 1 }, mutations: [{ method: 'PUT', url: pin }] });
});

test('counts progress reads with cursor queries without matching unrelated routes', () => {
  assert.equal(isProgressReadUrl(`${origin}/nested/api/v1/jobs/j/runs/r/events?after=204&limit=200`), true);
  assert.equal(isProgressReadUrl(`${origin}/nested/api/v1/jobs/j/runs/r/snapshot?revision=1`), true);
  assert.equal(isProgressReadUrl(`${origin}/nested/api/v1/jobs?cursor=events`), false);
  assert.equal(isProgressReadUrl('/nested/api/v1/jobs/j/runs/r/events?after=204'), false);
});

test('publishes by atomic rename and leaves no temporary file', async () => {
  const build = join(process.cwd(), 'build');
  await mkdir(build, { recursive: true });
  const directory = await mkdtemp(join(build, 'restart-publish-'));
  try {
    const path = join(directory, 'agent-progress.json');
    await writeFile(path, 'old');
    await publishAtomically(path, 'new');
    assert.equal(await readFile(path, 'utf8'), 'new');
    assert.deepEqual(await readdir(directory), ['agent-progress.json']);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
