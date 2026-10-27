import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assertCredentialAbsent, collectGitRedactionSurfaces, credentialCanaries, scanCredentialStorage } from './packaged-git-redaction.mjs';

// Exercise the exact dependency-free function injected into the packaged browser.
const collect = new Function(`return (${collectGitRedactionSurfaces.toString()})`)();
const base = '/nested/api/v1/jobs/1234567890abcdef1234567890abcdef/repositories';
const jobId = '1234567890abcdef1234567890abcdef';
const merged = '0123456789abcdef0123456789abcdef01234567';
const uiText = 'Source repository · canary.invalid';
const names = ['listing', 'bootstrap', 'workspace', 'remotes', 'audit', 'status', 'history', 'refs'];

async function surfaceFixture() {
  const files = ['git-repositories', 'bootstrap', 'git-workspace', 'git-remotes', 'git-audit', 'git-status', 'git-history', 'git-refs'];
  const dtos = await Promise.all(files.map(async file => JSON.parse(await fs.readFile(new URL(`../contracts/web/v1/fixtures/${file}.json`, import.meta.url), 'utf8'))));
  const repositoryId = dtos[0].data.repositories[0].repositoryId;
  for (const dto of dtos.slice(2)) dto.data.repositoryId = repositoryId;
  dtos[2].data.headObjectId = merged;
  dtos[3].data.remotes[0].name = 'origin';
  dtos[3].data.remotes[1].name = 'canary';
  dtos[4].data.entries.push({ action: 'push', outcome: 'published', newObjectId: merged });
  dtos[7].data.refs[0].displayName = 'refs/heads/main';
  const path = base + '/' + repositoryId;
  const urls = [base, '/nested/api/v1/bootstrap', path, path + '/remotes', path + '/audit?limit=200', path + '/status', path + '/history', path + '/refs'];
  const responses = new Map(urls.map((url, index) => [url, { status: 200, dto: dtos[index] }]));
  const fetched = [];
  const fetchRead = async (url, options) => {
    assert.equal(options.credentials, 'same-origin');
    fetched.push(url);
    const response = responses.get(url);
    if (!response) return undefined;
    return new Response(response.raw ?? JSON.stringify(response.dto), { status: response.status });
  };
  return { dtos, urls, responses, fetchRead, fetched };
}

test('coverage requires every named successful DTO and the real browser UI', async () => {
  const fixture = await surfaceFixture();
  const surfaces = await collect(base, jobId, merged, uiText, fixture.fetchRead);
  assert.deepEqual(surfaces.map(surface => surface.name), [...names, 'UI']);
  assert.deepEqual(fixture.fetched, fixture.urls, 'each required read is checked exactly once');
  for (const { text, name } of surfaces) assertCredentialAbsent(text, ['synthetic-secret'], name);
});

for (const [index, name] of names.entries()) {
  for (const failure of ['HTTP 503', 'missing response', 'null data', 'wrong kind', 'malformed JSON']) {
    test(`coverage rejects ${failure} on required ${name} surface`, async () => {
      const fixture = await surfaceFixture();
      const response = fixture.responses.get(fixture.urls[index]);
      if (failure === 'HTTP 503') response.status = 503;
      if (failure === 'missing response') fixture.responses.delete(fixture.urls[index]);
      if (failure === 'null data') response.dto.data = null;
      if (failure === 'wrong kind') response.dto.kind = 'error';
      if (failure === 'malformed JSON') response.raw = 'not JSON';
      await assert.rejects(collect(base, jobId, merged, uiText, fixture.fetchRead), new RegExp(`Required redaction surface ${name}`));
    });
  }
  test(`coverage rejects empty ${name} contents despite a successful envelope`, async () => {
    const fixture = await surfaceFixture();
    fixture.dtos[index].data = {};
    await assert.rejects(collect(base, jobId, merged, uiText, fixture.fetchRead), new RegExp(`Required redaction surface ${name}`));
  });
}

test('a valid listing followed only by unavailable reads cannot pass credential-absence qualification', async () => {
  const fixture = await surfaceFixture();
  for (const url of fixture.urls.slice(1)) fixture.responses.get(url).status = 503;
  await assert.rejects(collect(base, jobId, merged, uiText, fixture.fetchRead), /Required redaction surface bootstrap/);
});

test('coverage rejects stale repository content and missing scenario evidence', async () => {
  for (const [index, field, value] of [[0, 'jobId', 'another-job'], [2, 'headObjectId', 'stale'], [3, 'remotes', []],
    [4, 'entries', []], [5, 'repositoryId', 'another-repository'], [6, 'entries', []], [7, 'refs', []]]) {
    const fixture = await surfaceFixture();
    fixture.dtos[index].data[field] = value;
    await assert.rejects(collect(base, jobId, merged, uiText, fixture.fetchRead), new RegExp(`Required redaction surface ${names[index]}`));
  }
  const fixture = await surfaceFixture();
  await assert.rejects(collect(base, jobId, merged, '', fixture.fetchRead), /Required redaction surface UI/);
});

const password = 'synthetic-secret-positive-control';
const encoded = Buffer.from(`canary-bot:${password}`).toString('base64');
const canaries = credentialCanaries('canary-bot', password);
const representations = [password, `canary-bot:${password}`, encoded, `Basic ${encoded}`, `Authorization: Basic ${encoded}`];

for (const [index, representation] of representations.entries()) {
  test(`redaction rejects credential representation ${index} on both response and storage surfaces`, async () => {
    assert.throws(() => assertCredentialAbsent(`response: ${representation}`, canaries, 'response'), /credential representation/);
    const root = await fs.mkdtemp(join(tmpdir(), 'git-redaction-'));
    try {
      await fs.writeFile(join(root, 'record'), `stored: ${representation}`);
      await assert.rejects(scanCredentialStorage(root, canaries), /credential representation/);
    } finally { await fs.rm(root, { recursive: true, force: true }); }
  });
}

test('storage scanner rejects a split encoded credential beyond the former 16 MiB exclusion', async () => {
  const root = await fs.mkdtemp(join(tmpdir(), 'git-redaction-'));
  try {
    const file = await fs.open(join(root, 'large-record'), 'w');
    try {
      // Sparse zeros keep construction cheap; the Base64 token crosses a 64 KiB chunk boundary.
      await file.write(encoded, 16 * 1024 * 1024 + 64 * 1024 - 3);
    } finally { await file.close(); }
    await assert.rejects(scanCredentialStorage(root, canaries), /credential representation/);
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});

test('clean coverage counts every regular-file byte and explicitly reports non-regular exclusions', async () => {
  const root = await fs.mkdtemp(join(tmpdir(), 'git-redaction-'));
  try {
    await fs.mkdir(join(root, 'nested'));
    await fs.writeFile(join(root, 'nested', 'record'), 'safe');
    await fs.writeFile(join(root, 'empty'), '');
    await fs.symlink('nested/record', join(root, 'link'));
    assertCredentialAbsent('Credential configured on the server', canaries, 'response');
    assert.deepEqual(await scanCredentialStorage(root, canaries), { regularFiles: 2, bytes: 4, skippedNonRegular: ['link'] });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
});
