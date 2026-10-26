import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assertCredentialAbsent, credentialCanaries, scanCredentialStorage } from './packaged-git-redaction.mjs';

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
