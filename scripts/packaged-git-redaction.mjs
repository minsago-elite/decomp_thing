import assert from 'node:assert/strict';
import { createReadStream, promises as fs } from 'node:fs';
import { join, relative } from 'node:path';

/** Match the server's HTTPS credential representations, including the actual child extraHeader. */
export function credentialCanaries(username, password) {
  const pair = `${username}:${password}`;
  const encoded = Buffer.from(pair).toString('base64');
  return [password, pair, encoded, `Basic ${encoded}`, `Authorization: Basic ${encoded}`];
}

/** Never echo the matched credential into test logs or retained evidence. */
export function assertCredentialAbsent(value, canaries, surface) {
  for (const canary of canaries) {
    assert.equal(value.includes(canary), false, `A credential representation reached ${surface}`);
  }
}

/**
 * Browser-serializable collector: a failed/missing DTO must never count as redaction coverage.
 * Keep all dependencies inside this function so the packaged browser and negative controls run
 * exactly the same code. Error bodies are deliberately not counted as successful surfaces.
 */
export async function collectGitRedactionSurfaces(base, jobId, merged, uiText, fetchRead = globalThis.fetch) {
  function requireSurface(condition, name) {
    if (!condition) throw new Error(`Required redaction surface ${name} is unavailable or has unexpected contents`);
  }
  const surfaces = [];
  async function read(name, url, kind, valid) {
    const response = await fetchRead(url, { credentials: 'same-origin' });
    requireSurface(response?.ok && response.status === 200, name);
    const text = await response.text();
    let dto;
    try { dto = JSON.parse(text); } catch { requireSurface(false, name); }
    requireSurface(dto?.apiVersion === 1 && dto.kind === kind && dto.data !== null && typeof dto.data === 'object', name);
    requireSurface(valid(dto.data), name);
    surfaces.push({ name, text });
    return dto.data;
  }
  const listing = await read('listing', base, 'gitRepositories', data => data.jobId === jobId
    && Array.isArray(data.repositories) && data.repositories.length === 1
    && typeof data.repositories[0]?.repositoryId === 'string' && data.repositories[0].repositoryId.length > 0
    && Array.isArray(data.operations) && data.operations.length > 0);
  const repository = listing.repositories[0].repositoryId;
  const path = base + '/' + encodeURIComponent(repository);
  await read('bootstrap', '/nested/api/v1/bootstrap', 'bootstrap', data => Array.isArray(data.apiVersions) && data.apiVersions.includes(1)
    && Array.isArray(data.capabilities) && data.capabilities.length > 0 && typeof data.runtime?.javaVersion === 'string');
  await read('workspace', path, 'gitWorkspace', data => data.repositoryId === repository && data.headObjectId === merged
    && typeof data.worktreeId === 'string' && typeof data.repositoryVersion === 'string' && Array.isArray(data.refs));
  await read('remotes', path + '/remotes', 'gitRemotes', data => data.repositoryId === repository && data.configured === true
    && Array.isArray(data.remotes) && ['origin', 'canary'].every(name => data.remotes.some(remote => remote?.name === name)));
  await read('audit', path + '/audit?limit=200', 'gitAudit', data => data.repositoryId === repository && Array.isArray(data.entries)
    && data.entries.some(entry => entry?.action === 'push' && entry.outcome === 'published' && entry.newObjectId === merged));
  await read('status', path + '/status', 'gitStatus', data => data.repositoryId === repository && data.headObjectId === merged
    && typeof data.worktreeId === 'string' && Array.isArray(data.entries) && typeof data.complete === 'boolean');
  await read('history', path + '/history', 'gitHistory', data => data.repositoryId === repository && Array.isArray(data.entries)
    && data.entries.some(entry => entry?.objectId === merged && typeof entry.subject === 'string'));
  await read('refs', path + '/refs', 'gitRefs', data => data.repositoryId === repository && Array.isArray(data.refs)
    && data.refs.some(ref => ref?.displayName === 'refs/heads/main' && ref.objectId === merged));
  requireSurface(typeof uiText === 'string' && uiText.includes('Source repository') && uiText.includes('canary.invalid'), 'UI');
  surfaces.push({ name: 'UI', text: uiText });
  return surfaces;
}

/** Stream every regular file, without a size exclusion; include matches spanning chunk boundaries. */
export async function scanCredentialStorage(root, canaries) {
  const overlap = Math.max(...canaries.map(value => Buffer.byteLength(value))) - 1;
  const coverage = { regularFiles: 0, bytes: 0, skippedNonRegular: [] };
  async function walk(directory) {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile()) {
        coverage.regularFiles++;
        let tail = Buffer.alloc(0);
        for await (const chunk of createReadStream(path, { highWaterMark: 64 * 1024 })) {
          coverage.bytes += chunk.length;
          const bytes = Buffer.concat([tail, chunk]);
          assertCredentialAbsent(bytes, canaries, `stored file ${relative(root, path)}`);
          tail = bytes.subarray(Math.max(0, bytes.length - overlap));
        }
      } else coverage.skippedNonRegular.push(relative(root, path));
    }
  }
  await walk(root);
  return coverage;
}
