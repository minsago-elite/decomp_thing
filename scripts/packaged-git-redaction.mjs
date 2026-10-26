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
