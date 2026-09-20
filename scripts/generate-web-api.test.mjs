import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const files = [
  'scripts/generate-web-api.mjs',
  'contracts/web/v1/contract.schema.json',
  'frontend/src/api/generated.ts',
  'frontend/src/api/generated-schema.ts',
];

function check(root, expectedStatus = 0) {
  const result = spawnSync(process.execPath, [join(root, 'scripts/generate-web-api.mjs'), '--check'], {
    encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, expectedStatus, result.stderr);
  return result;
}

test('the generated API drift gate rejects schema and both TypeScript output changes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'decomp-api-drift-test-'));
  try {
    for (const path of files) {
      const target = join(root, path);
      await mkdir(dirname(target), { recursive: true });
      await copyFile(join(sourceRoot, path), target);
    }

    assert.match(check(root).stdout, /Web API generated contracts verified/);
    const types = join(root, 'frontend/src/api/generated.ts');
    const schemaModule = join(root, 'frontend/src/api/generated-schema.ts');
    const source = join(root, 'contracts/web/v1/contract.schema.json');

    for (const path of [types, schemaModule]) {
      const original = await readFile(path);
      await writeFile(path, Buffer.concat([original, Buffer.from('\n// unintended drift\n')]));
      assert.match(check(root, 1).stderr, /Generated contract drift:/);
      assert.deepEqual(await readFile(path), Buffer.concat([original, Buffer.from('\n// unintended drift\n')]),
        'The check must report drift without silently rewriting the file');
      await writeFile(path, original);
      check(root);
    }

    const originalSchema = await readFile(source);
    const changed = JSON.parse(originalSchema);
    changed.definitions.driftProbe = { type: 'string', enum: ['new-contract-case'] };
    await writeFile(source, `${JSON.stringify(changed, null, 2)}\n`);
    assert.match(check(root, 1).stderr, /Generated contract drift:/);
    assert.deepEqual(await readFile(types), await readFile(join(sourceRoot, 'frontend/src/api/generated.ts')),
      'Schema drift must not silently regenerate TypeScript during CI');
    await writeFile(source, originalSchema);
    check(root);

    const unsupported = JSON.parse(originalSchema);
    unsupported.definitions.driftProbe = { type: 'string', minProperties: 1 };
    await writeFile(source, `${JSON.stringify(unsupported, null, 2)}\n`);
    assert.match(check(root, 1).stderr, /Unsupported schema keyword: minProperties/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
