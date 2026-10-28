import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { assertLiveStorageInventory, seedLive } from './packaged-browser-live.mjs';

const build = resolve(dirname(fileURLToPath(import.meta.url)), '../build');

async function fixture(t) {
  await fs.mkdir(build, { recursive: true });
  const temporary = await fs.mkdtemp(join(build, 'packaged-live-inventory-'));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  const seeded = await seedLive(join(temporary, 'store'));
  for (const name of ['.web-owner.lock', '.workflow-owner.lock']) {
    await fs.writeFile(join(seeded.root, name), '', { flag: 'wx', mode: 0o600 });
  }
  await fs.mkdir(join(seeded.root, '.web-audit'), { mode: 0o700 });
  return seeded;
}

test('live inventory admits server-owned audit storage without changing fixture data', async t => {
  const { root, jobs, input } = await fixture(t);
  await fs.writeFile(join(root, '.web-audit/current.jsonl'), 'server-owned audit entry\n');
  await assertLiveStorageInventory(root, jobs);
  for (const job of jobs) {
    assert.deepEqual(await fs.readFile(join(root, job.id, 'input.elf')), input);
    assert.equal(await fs.readFile(join(root, job.id, 'job.json'), 'utf8'), JSON.stringify(job));
  }
  assert.equal(await fs.readFile(join(root, '.web-audit/current.jsonl'), 'utf8'), 'server-owned audit entry\n');
});

test('live inventory still rejects unexpected root files and missing jobs or owner locks', async t => {
  const { root, jobs } = await fixture(t);
  await fs.writeFile(join(root, '.unexpected'), 'unexpected');
  await assert.rejects(assertLiveStorageInventory(root, jobs), assert.AssertionError);
  await fs.unlink(join(root, '.unexpected'));
  for (const name of ['.web-owner.lock', '.workflow-owner.lock', jobs[0].id]) {
    await fs.rename(join(root, name), join(root, '..', 'held'));
    await assert.rejects(assertLiveStorageInventory(root, jobs), assert.AssertionError);
    await fs.rename(join(root, '..', 'held'), join(root, name));
  }
  await assertLiveStorageInventory(root, jobs);
});

test('live inventory rejects missing, symlinked and non-directory audit storage', async t => {
  const { root, jobs } = await fixture(t);
  const audit = join(root, '.web-audit');
  await fs.rmdir(audit);
  await assert.rejects(assertLiveStorageInventory(root, jobs), assert.AssertionError);
  await fs.symlink(jobs[0].id, audit);
  await assert.rejects(assertLiveStorageInventory(root, jobs), /Audit storage must be a real directory/);
  await fs.unlink(audit);
  await fs.writeFile(audit, 'not a directory');
  await assert.rejects(assertLiveStorageInventory(root, jobs), /Audit storage must be a real directory/);
});
