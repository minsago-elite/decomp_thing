import assert from 'node:assert/strict';
import test from 'node:test';
import { promises as fs } from 'node:fs';
import { resolve, join } from 'node:path';
import { inspectLiveStorage } from './packaged-browser-live.mjs';

async function fixture(t) {
  const parent = resolve('build/test-tmp/live-storage');
  await fs.mkdir(parent, { recursive: true });
  const root = await fs.mkdtemp(join(parent, 'fixture-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const jobs = [{ id: 'a'.repeat(32) }];
  await fs.mkdir(join(root, jobs[0].id));
  for (const name of ['.web-owner.lock', '.workflow-owner.lock']) await fs.writeFile(join(root, name), 'owner');
  await fs.mkdir(join(root, '.web-audit'));
  await fs.writeFile(join(root, '.web-audit/current.jsonl'), 'authored audit fixture\n');
  await fs.writeFile(join(root, '.web-audit/incomplete'), '0');
  return { root, jobs };
}

test('live storage qualification recognizes audit metadata while retaining its bytes and both owner locks', async t => {
  const { root, jobs } = await fixture(t);
  const before = await inspectLiveStorage(root, jobs);
  assert.equal(before.owners.length, 2);
  assert.deepEqual(before.audit.map(entry => entry.name), ['current.jsonl', 'incomplete']);
  assert.deepEqual(await inspectLiveStorage(root, jobs), before);
  await fs.writeFile(join(root, '.web-audit/current.jsonl'), 'unexpected mutation');
  assert.notDeepEqual((await inspectLiveStorage(root, jobs)).audit, before.audit);
});

test('unknown hidden storage entries are still rejected', async t => {
  const { root, jobs } = await fixture(t);
  await fs.mkdir(join(root, '.unexpected'));
  await assert.rejects(inspectLiveStorage(root, jobs), assert.AssertionError);
});

test('audit directory and segment links cannot masquerade as listener metadata', async t => {
  for (const segment of [false, true]) {
    const { root, jobs } = await fixture(t);
    const path = join(root, segment ? '.web-audit/current.jsonl' : '.web-audit');
    const original = `${root}-original`;
    t.after(() => fs.rm(original, { recursive: true, force: true }));
    await fs.rename(path, original);
    await fs.symlink(original, path);
    await assert.rejects(inspectLiveStorage(root, jobs), assert.AssertionError);
  }
});
