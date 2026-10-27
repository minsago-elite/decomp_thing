import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { snapshotLiveAudit } from './packaged-browser-live.mjs';

async function fixture(run) {
  const parent = new URL('../build/test-tmp/live-audit/', import.meta.url);
  await fs.mkdir(parent, { recursive: true });
  const root = await fs.mkdtemp(join(parent.pathname, 'store-'));
  const audit = join(root, '.web-audit');
  await fs.mkdir(audit);
  await fs.writeFile(join(audit, 'current.jsonl'), '{"action":"session.start"}\n');
  await fs.writeFile(join(audit, 'incomplete'), '0');
  try { await run(root, audit); } finally { await fs.rm(root, { recursive: true }); }
}

test('live qualification captures legitimate audit files and detects later writes', async () => {
  await fixture(async (root, audit) => {
    const before = await snapshotLiveAudit(root);
    assert.deepEqual(await snapshotLiveAudit(root), before);
    await fs.appendFile(join(audit, 'current.jsonl'), '{"unexpected":"mutation"}\n');
    assert.notDeepEqual(await snapshotLiveAudit(root), before);
  });
});

test('live qualification rejects unexpected hidden storage inside audit', async () => {
  await fixture(async (root, audit) => {
    await fs.writeFile(join(audit, 'unexpected'), 'not allowed');
    await assert.rejects(snapshotLiveAudit(root), assert.AssertionError);
  });
});

test('live qualification rejects symlinked audit directories and segments', async () => {
  await fixture(async (root, audit) => {
    const segment = join(audit, 'current.jsonl');
    await fs.rename(segment, join(root, 'outside-segment'));
    await fs.symlink(join(root, 'outside-segment'), segment);
    await assert.rejects(snapshotLiveAudit(root), assert.AssertionError);
    await fs.unlink(segment);
    await fs.rename(join(root, 'outside-segment'), segment);
    await fs.rename(audit, join(root, 'other-audit'));
    await fs.symlink(join(root, 'other-audit'), audit);
    await assert.rejects(snapshotLiveAudit(root), assert.AssertionError);
  });
});
