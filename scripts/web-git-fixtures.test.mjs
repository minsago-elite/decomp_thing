import assert from 'node:assert/strict';
import { lstat } from 'node:fs/promises';
import test from 'node:test';
import { createWebGitFixture } from './web-git-fixtures.mjs';
import { createFakeGitHubFixture } from './web-github-fixture.mjs';

test('independent roots produce the same isolated diverged history and disposable remote', async () => {
  const first = await createWebGitFixture();
  const second = await createWebGitFixture();
  try {
    assert.notEqual(first.paths.root, second.paths.root);
    assert.deepEqual(first.commits, second.commits);
    assert.match(first.commits.base, /^[0-9a-f]{40}$/);
    assert.notEqual(first.commits.local, first.commits.remote);
    assert.equal(first.git('local', ['rev-list', '--left-right', '--count', 'main...origin/main']).stdout.trim(), '1\t1');
    assert.equal(first.git('local', ['status', '--porcelain']).stdout, '');
    assert.equal(first.git('peer', ['status', '--porcelain']).stdout, '');
    assert.equal(first.git('remote', ['rev-parse', 'refs/heads/main']).stdout.trim(), first.commits.remote);
    assert.equal(first.git('remote', ['rev-parse', 'refs/heads/feature']).stdout.trim(), first.commits.local);
    assert.equal(first.git('local', ['show', 'main:local.txt']).stdout, 'local-only fixture change\n');
    assert.equal(first.git('local', ['show', 'origin/main:remote.txt']).stdout, 'remote-only fixture change\n');
    assert.equal(first.git('local', ['remote', 'get-url', 'origin']).stdout.trim(), first.paths.remote);
    assert.equal(first.git('local', ['config', '--get', 'core.hooksPath']).stdout.trim(), '/dev/null');
    assert.equal((await lstat(first.paths.root)).mode & 0o777, 0o700);
    assert.equal(first.git('local', ['log', '-1', '--format=%at|%ct']).stdout.trim(),
      `${Date.parse('2026-01-01T00:00:01Z') / 1000}|${Date.parse('2026-01-01T00:00:01Z') / 1000}`);
    console.log(`web-git-fixture: ${JSON.stringify({ state: first.state, commits: first.commits, branches: first.branches })}`);
    assert.throws(() => first.git('outside', ['status']), /Unsupported Git fixture inspection/);
    for (const args of [
      ['-C', '/tmp/decomp-d-607', 'rev-parse', '--show-toplevel'],
      ['--git-dir', '/tmp/decomp-d-607/.git', 'status'],
      ['--git-dir=/tmp/decomp-d-607/.git', 'status'],
      ['--work-tree', '/tmp/decomp-d-607', 'status'],
      ['-c', 'core.hooksPath=/tmp', 'status'],
      ['--config-env', 'core.hooksPath=PATH', 'status'],
      ['status', '--git-dir=/tmp/decomp-d-607/.git'],
      ['status', '--work-tree=/tmp/decomp-d-607'],
      ['status', '--config-env=core.hooksPath=PATH'],
      ['show', 'main:README.md', '--output=/tmp/escape'],
      ['diff', '--no-index', '/etc/hosts', '/etc/passwd'],
      ['worktree', 'add', '/tmp/escape'],
      ['fetch', 'https://example.invalid/no-network'],
      ['config', '--global', 'user.name'],
      ['config', '--file', '/tmp/escape', 'user.name', 'Escape'],
      ['commit', '-m', 'outside mutation'],
    ]) assert.throws(() => first.git('local', args), /Unsupported Git fixture inspection/);
  } finally {
    await first.dispose();
    await second.dispose();
  }
  await assert.rejects(lstat(first.paths.root), { code: 'ENOENT' });
  await assert.rejects(lstat(second.paths.root), { code: 'ENOENT' });
});

test('a fixture-owned executable hook cannot run during deterministic construction', async () => {
  const guarded = await createWebGitFixture({ poisonHooks: true });
  const control = await createWebGitFixture();
  try {
    assert.deepEqual(guarded.commits, control.commits);
    assert.equal(guarded.git('local', ['config', '--get', 'core.hooksPath']).stdout.trim(), '/dev/null');
  } finally {
    await guarded.dispose();
    await control.dispose();
  }
});

test('conflicted history leaves a real unmerged index and deterministic branch tips', async () => {
  const first = await createWebGitFixture({ state: 'conflicted' });
  const second = await createWebGitFixture({ state: 'conflicted' });
  try {
    assert.deepEqual(first.commits, second.commits);
    assert.equal(first.git('local', ['rev-list', '--left-right', '--count', 'main...origin/main']).stdout.trim(), '1\t1');
    assert.equal(first.git('local', ['diff', '--name-only', '--diff-filter=U']).stdout, 'shared.txt\n');
    assert.match(first.git('local', ['status', '--porcelain']).stdout, /^UU shared\.txt\n$/);
    assert.equal(first.git('local', ['show', ':1:shared.txt']).stdout, 'baseline\n');
    assert.equal(first.git('local', ['show', ':2:shared.txt']).stdout, 'local edit\n');
    assert.equal(first.git('local', ['show', ':3:shared.txt']).stdout, 'remote edit\n');
    assert.equal(first.git('remote', ['rev-parse', 'refs/heads/feature']).stdout.trim(), first.commits.local);
    assert.equal(first.git('remote', ['rev-parse', 'refs/heads/main']).stdout.trim(), first.commits.remote);
  } finally {
    await first.dispose();
    await second.dispose();
  }
});

test('fake GitHub PR lifecycle is deterministic, duplicate-safe and credential-free', async () => {
  const provider = createFakeGitHubFixture();
  const path = `${provider.repository}/pulls`;
  const payload = JSON.stringify({ head: 'feature', base: 'main', title: 'Synthetic change', body: 'No real source or credential.' });
  const headers = { Authorization: `Bearer ${provider.token}`, 'Content-Type': 'application/json' };
  try {
    assert.equal(provider.handle({ method: 'POST', path, body: payload }).status, 401);
    assert.equal(provider.handle({ method: 'POST', path, headers: { ...headers, Authorization: 'Bearer real-secret' }, body: payload }).status, 401);
    assert.equal(provider.handle({ method: 'POST', path, headers, body: payload }).status, 201);
    assert.equal(provider.handle({ method: 'POST', path, headers, body: payload }).body.errors[0].code, 'already_exists');
    const listed = provider.handle({ method: 'GET', path: `${path}?state=open&head=fixture-owner:feature&base=main` });
    assert.equal(listed.body.length, 1);
    assert.equal(listed.body[0].html_url, 'https://fixture.invalid/fixture-owner/fixture-repo/pull/1');
    assert.equal(provider.handle({ method: 'GET', path: `${path}/1` }).body.number, 1);
    assert.equal(provider.handle({ method: 'PATCH', path: `${path}/1`, headers, body: '{"state":"closed"}' }).body.state, 'closed');
    assert.deepEqual(provider.handle({ method: 'GET', path: `${path}?state=open` }).body, []);
    assert.equal(provider.handle({ method: 'POST', path, headers, body: payload }).body.number, 2);
    assert.equal(provider.handle({ method: 'GET', path: `${path}?state=all` }).body.length, 2);
    assert.equal(provider.handle({ method: 'POST', path, headers, body: JSON.stringify({ head: 'missing', base: 'main', title: 'Bad', body: '' }) }).status, 422);
    assert.equal(provider.handle({ method: 'GET', path: `${path}/99` }).status, 404);
    assert.equal(JSON.stringify(provider.requests).includes('real-secret'), false);
    assert.equal(JSON.stringify(provider.requests).includes(provider.token), false);
  } finally { await provider.dispose(); }
});
