import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, symlink } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const dir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(dir, '..');
const build = path.join(root, 'build');

function runGit(repo, ...args) {
  const result = spawnSync('git', ['--git-dir', repo, ...args], { encoding: 'utf8', timeout: 30_000, maxBuffer: 2 * 1024 * 1024, env: { PATH: process.env.PATH, HOME: '/nonexistent', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' } });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

test('generates reproducible 10,000 commit scale repositories with boundary commits', async t => {
  await mkdir(build, { recursive: true });
  const tempA = await mkdtemp(path.join(build, '.git-scale-a-'));
  const tempB = await mkdtemp(path.join(build, '.git-scale-b-'));
  const a = path.join(tempA, 'fixture');
  const b = path.join(tempB, 'fixture');
  t.after(async () => { await rm(tempA, { recursive: true, force: true }); await rm(tempB, { recursive: true, force: true }); });
  for (const output of [a, b]) {
    const result = spawnSync(process.execPath, [path.join(dir, 'generate-git-scale-repo.mjs'), output], { cwd: root, encoding: 'utf8', timeout: 120_000, maxBuffer: 2 * 1024 * 1024 });
    assert.equal(result.status, 0, result.stderr);
  }
  const ma = JSON.parse(await readFile(path.join(a, 'manifest.json'), 'utf8'));
  const mb = JSON.parse(await readFile(path.join(b, 'manifest.json'), 'utf8'));
  assert.deepEqual(ma, mb);
  assert.equal(ma.commitCount, 10_000);
  assert.equal(ma.branch, 'refs/heads/main');
  for (const base of [a, b]) {
    const repo = path.join(base, 'history.git');
    assert.equal(runGit(repo, 'rev-list', '--count', 'refs/heads/main'), '10000');
    assert.equal(runGit(repo, 'branch', '--list'), '* main');
    assert.equal(runGit(repo, 'symbolic-ref', 'HEAD'), 'refs/heads/main');
    assert.equal(ma.commitIds.length, 10_000);
    assert.equal(ma.commitIds[0], ma.firstCommit);
    assert.equal(ma.commitIds.at(-1), ma.tip);
    assert.equal(runGit(repo, 'diff-tree', '--no-commit-id', '--name-only', '-r', ma.commitIds[99]).split('\n').length, 2000);
    assert.equal(runGit(repo, 'diff-tree', '--no-commit-id', '--name-only', '-r', ma.commitIds[199]).split('\n').length, 2001);
    const textPath = 'large/patch.txt', binaryPath = 'large/payload.bin';
    assert.ok(Number(runGit(repo, 'cat-file', '-s', `refs/heads/main:${textPath}`)) > 128 * 1024);
    assert.equal(Number(runGit(repo, 'cat-file', '-s', `refs/heads/main:${binaryPath}`)), 3 * 1024 * 1024);
    assert.equal(runGit(repo, 'rev-parse', 'refs/heads/main'), ma.tip);
    assert.ok([...runGit(repo, 'log', '-1', '--format=%s')].length > 200);
  }
});

test('rejects output parents reached through symlinks before creating fixture files', async t => {
  await mkdir(build, { recursive: true });
  const parent = await mkdtemp(path.join(build, '.git-scale-safety-'));
  t.after(() => rm(parent, { recursive: true, force: true }));
  const outsideBuild = path.join(parent, 'link');
  await symlink(root, outsideBuild);
  const output = path.join(outsideBuild, 'fixture');
  const result = spawnSync(process.execPath, [path.join(dir, 'generate-git-scale-repo.mjs'), output], {
    cwd: root, encoding: 'utf8', timeout: 10_000, maxBuffer: 100_000,
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /output parent must be a real directory beneath/);
});
