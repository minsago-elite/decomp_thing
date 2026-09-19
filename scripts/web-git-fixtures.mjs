// Test-only Git histories for D-series local/remote workflow checks.
// Every process is restricted to file transport and uses no user Git config.
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';

const identities = Object.freeze({
  author: 'Web Fixture Author',
  committer: 'Web Fixture Committer',
});

function runGit(cwd, args, { date = '2026-01-01T00:00:00Z', expectStatus = 0 } = {}) {
  const environment = {
    PATH: process.env.PATH ?? '/usr/bin:/bin', LC_ALL: 'C', TZ: 'UTC',
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_TERMINAL_PROMPT: '0', GIT_ALLOW_PROTOCOL: 'file',
    GIT_AUTHOR_NAME: identities.author, GIT_AUTHOR_EMAIL: 'web-fixture@example.invalid',
    GIT_COMMITTER_NAME: identities.committer, GIT_COMMITTER_EMAIL: 'web-fixture@example.invalid',
    GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date,
  };
  const result = spawnSync('git', [
    '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgSign=false',
    '-c', 'tag.gpgSign=false', '-c', 'core.autocrlf=false', ...args,
  ], { cwd, env: environment, encoding: 'utf8', timeout: 15_000, maxBuffer: 1024 * 1024 });
  if (result.error) throw result.error;
  if (result.status !== expectStatus) {
    throw new Error(`Git fixture command failed (${result.status}, expected ${expectStatus}): git ${args[0]}: ${result.stderr.trim()}`);
  }
  return { stdout: result.stdout, stderr: result.stderr, status: result.status };
}

/**
 * Create two path-independent histories with a real bare remote. The local and
 * peer branches diverge; `conflicted` additionally leaves an unmerged index.
 * Call dispose() when finished. No test data is created outside its private root.
 */
export async function createWebGitFixture({ state = 'diverged' } = {}) {
  if (!['diverged', 'conflicted'].includes(state)) throw new Error('Unknown Git fixture state');
  const root = await mkdtemp(join(tmpdir(), 'decomp-web-git-'));
  if (!isAbsolute(root)) throw new Error('Temporary Git fixture root must be absolute');
  const paths = Object.freeze({ root, local: join(root, 'local'), peer: join(root, 'peer'), remote: join(root, 'remote.git') });
  let disposed = false;
  const git = (repository, args, options) => {
    if (disposed || !['local', 'peer', 'remote'].includes(repository) || !Array.isArray(args)
      || args.length === 0 || args.some(arg => typeof arg !== 'string')) throw new Error('Invalid Git fixture command');
    return runGit(paths[repository], args, options);
  };
  try {
    runGit(root, ['init', '--bare', '--object-format=sha1', '--initial-branch=main', paths.remote]);
    runGit(root, ['init', '--object-format=sha1', '--initial-branch=main', paths.local]);
    await writeFile(join(paths.local, 'README.md'), 'Synthetic Git workflow fixture. No production source.\n');
    await writeFile(join(paths.local, 'shared.txt'), 'baseline\n');
    git('local', ['add', '--', 'README.md', 'shared.txt']);
    git('local', ['commit', '-m', 'fixture: baseline'], { date: '2026-01-01T00:00:00Z' });
    git('local', ['remote', 'add', 'origin', paths.remote]);
    git('local', ['push', '-u', 'origin', 'main']);
    runGit(root, ['clone', '--no-local', '--branch', 'main', paths.remote, paths.peer]);

    if (state === 'conflicted') {
      await writeFile(join(paths.local, 'shared.txt'), 'local edit\n');
      await writeFile(join(paths.peer, 'shared.txt'), 'remote edit\n');
    } else {
      await writeFile(join(paths.local, 'local.txt'), 'local-only fixture change\n');
      await writeFile(join(paths.peer, 'remote.txt'), 'remote-only fixture change\n');
    }
    const changed = state === 'conflicted' ? 'shared.txt' : 'local.txt';
    git('local', ['add', '--', changed]);
    git('local', ['commit', '-m', 'fixture: local branch'], { date: '2026-01-01T00:00:01Z' });
    const remoteChanged = state === 'conflicted' ? 'shared.txt' : 'remote.txt';
    git('peer', ['add', '--', remoteChanged]);
    git('peer', ['commit', '-m', 'fixture: remote branch'], { date: '2026-01-01T00:00:02Z' });
    git('peer', ['push', 'origin', 'main']);
    git('local', ['fetch', 'origin', 'main']);
    git('local', ['push', 'origin', 'main:refs/heads/feature']);
    const commits = Object.freeze({
      base: git('local', ['merge-base', 'main', 'origin/main']).stdout.trim(),
      local: git('local', ['rev-parse', 'main']).stdout.trim(),
      remote: git('local', ['rev-parse', 'origin/main']).stdout.trim(),
    });
    if (state === 'conflicted') git('local', ['merge', '--no-edit', 'origin/main'], { expectStatus: 1 });
    return Object.freeze({ state, paths, branches: Object.freeze({ base: 'main', head: 'feature' }), commits, git, async dispose() {
      if (disposed) return;
      disposed = true;
      await rm(root, { recursive: true });
    } });
  } catch (error) {
    disposed = true;
    await rm(root, { recursive: true });
    throw error;
  }
}
