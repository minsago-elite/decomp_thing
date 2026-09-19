# Isolated web Git fixtures (#607)

`scripts/web-git-fixtures.mjs` supplies real, small Git histories for future D8/D9
tests. `createWebGitFixture()` creates a private temporary root with a local
repository, a peer clone, and a bare remote. The local and remote `main` tips
each have one distinct commit after a common base; the local tip is also
published as remote `feature`, ready for an optional PR test. Use
`createWebGitFixture({ state: 'conflicted' })` to leave `shared.txt` in a real
three-stage unmerged index after a conflicting merge attempt. The `commits`,
`branches`, `paths`, and `git(repository, args)` properties expose the fixture
without making a real user repository a test input.

```js
import { createWebGitFixture } from './scripts/web-git-fixtures.mjs';
import { createFakeGitHubFixture } from './scripts/web-github-fixture.mjs';

const git = await createWebGitFixture({ state: 'diverged' });
const github = createFakeGitHubFixture({
  headRefs: [git.branches.head], baseRefs: [git.branches.base],
});
try {
  const difference = git.git('local', ['rev-list', '--left-right', '--count', 'main...origin/main']);
  const fake = github.handle({
    method: 'POST', path: `${github.repository}/pulls`,
    headers: { Authorization: `Bearer ${github.token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ head: 'feature', base: 'main', title: 'Synthetic review', body: '' }),
  });
  // difference.stdout is "1\t1\n"; fake.status is 201.
} finally {
  await github.dispose();
  await git.dispose();
}
```

The fake provider can also `await github.listen()` on an ephemeral
`127.0.0.1` port and returns a `baseUrl`/`close()` pair. It supports PR
create, duplicate rejection, filtered list, detail and state change at
`/repos/fixture-owner/fixture-repo/pulls`. Its review links end in
`fixture.invalid`; only the fixed `fixture-only-token` permits writes. It does
not contact GitHub or accept a real credential. Its request log excludes
headers and bodies. This is a deliberately small API fake, not a claim of
GitHub production compatibility or authorization completeness.

The Git child-process environment omits user secrets, ignores system/global
config, disables hooks and signing, forbids non-file transport, fixes authors
and dates, and bounds command time/output. Generated roots are distinct and
removed only by their own `dispose()`. Tests compare exact commit IDs across
independent roots, exercise both clean divergence and actual conflict stages,
verify hook and network suppression, and check the fake PR lifecycle through
both its in-process handler and the loopback adapter. The CI frontend job runs
the Node test suite and retains its output. Bun also runs the process-only
suite locally; the loopback test uses the repository-pinned Node runtime.

This is a reusable synthetic fixture foundation. It does not implement the
managed Git workspace, remote credential handling, review UI, or full #214
fixture family, and no live remote or production workflow is qualified here.
