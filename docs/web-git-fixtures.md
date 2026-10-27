# Isolated web Git fixtures (#607)

`scripts/web-git-fixtures.mjs` supplies real, small Git histories for future D8/D9
tests. `createWebGitFixture()` creates a private temporary root with a local
repository, a peer clone, and a bare remote. The local and remote `main` tips
each have one distinct commit after a common base; the local tip is also
published as remote `feature`, ready for an optional PR test. Use
`createWebGitFixture({ state: 'conflicted' })` to leave `shared.txt` in a real
three-stage unmerged index after a conflicting merge attempt. The `commits`,
`branches`, `paths`, and `git(repository, args)` properties expose the fixture
without making a real user repository a test input. `git()` permits only a
small audited set of read-only inspections; it rejects Git global options,
config/work-tree overrides, output files, mutation commands and arbitrary
network targets before starting a process. Exercise mutations through the
adapter under test, pointed at the fixture-owned paths. Future inspection
forms require explicit review rather than widening this helper generically.

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
prove an executable fixture hook is skipped, reject public-helper repository
and network escapes, and check the fake PR lifecycle through
both its in-process handler and the loopback adapter. The CI frontend job runs
the Node test suite and retains its output. Bun also runs the process-only
suite locally; the loopback test uses the repository-pinned Node runtime.

This is a reusable synthetic fixture foundation. It does not implement the
managed Git workspace, remote credential handling, review UI, or full #214
fixture family, and no live remote or production workflow is qualified here.

## Git adapter extension contract

The current production v1 dispatcher has no managed repository/worktree Git
operations. The [architecture](web-architecture.md) and
[versioned API contract](web-api.md#git-object-and-revision-binding) define the
implementation boundary below. The fixture factories above supply isolated
histories and a fake provider for that work; current schema availability does not
advertise a production Git capability.

### Typed service boundary and argument/configuration isolation

The HTTP adapter must accept a closed typed intent with registered job,
repository/worktree/ref identities, version guards and explicit source selection.
The service resolves managed roots, checks authorization and capability, reserves
bounded resources and persists the operation identity. The Git adapter alone
selects the trusted executable, working directory and allowlisted argv. Keep raw
shell commands, global Git options, arbitrary paths/URLs and credential values
outside browser requests and public DTOs.

Validate identities before argv construction and resolve files through the shared
source/artifact containment policy. Imported config, hooks, filters, external diff
helpers, attributes, submodules and credential helpers must not run implicitly.
Use an explicit sanitized environment and reviewed configuration/transport policy;
disabling only global config is insufficient for an imported repository. Local
status/history/navigation remain reads and cannot initiate fetch or publication.
Remote operations require a separately enabled permitted transport and an opaque
server-side credential handle. Display only sanitized remote labels and fixed
public failure reasons. Keep credentials and raw transport diagnostics private.

The existing test fixture provides a concrete limited process boundary:

| Fixture behavior | Current implementation |
|---|---|
| Child environment | A fresh map with PATH, C locale, UTC, fixed author/committer names/dates, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_TERMINAL_PROMPT=0` and file-only transport. |
| Invocation | `spawnSync` receives a separate argv array and fixture-owned cwd, with hooks/signing disabled. |
| Bounds | A 15-second child timeout and 1 MiB captured output; generated roots are private and independently disposable. |
| Public inspection | `git(repository, args)` accepts only its small reviewed read-only forms and registered local/peer/remote roots. |
| Synthetic provider | In-process handling or an ephemeral loopback HTTP server; only `fixture-only-token` permits its fake writes, and request records omit headers/bodies. |

Those fixtures construct their own controlled repositories and select Git from
their test PATH. A production adapter still needs its trusted executable,
imported-repository policy, durable operations and complete hostile-input/cleanup
qualification. Preserve the [production budget and trust contract](web-trust.md#git-and-remote-deployment)
when implementing that adapter; fixture timeout/output settings describe these
tests, not newly qualified production resource limits.

### Repository, source and evidence identity mapping

Keep the following identities separate at every DTO, service and persistence seam:

| Identity | Role |
|---|---|
| `repositoryId` / `worktreeId` | Registered managed repository and workspace, with their own versions and containment policy. |
| `refId` / `objectId` / `objectFormat` | Registered ref and full opaque Git object identity. An adapter must validate the declared format; the current fixture deliberately constructs SHA-1 histories. |
| `jobId` / `runId` / `revisionId` | Job, explicit workflow attempt and immutable source snapshot registration. |
| `sourceSha256` / `archiveArtifactId` | Canonical source-tree commitment and the artifact verified against that same source snapshot. |
| Acceptance/evidence reference | The separate canonical validation/publication relationship for that revision. |
| `operationId` | Durable typed intent, guards, stage/outcome and recovery requirements for one explicit Git operation. |

Do not truncate object IDs for a write, convert them to numbers or assume every
production repository uses the fixture's 40-character format. Preserve the declared
format and reject unknown/unqualified write identities. Branch names and display
abbreviations are not source-snapshot or acceptance authority.

The provenance record binds
`(repositoryId, objectId, revisionId, sourceSha256, archiveArtifactId)` and separately
the acceptance evidence reference/state. Materialize an admitted immutable source
snapshot from the exact selected tree, compute the existing canonical source
commitment, and verify the archive against those same bytes. Multiple commits can
contain the same source, and a commit can identify an unvalidated candidate. Keep
unknown legacy mappings unknown. Imported commits, resolved conflicts and edited
working trees return through the existing candidate validation/publication path.

Read snapshots carry repository/worktree versions and observed HEAD/ref objects.
Mutations recheck those guards under the operation's repository/worktree lock;
changed refs or dirty/conflicting snapshots require an explicit fresh review.
Push binds the registered remote/ref, exact local object and expected remote
object, with the expected value enforced at the update boundary. Preserve local
dirty/unpushed work. Recovery reconciles durable intent with actual refs before
offering an explicit next action; restart/navigation never silently repeats a
remote write, resets/stashes work or publishes a PR.

### Use the fixture factories to test the adapter seam

Use `createWebGitFixture({ state: 'diverged' })` for independent local/remote commits
and `{ state: 'conflicted' }` for the real three-stage index. The existing example
above combines the managed histories with `createFakeGitHubFixture`; exercise new
adapter mutations against only those owned paths. `poisonHooks: true` supplies a
controlled executable hook for suppression checks. Retain `finally` disposal for
every factory and for any acquired loopback server.

With the pinned Node and repository-local `TMPDIR` from
[the setup guide](web-packaging.md#repository-local-frontend-setup-and-rebuilds):

```sh
node --test scripts/web-git-fixtures.test.mjs \
  scripts/web-github-fixture-http.test.mjs
```

These existing checks compare exact commits across independent roots, verify
divergence/conflict stages and disabled hooks, reject inspection escapes and
exercise fake PR create/duplicate/list/detail/close behavior without a real remote
or credential. Keep these controls when adding the production adapter. Extend its
own tests for hostile imported config/paths, stale versions/refs, dirty work,
concurrent operations, bounded cancellation and crash/publication ambiguity.
Assert that rejected requests start no operation and retained failures do not
become accepted source or a claimed cleanup success. The fixture suite's passing
result alone cannot establish that unimplemented adapter behavior.
