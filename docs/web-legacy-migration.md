# Legacy route, API and persisted-job migration

This is the migration contract and evidence for [#230](https://github.com/minsago-elite/decomp_thing/issues/230)
([#662](https://github.com/minsago-elite/decomp_thing/issues/662),
[#663](https://github.com/minsago-elite/decomp_thing/issues/663),
[#664](https://github.com/minsago-elite/decomp_thing/issues/664)). Issue status lives in GitHub. The behavior
below is what `master` does today and is pinned by `src/test/kotlin/decompengine/web/WebLegacyMigrationTest.kt`;
a test also checks that the route table below matches the tested table row for row.

## What changes and what does not

The release ships two presentations over the same job store: the legacy Kotlin-rendered workbench
(`llm_bin_patch web`, still the default) and the embedded SPA (`llm_bin_patch web --ui spa`). Both open a data
directory written by the D0 release. Neither presentation rewrites `job.json`, reports, source trees or archives,
and opening any link in either presentation never starts exploration, reconstruction, repair or authentication
inspection.

**Compatibility window.** Legacy routes keep their documented behavior in the legacy presentation through the first
D-series release and at least one subsequent minor release, as promised in
[the API contract](web-api.md#legacy-compatibility). The sunset release and date are not yet published; they are
owned by the legacy UI removal checkpoint ([#231](https://github.com/minsago-elite/decomp_thing/issues/231)),
which must publish successor links before removing any row below. Until then a user who depends on a row marked
*legacy presentation only* starts the server without `--ui spa`.

## Route matrix

`J` is a retained job ID. Status codes are the answers to a request carrying a valid local session (see
[sessions](web-api.md#legacy-session-migration)); without one, pages answer 401 and the SPA's public shell routes
still load. "SPA" means the SPA presentation (`--ui spa`) on the same data directory.

| Case | Legacy route | Legacy | SPA | Migration outcome | Parity |
| --- | --- | --- | --- | --- | --- |
| MIG-01 | `GET /` | 200 | 200 | Equivalent: job library in both. | PAR-01 |
| MIG-02 | `GET /login` | 200 | 404 | Deliberate deprecation in the SPA: the launcher prints `/#bootstrap=…` instead of `/login#bootstrap=…`. | — |
| MIG-03 | `GET /assets/app.css` | 200 | 404 | Deliberate deprecation: the SPA serves hashed assets under `/assets/ui/`. | PAR-16 |
| MIG-04 | `GET /jobs/{J}` | 200 | 200 | Equivalent: job overview at the same path. | PAR-04 |
| MIG-05 | `GET /jobs/{I}` | 200 | 200 | Equivalent; a historically interrupted job (`{I}`) shows interruption, not a running attempt. | PAR-08 |
| MIG-06 | `GET /jobs/{J}/source/src/modules/core.c` | 200 | 404 | Legacy presentation only. SPA source views are revision-bound (`/jobs/J/runs/R/revisions/V/sources`); a D0 job has no run or revision identity, so none is invented. | PAR-11, PAR-12 |
| MIG-07 | `GET /jobs/{J}/artifacts/reports/exploration.json` | 200 | 404 | Legacy presentation only. The SPA download (`/api/v1/jobs/J/artifacts/A/content`) is run-bound. | PAR-14 |
| MIG-08 | `GET /jobs/{J}/artifacts/reports/source-tree.zip` | 400 | 404 | Unverified D0 archives are refused, never relabelled verified; bytes are kept. | PAR-15 |
| MIG-09 | `GET /api/jobs/{J}` | 200 | 404 | Legacy presentation only, sanitized projection; successor `GET /api/v1/jobs/J`. | PAR-17 |
| MIG-10 | `HEAD /api/jobs/{J}` | 200 | 404 | As MIG-09, without a body. | PAR-17 |
| MIG-11 | `GET /api/jobs/{J}/events` | 503 | 404 | Legacy presentation only; a D0 job has no retained journal, so `PROGRESS_UNAVAILABLE` (never an empty history). Successor `GET /api/v1/jobs/J/runs/R/events`. | PAR-07 |
| MIG-12 | `GET /api/recovery` | 200 | 404 | Successor `GET /api/v1/recovery` (display-only). | PAR-08 |
| MIG-13 | `GET /api/operator/auth-methods` | 200 | 404 | Legacy presentation only operator status; no SPA successor yet. | — |
| MIG-14 | `GET /jobs/{J}/explore` | 404 | 404 | Opening an execution URL is not a request to execute. | PAR-05 |
| MIG-15 | `GET /jobs/{J}/reconstruct` | 404 | 404 | As MIG-14. | PAR-06 |
| MIG-16 | `GET /api/v1/jobs/{J}` | 404 | 200 | The v1 job DTO exists only in the SPA presentation; legacy mode advertises no successor prematurely. | PAR-17 |
| MIG-17 | `GET /api/v1/recovery` | 404 | 200 | As MIG-16. | PAR-08 |

Every 404 above is a JSON `NOT_FOUND` envelope (or the legacy HTML error page for MIG-14/MIG-15 in the legacy
presentation); API, attachment and source requests never receive the SPA shell. No answer copies a stored
`status_message`, host path or exception text. The legacy `GET /api/jobs/J` body has exactly the documented keys
`id`, `filename`, `status`, `created_at`, `updated_at`, `size_bytes` and `metadata`; a D0 record without
`updated_at` reports its `created_at`, and `metadata.entry_point` stays numeric. Legacy API failures use
`{requestId, error: {code, message}}`.

**Explicit execution routes.** `POST /jobs` (upload), `POST /jobs/J/explore`, `POST /jobs/J/reconstruct` and
`POST /api/operator/auth-methods` remain explicit, session- and CSRF-guarded requests in the legacy presentation.
In the SPA presentation each answers 404 or 405 and starts nothing, even with a valid session and CSRF token;
SPA uploads use `POST /api/v1/jobs` and SPA workflow starts use the v1 run API.

**In the browser.** The packaged legacy browser journey (`scripts/packaged-browser-legacy.mjs`) opens a D0-shaped
job and asserts that the only non-GET requests are the session exchange, the explicit upload and sign-out. In the
SPA on `master`, the typed client's only mutations are the session exchange, upload, progress pin and the attempt
cancel/recover commands, each sent only from an explicit control; no SPA code path starts a workflow (the launch
form is pending in #1702). The SPA routes added by the D-series (`/runtime`, `/upload`, attempt, activity, evidence
and source views) are specified in [navigation](web-navigation.md) and exercised by the packaged browser suite
(#225).

## Persisted-job upgrade

Upgrading means starting the current build on a data directory written by an earlier one. Startup inspects every
job record within fixed bounds and only then applies recovery writes. The rehearsal in the test runs the sequence
legacy → SPA → SPA → legacy on a D0-shaped store (three jobs: completed with exploration report, generated source
tree, manifest, progress report and an unverified archive; historically `analyzing`; plain `uploaded`). Each
`job.json` is written the way the D0 `JobStore.persist` (`27feba3`) wrote it: pretty-printed and newline-terminated;
the completed job's record predates `updated_at` and carries a private `status_message`. After every lifecycle the
test hashes every file and checks:

- every pre-existing file is byte-identical, including `job.json`, `input.elf`, every report, the source tree,
  its manifest and the archive;
- no directory is created or removed;
- exactly these files are added, and nothing else:

| Added file | Written when | Contents |
| --- | --- | --- |
| `<data-dir>/.web-owner.lock` | First start on an existing directory | Empty; cross-process web ownership lock |
| `<data-dir>/.workflow-owner.lock` | First start on an existing directory | Empty; workflow-store ownership lock |
| `<data-dir>/<job>/workflow-state.json` | Only for a job whose D0 status was `queued` or `analyzing` | `schemaVersion: 1`, `attempts: []`, `legacy.status`, `legacy.recoveredInterrupted: true` and the SHA-256 of the unchanged `job.json` |

A D0 job whose status was `queued` or `analyzing` is not rewritten to `failed`, and no attempt is invented for it;
it is shown as historically interrupted and needs an explicit new request. Other jobs get no sidecar at all.
Later lifecycles on the same directory change nothing. The SPA's progress retention worker acts only on journals of
recorded attempts; D0 jobs have none, and the SPA lifecycles in the rehearsal write nothing.

## Migration failure and rollback

**Failure preserves data.** Startup reads every record before writing any. A damaged `job.json`
(`CORRUPT_LEGACY_JOB`), a damaged `workflow-state.json` (`CORRUPT_WORKFLOW_STATE`) or an unsupported workflow
schema (`UNSUPPORTED_WORKFLOW_SCHEMA`) refuses startup in both presentations before any recovery write. Every
stored byte stays in place; at most the two empty lock files appear. The launcher prints fixed guidance instead of
a stack trace and exits with status 2, for example:

```text
Job storage refused startup (CORRUPT_LEGACY_JOB). A job.json upload record is damaged or uses an unsupported shape. Preserve it and restore a verified backup of that job directory before retrying.
No recovery changes were applied; stored job files are unchanged.
Back up the stopped data directory before editing it; see docs/web-legacy-migration.md (Migration failure and rollback).
```

The guidance never includes record contents, host paths or exception text. If a refusal reports that recovery
changes may have begun (an I/O failure after the write phase started), preserve the whole directory and reconcile it
before retrying. A record damaged while the server is already running is isolated instead: the library shows a
diagnostic row for it and the other jobs remain readable (covered by `DurableWebWorkflowTest` and
`UploadServerTest`).

**Back up before upgrading.** The server does not take an automatic backup. Before upgrading, stop the server and
copy the whole data directory (for example `cp -a <data-dir> <data-dir>.pre-upgrade`). The test performs this copy,
runs the upgrade, then restores it and confirms the restored tree hashes identically and serves again.

**Rollback is explicit.**

- *Presentation rollback* (SPA back to the legacy presentation of the same build) needs nothing: both read the same
  files and the test shows no further writes.
- *Downgrade to the D0 release* (by inspection of the `27feba3` source; not executed): D0 reads `job.json`, which
  is unchanged, and ignores files at the data-directory root and any `workflow-state.json`. It sees a historically
  `analyzing` job with its original status and applies its own restart behavior, rewriting that `job.json` to
  `failed` with an interruption message. On a later re-upgrade the current build keeps the existing sidecar, whose
  recorded historical status still labels the job as interrupted, and rewrites nothing. If you need byte-identical
  history across a downgrade, restore the pre-upgrade backup instead of starting D0 on the upgraded directory.
- *A newer schema seen by an older build*: when a later release writes `workflow-state.json` with a schema version
  this build does not support, this build refuses startup with `UNSUPPORTED_WORKFLOW_SCHEMA` and leaves the file
  unchanged (tested by rewriting the version to 2). It never silently downgrades or rewrites a newer schema. Start the
  newer release again, or restore the backup taken before that upgrade.

## Non-Git jobs and user repositories

Jobs from the D0 release are not Git repositories and stay fully usable without one: overview, legacy and v1 job
reads answer normally. No Git workspace routes exist on `master` (the Git workspace, read, commit, remote, push and
GitHub work is in open pull requests #1701, #1705, #1708, #1734, #1760, #1765, #1767 and #1771), so nothing can
attach Git implicitly. Migration and restart never create a `.git` entry in the job store and never run Git.

The test places the job store inside a user's own Git working tree and runs both presentations. Afterwards the
repository's `HEAD`, every ref, its object count, stash list, local configuration and index bytes are identical.
The only `git status` difference is the job store's own untracked files. Keep the data directory outside source
repositories anyway; when managed Git lands, attaching a repository to a job must remain an explicit action and is
specified in [the Git contract](web-api.md) and [Git fixtures](web-git-fixtures.md).

## Evidence and remaining gaps

| Claim | Evidence | Status |
| --- | --- | --- |
| Every D0 route has an equivalent, redirect or deliberate deprecation | MIG matrix, `every legacy route answers its documented migration outcome…` | Merged behavior, tested |
| Legacy JSON compatibility and sanitized responses | MIG-09/10, exact key set, error envelope, private-diagnostic and host-path checks | Tested; sunset date unpublished (#231) |
| Opening old deep links or migrated jobs starts nothing | Analyzer/reconstructor counters, byte-identical storage after every GET/HEAD, SPA POST refusals | Tested at the server; browser journey in #225 |
| Upgrade/restart/rollback preserve authoritative bytes | `upgrade restart and presentation rollback preserve…` | Tested |
| Failure preserves data with actionable guidance | Damaged-record and newer-schema refusals, `webStorageStartupGuidance` | Tested |
| Non-Git jobs and user repository history untouched | `migration never creates or invokes Git…` | Tested; managed Git pending in open PRs |

Remaining gaps, for the removal checkpoint (#231) rather than this contract:

- D0 source trees, exploration reports and archives of jobs without a recorded attempt are browsable only in the
  legacy presentation (MIG-06, MIG-07, MIG-11). Removing the legacy presentation needs an SPA view for unattributed
  historical evidence, labelled as such, or a scoped deferral.
- The successor links and sunset date for the legacy JSON routes are not yet published.
- No automatic pre-upgrade backup exists; the documented procedure is a stopped-server copy.
- The rehearsal runs in the JVM test harness against synthetic D0-shaped files, not against a retained data
  directory produced by an actual D0 release binary.
