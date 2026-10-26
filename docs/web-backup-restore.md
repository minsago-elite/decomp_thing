# Backing up and restoring workbench data

This document covers [#666](https://github.com/minsago-elite/decomp_thing/issues/666) under
tracker [#232](https://github.com/minsago-elite/decomp_thing/issues/232). It describes how
to back up and restore the web workbench data directory without changing any stored byte. It is
written against `master` at `33c49f95`. The managed Git section describes work that is still in
open pull requests.

The [operations guide](web-operations.md) shows how to inspect a store before and after these
steps. The [user guide](workbench-user-guide.md) explains what users see.

## What the data directory holds

Everything the workbench persists lives under the `--data-dir` passed to `web`. The default is
`.decomp_engine/jobs`, resolved against the launcher's working directory. Application files in the
installed distribution are never written. The store looks like this:

```text
<data-dir>/
  .web-owner.lock                     advisory lock of the live web server (empty)
  .workflow-owner.lock                advisory lock of the workflow store (empty)
  .upload-stream-v1-<digits>/         only while an upload is unpublished, or after a crash
  <32-hex job id>/
    input.elf                         the uploaded binary
    job.json                          upload record (fields below)
    upload-receipt.json               idempotency receipt of a streamed upload (schemaVersion 1)
    workflow-state.json               durable attempts and accepted revision (schemaVersion 1)
    workflow-state.pending.json       only while a state write is in progress, or after a crash
    reports/                          legacy single-run reports
    reports/runs/<run id>/            per-attempt reports: agent-progress.json, exploration.json,
                                      validation reports, source trees, source-tree.zip, ...
```

| Record | Format and compatibility boundary |
|---|---|
| `job.json` | Unversioned. Keys are limited to `id`, `filename`, `status`, `created_at`, `updated_at`, `status_message`, `size_bytes`, `binary_path` and `metadata`, and the reader rejects any other key. **`binary_path` is the absolute path of `<data-dir>/<id>/input.elf`, and every read checks it against the store's current location.** |
| `workflow-state.json` | `schemaVersion` 1. Holds every attempt, its state and version, the candidate revision, the accepted-revision reference (job, run, revision, source SHA-256, graph node, artifact and artifact SHA-256), pin audit and cancellation receipts. It also keeps `legacy.originalJobSha256`, the SHA-256 of the `job.json` it was derived from. Any other `schemaVersion` is refused with `UNSUPPORTED_WORKFLOW_SCHEMA`. |
| `upload-receipt.json` | `schemaVersion` 1. Binds the idempotency key and intent hashes to the published job. |
| `reports/runs/<run>/agent-progress.json` | Progress journal, `schemaVersion` 1. Terminal journals may be compacted by retention unless the attempt is pinned. See the [API contract](web-api.md). |
| Reports, source trees and archives | Producer-owned bytes. The server reads them through fixed containment rules and never rewrites them. |

The server writes no other files. It does not keep a separate database, cache or index that a
backup would need to capture.

## Procedure

1. **Stop the server** and any CLI process that uses the same data directory. Ownership is
   enforced with the lock files above. A copy taken from a live store can mix a renamed state file
   with an older report, and the procedure does not support that.
2. **Record where the store lives.** Use the absolute path, for example `realpath <data-dir>`.
   You must restore to this same absolute path; see [why](#restore-to-the-same-absolute-path).
3. **Write a manifest** of every regular file except the empty lock files:

   ```sh
   cd <data-dir>
   find . -type f ! -name '*.lock' -print0 | sort -z | xargs -0 sha256sum > ../jobs.sha256
   ```

4. **Copy the store byte for byte**, keeping modes and timestamps, for example
   `tar -C <parent> -cpf jobs-backup.tar <name>`. Do not exclude the pending files or
   `.upload-stream-v1-*` directories: if they exist, they record an interrupted operation that
   startup must reconcile. Copying the lock files is harmless; they carry no content.
5. **Store the manifest with the archive**, and record the application version and
   `applicationBuildId` from the [operations guide](web-operations.md#version-and-build-identity).

To restore:

1. Stop the server and move the damaged store aside. Do not delete it until the restore is
   verified.
2. Extract the backup to **the original absolute path**, for example `tar -C <parent> -xpf jobs-backup.tar`.
3. Run `sha256sum -c ../jobs.sha256` from inside the restored directory. Every line must say `OK`.
4. Start the same application version, or a newer one that still reads workflow schema 1. Open the
   job library and check the restored jobs and attempts.

Restoring never starts work. Startup recovery marks queued or running attempts as interrupted.
Reading jobs, attempts, reports and sources does not change any existing file.

### Restore to the same absolute path

`job.json` stores the absolute path of the job's binary, and the store refuses a record whose path
does not match its location. If you restore to another directory, or start the server with a
`--data-dir` that resolves differently (the default is relative to the working directory), every
job read fails. The library then refuses to show a partial list. Nothing is rewritten, so moving
the store back fixes it. There is no supported relocation tool. Do not edit `job.json` by hand,
because `workflow-state.json` binds the original `job.json` bytes through `legacy.originalJobSha256`.

### Schema compatibility and rollback

- `master` reads and writes only workflow schema 1. A store whose `workflow-state.json` has
  another `schemaVersion` stops startup before the server binds. The launcher prints
  `WorkflowStoreException: This workflow storage version is unsupported; use a compatible
  application or restore a backup.` and exits with status 1. No file is rewritten or downgraded.
  `storage.json` in a [support bundle](web-operations.md#support-bundles) counts the schema
  versions present.
- Rolling back to an older application is supported only if that version reads every schema
  present in the store. If it does not, restore the backup that was taken with the older version.
- A damaged `job.json` or `workflow-state.json` can stop startup recovery, which inspects every
  job, and it makes the library refuse a partial listing. The message (`CORRUPT_LEGACY_JOB`,
  `CORRUPT_WORKFLOW_STATE`) asks you to preserve the file and restore a verified backup. The
  server never repairs or deletes these files.

## Verification

`decompengine.web.WebBackupRestoreRehearsalTest` rehearses this procedure on a populated store:
a job with a completed attempt, its accepted revision, a progress journal, `exploration.json`
and a `source-tree.zip`, plus a job that has only an upload.

- Opening the store and reading every projection changes no existing file. The first start of an
  older store may only add the durable `workflow-state.json` for a job that has none.
- The byte copy and the restore to the original path reproduce the manifest exactly.
- The restored server returns the same v1 projections for the job, the upload-only job, the
  attempt list (including the accepted revision ID) and the exploration report. A later start
  rewrites nothing.
- After a restore to another absolute path, the job read is refused, the listing returns 503,
  and no byte changes.
- With a `workflow-state.json` that claims `schemaVersion` 2, startup is refused with
  `UNSUPPORTED_WORKFLOW_SCHEMA`, no host path appears in the message, and the file is not rewritten.

Run it with `./gradlew test --tests 'decompengine.web.WebBackupRestoreRehearsalTest'`. On
2026-10-26 it passed locally on `33c49f95` plus this change. The launcher's
unsupported-schema output quoted above was observed with the installed distribution.

The rehearsal used synthetic data and the v1 API. It did not exercise a staged release archive
on a second host. It also did not verify a source-archive receipt, because archive verification
is still pending in #1712.

## Managed Git repositories (pending)

`master` has no managed Git repositories, worktrees or credentials. The runtime reports
`gitVersion: null`, so a backup of today's store contains no Git state.

The Git workspace pull requests (#1701, #1705, #1708, #1760, #1765, #1767 and #1734) would store
managed Git state inside the data directory. As currently proposed, the state lives under
`<data-dir>/<job>/git/`, with repositories under `git/repositories/<id>/`. Each repository
holds its Git directory, linked worktree records, commit-to-source mapping records under
`mappings/` and fetch state. Operations and staging go under `git/operations/` and
`git/staging/`, and a sanitized runtime goes in `<data-dir>/.git-runtime`. Those PRs require Git
2.36.0 or newer, the version they check before enabling the capability. Remote credentials are
operator files referenced by the server's credential configuration. They are not stored in the
data directory, so this backup procedure would not export them.

Once those PRs land, this document must be updated and the rehearsal extended. The update needs
to name the exact mapping and worktree records to back up, check that restored commits still
map to the same source revisions, and confirm that a restore never rewrites a repository or its
history. Until then, #666's Git criterion is not met.
