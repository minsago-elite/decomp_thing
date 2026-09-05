# Upload staging recovery

Web service initialization acquires the exclusive job-root ownership lease before
reconciling upload staging, then recovers workflow records and admits requests.
Reads never trigger or repeat staging cleanup. The root and reserved staging names
are application-owned storage; display filenames cannot select these directories.

Cleanup recognizes only `.upload-` followed by 1–20 decimal digits, the namespace
used by the existing `Files.createTempDirectory` publisher. It scans at most 10,512
root entries and accepts at most 256 staging candidates per startup. Those limits
fail before any deletion. Every candidate is inspected before deletion begins.
Unrelated names and published hexadecimal job identities are outside this selection.

A candidate must be a mode-0700 directory with the same owner and mount as its root.
Its entries may only be input.elf, job.json and upload-receipt.json; each must be a
regular file with the same owner/mount and one hard link. Empty staging directories
and partial known files are valid unpublished remnants. Contents are not parsed or
trusted as evidence of publication. Symlinks, subdirectories, extra files, wrong
permissions/owners/mounts and excessive candidates cause explicit
UPLOAD_STAGING_RECOVERY_REQUIRED, preserving unexpected data for inspection.

All inspection and unlink operations use pinned directory descriptors. Candidate,
child and named-file identities are rechecked before removal; no recursive pathname
walk follows uploaded data. Known file entries are unlinked, the empty directory is
synced and removed, and the parent is synced. If cleanup is interrupted, a remaining
private directory contains a subset of the same allowed files and can be reconciled
again. The ownership lease excludes cooperative upload writers during this process;
manual concurrent edits to application-owned storage are unsupported.

Startup failure closes the acquired lease and does not admit work. It does not
silently delete unknown data or publish a reconstructed partial job. After the atomic
publication rename, the directory is a job identity and cleanup leaves its binary,
metadata and durable idempotency receipt intact.

## Qualification

Separate JVM publishers are forcibly terminated during input writing, after binary
sync, after metadata sync, immediately before rename and immediately after rename.
The parent proves that the live child excludes another owner, waits for confirmed
process death, reacquires ownership and runs recovery. Pre-rename cases leave no job;
post-rename recovery retains the complete job and replays its original receipt.
Retrying every scenario produces exactly one job. The fixture is an inert ELF header
and is never executed.

Additional tests cover unrelated hidden data, published jobs, empty/repeated recovery,
extra entries, symbolic/hard links, subdirectories, permissions and the candidate
ceiling. Service tests verify startup-only maintenance and lease release after
refusing unexpected data. These tests qualify process termination, not power loss
or every filesystem's durability semantics. Total retained-storage quotas remain
open under #162.

All 138 web/jobs tests and distZip passed. The
[retained JUnit evidence](evidence/web-upload-staging-recovery-20260905.xml) records
the dedicated recovery suite, including all five process-kill points in its publisher
termination test. No tests in the web/jobs run were skipped.

After integrating master through 8c4b96a, the combined web/jobs and bundled-operation
run passed 186 tests; two root-owned-runtime prerequisite checks skipped. distZip and
the [packaged upload regression](evidence/web-staging-merge-20260905.json) also passed.
The merge retains bounded shutdown, diagnostic redaction, atomic metadata writes and
attempt-bound legacy progress. Shutdown tests cover interruptible, interruption-swallowing
and uncooperative worker processes, including truthful restart projection.
