# Host mount churn during ACP sandbox setup

Issue #1799 tracks hosted failures with `host mounts changed during runtime manifest` and the witness
`mount-event-v1 phase=CHECKPOINT generation=NOT_EVALUATED outcome=EVENT rc=1 revents=10 errno=NA`.
This note records which events the check treats as fatal, the events observed on hosted runners, and
the bounded restart that now applies before untrusted execution.

## What the scope latch refuses

`RuntimePrivateControlScope` protects every runtime-manifest walk and private runtime snapshot copy.
Each scope opens `/proc/self/mountinfo` once, reads one table snapshot from that descriptor, and polls
the same descriptor for `POLLPRI | POLLERR` at every checkpoint (`CHECKPOINT`), at concurrent control
admission (`CONTROL_ADMISSION`) and after a registry refresh (`REFRESH`). The kernel raises this event
for any mount, unmount, move or propagated change in the JVM's mount namespace, including a mount that
is removed again before the next table read. `revents=10` is `POLLPRI | POLLERR`.

The first event latches the scope. Every later check in that scope fails with the same witness, and
the scope never acknowledges the event and continues. The scope relies on its single snapshot for
private-control exposure, nested-mount coverage and source-root coordinates, and the manifest walk
lists names by path. A mount that appears and disappears between two table reads can hide or
substitute directory entries without leaving a table difference, so the event is the only signal for
that window. Within one scope, every event is therefore fatal, whatever its location.

Some events fall outside this check. No scope observes the gaps between scopes; the next scope takes a
fresh snapshot. The full-table comparisons in `finish`, scope admission, private-control protection,
staging-root admission and cleanup admission are separate point-in-time checks. They are unchanged.

## Events observed on hosted runners

The passive observer (`docs/ci.md`) retained two `required-contract` occurrences on 2026-11-28. Both
occurred in the runner's initial mount namespace (inode `4026531832`):

- Run [46102066453](https://github.com/minsago-elite/decomp_thing/actions/runs/46102066453): an ext4
  mount from device `259:1` was added below parent mount 28 at 03:33:07.400 UTC and removed about
  2.4 ms later. Device `259:1` is the block device that backs the root filesystem, so the mount
  exposes a subtree of the root filesystem at a second path. The mount used shared propagation.
  The target was classified `other`: it was outside the workspace and build roots, and it was not
  a snap, docker, credential or user-runtime path. A tmpfs mount on the same parent remained for
  about 8 minutes. The JUnit cause chain for
  `MvpPatchAcpIntegrationTest.ordinary refusal and process failure persist raw receipts before
  rejected assessment` is `calculateAcpRuntimeManifestSha256` → `checkpointLocked` → the latch
  above, during test provisioning. No sandbox existed at that point.
- Run [46099187624](https://github.com/minsago-elite/decomp_thing/actions/runs/46099187624): the same
  pattern recurred at 03:54:35.16 UTC: an ext4 mount from device `259:1` on parent 28, target class
  `other`, was added and removed about 2.5 ms later. A tmpfs mount on parent 28 was also present.
  The failing `default ACP patch turns use captured filesystem callbacks and archive both
  executions` receipt records `phaseReached=sandbox-launch`, failure kind `configuration` and
  cleanup `unverified`. These values match the refusal signature. The XML does not retain the cause
  chain, so this occurrence is consistent with the latch but does not prove it.

The trigger is short-lived churn on paths unrelated to the sandbox. The mounting process is still
unknown, because the observer cannot attribute events to processes.

## Bounded restart before untrusted execution

A scope-owned unit is one complete runtime manifest (`buildRuntimeManifestOwned`) or one private
snapshot copy (`stagePrivateRuntimeSnapshot`). The unit may be discarded and rebuilt only when all of
these hold:

- The failure is the exact refusal built by the latch of a scope that the same attempt opened. Its
  only suppressed throwable is its own witness. Query failures (`INVALID_DESCRIPTOR`,
  `SYSCALL_ERROR`), table-comparison failures, closure or identity refusals, and any close or cleanup
  failure added while unwinding are final.
- Cleanup of the refused attempt has been proven. The scope is closed. A refused snapshot container
  must be deleted with proof before the restart; otherwise `AcpCleanupProofFailure` is raised and is
  final.
- The attempt's owner still holds its restart permit.
- Fewer than three attempts have run, and the caller's cancellation and deadline checkpoint passes.

Each new attempt opens a new mountinfo descriptor, baseline, table snapshot and set of retained control
identities. It reuses nothing that the refused attempt computed.

| Caller | Restart |
| --- | --- |
| `calculateAcpRuntimeManifestSha256(source, limits)`: trusted provisioning | Yes |
| `LinuxBubblewrapBoundary.prepare`: helper validation and launcher pinning | Yes |
| A boundary's `validateReadOnlyMounts`, launch pinning and launch revalidation | Until the boundary's first authorization commit |
| Later launches on that boundary, including terminal launches | No |
| Internal `calculateAcpRuntimeManifestSha256(source, limits, check)`, Full-tree Ninja re-verification, sealed snapshot checks | No |

The boundary revokes its permit after it reserves launch evidence, before the broker's write-ahead
authorization callback and the start byte. The permit never returns, even after cleanup is proven.

Each discarded refusal keeps its closed witness. If the unit still fails, those witnesses are
attached as suppressed throwables to the final failure. If a restart succeeds, the 16 most recent
witnesses and a total count are kept in `AcpHostMountChurnRestarts` for display only.

## Why isolation is not weakened

- Every accepted result still comes from an attempt with no mount event anywhere in its window.
- A restart produces the same state as churn that happened just before the scope opened. The
  original design already accepts that case, because no scope watches the gaps between scopes.
- The fresh attempt applies its full checks to the current table. A persistent mount that reaches
  the closure or a private control is refused, for example
  `sandbox runtime closure crosses a mount boundary`.
- After a boundary's first authorization commit, every refusal in that boundary is final.

## Verification

- `pre-execution scopes restart after unrelated mount churn and refuse churn that reaches the
  closure` runs a child JVM in a private user and mount namespace. It issues real `mount(2)` calls
  during scope admission and during hashing. Unrelated churn restarts once and returns the original
  digest. A strict or revoked permit fails on the first event. Persistent churn stops after three
  attempts and keeps three witnesses. A tmpfs mounted over a closure directory is refused by the
  fresh attempt. A refused snapshot copy deletes its container before the copy that succeeds.
- `setup restart permission ends before the first authorization decision and never returns` checks
  the permit on a live boundary. The permit survives a launch that is refused before start. It is
  revoked inside the authorization callback, and it stays revoked after cleanup.

## Remaining work

The table-comparison refusals listed above do not restart. Terminal launches after the outer agent's
authorization remain strict. The issue's requirement for 20 consecutive hosted runs without a refusal
still needs hosted evidence.
