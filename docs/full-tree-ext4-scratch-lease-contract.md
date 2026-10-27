# Full-tree ext4 scratch lease contract

This document records the small contract currently established by the Kotlin
disk authority for issue [#138](https://github.com/minsago-elite/decomp_thing/issues/138).
It is an evidence map, not a completion claim for the dedicated-ext4 lifecycle.

## Evidence currently established

`FullTreeDiskScratchEvidence` is canonical, self-hashed, and bound to the
operation, request, shard, scope, mount path hash, mount/device/root identities,
filesystem type, byte/inode totals and acquisition availability, owner/mode,
required mount flags, policy maxima/minima, lease-root identity, and the exact
lease-record hash. Its constructor rejects a non-ext4 filesystem, a capacity or
availability outside policy, and a mode other than owner-only `0700`.

`FullTreeDiskScratchLease.requireCurrent` rechecks the trusted mount ancestry,
descriptor-pinned mount and lease-root identities, immutable lease-record bytes,
and exact lease-root population at each declared worker/publication stage. Active
stages require the operation-bound run root; record-only stages reject it. The
authority therefore supplies an opaque bounded scratch lease to its Kotlin
consumers without moving authority to Python, ACP, or a host workspace path.

`close()` and `abandonForRecovery()` close descriptors and release the
cooperative mount lock while preserving lease residue. The only destructive
operation is `requireCleanAndRelease`, which performs its own release-stage
validation and one-way quarantine ordering. The cold lease is observation-only:
it retains its lock and descriptors while authenticating an exact caller-supplied
acquisition artifact, and its snapshot cannot authorize mutation, release, or
recovery. These boundaries preserve historical evidence and unresolved states.

The source of truth for this slice is
[`FullTreeDiskScratchAuthority.kt`](../src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt),
with focused behavioral coverage in
[`FullTreeDiskScratchAuthorityTest.kt`](../src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthorityTest.kt).
The coordinator and its operation journal remain separate authorities; this
document does not promote the lease into worker START, output publication, or
terminal release authority.

## Actual mounted admission qualification

The focused admission outcome in
[#930](https://github.com/minsago-elite/decomp_thing/issues/930) has a separate
hosted fixture and the 18 named controls in
[`FullTreeDiskScratchAdmissionMountedTest.kt`](../src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAdmissionMountedTest.kt).
These invoke the production admission API against real kernel state: pinned
capacity, exclusive acquisition, total byte/inode maxima, available byte/inode
minima, each required mount flag, read-only ext4, tmpfs, nested mounts, bind
subtrees, visible device aliases, owner/mode, ordinary subdirectories, symlinks,
and replacement of the mounted root while the old lease remains pinned. The
replacement control verifies that stale release refuses and preserves both the
original lease record and the replacement canary. These controls are distinct
from the existing canonical-JSON mutation tests.

The exclusive-acquisition control first holds an independent descriptor's lock
on the empty mount and requires the production lock-conflict diagnostic without
mutation. After unlocking, successful acquisition must retain a lock that an
independent descriptor cannot acquire. The second API acquisition also requires
the lock-conflict diagnostic. The nested-mount control requires the specific
nested-mount diagnostic. Neither control can receive credit from the later
nonempty-filesystem recovery refusal if its intended predicate is bypassed.

The `live-fulltree` CI shard provisions two separate 64 MiB / 4096-inode ext4
images using
[`ci-oracle-ext4-admission.py`](../scripts/ci-oracle-ext4-admission.py).
The helper accepts only named fixture actions, retains repository-local images
and root-owned state, authenticates the owned loop backing objects and exact
mount inventory, and uses the existing trusted `/var/lib` mount ancestry model.
An owned 1 MiB / 32-inode tmpfs parent supplies private mount propagation for
the replacement control without changing host-root propagation.
It refuses unknown mounts, changed canaries, and ambiguous residue. It is a
qualification fixture, not a production provisioner or a crash-reset capability.
No local privileged mount experiments are required to develop these controls.

CI sets `DECOMP_REQUIRE_ORACLE_EXT4_ADMISSION=true` and runs
[`verify-oracle-ext4-admission.py`](../scripts/verify-oracle-ext4-admission.py)
against the actual JUnit report. Every named control must execute exactly once
and pass, with zero skipped tests. The retained `build/issue930-evidence`
artifact includes helper observations, the JUnit report digest and the named
qualification result. Local helper/report tests and an environment-gated local
JUnit skip do not satisfy this gate. Closure requires successful hosted evidence
at the qualified source, review/CI completion, and a post-merge acceptance audit.

## Gates still unavailable or unresolved

The privileged integration cases require a trusted provisioner to publish
`DECOMP_TEST_ORACLE_EXT4_SCRATCH`. CI creates the fixed-size ext4 image and
mount with `rw,nodev,nosuid,noexec,noatime`, owner `0700`, and explicit byte and
inode counts, then runs with
`DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH=true`. Where the required fixture environment
is absent, local execution cannot qualify capacity/inode exhaustion, concurrent
acquisition, mount/path ABA, privileged quarantine cutoffs, or cold lease
integration; environment-gated skips remain distinct from hosted successes.

The remaining production gates are also open: authenticated worker START and
cgroup/process absence, publication under the retained lease and journal
authorities, terminal release after exact absence, trusted reset of quarantined
residue, cleanup bounded independently of sparse size/depth, and whole-run
active-plus-residue byte/inode accounting. No snapshot, fixture, journal
diagnostic, or hosted test count substitutes for those gates.

Bundled Ghidra remains an independent application-owned Java-API dependency.
Production analysis must continue to use the bundled runtime with `GHIDRA_HOME`
unset and must not fall back to an external `analyzeHeadless` installation. ACP
may consume completed evidence read-only; it cannot issue or mutate this lease.

## Trusted retained-slot reset transaction

The focused provisioner for [#933](https://github.com/minsago-elite/decomp_thing/issues/933)
uses a fixed root-private deployment at `/var/lib/decomp-oracle-ext4-reset-ci`.
[`oracle-ext4-reset.py`](../scripts/oracle-ext4-reset.py) accepts only the recorded
slot generation or existing intent. Its root-private image is allocated at
creation, bound to one non-autoclear loop, and never detached, rebound, deleted,
or credited as released by reset. Existing runner-owned images cannot be
promoted into this authority. The trust boundary excludes an administrator
retaining or transferring raw image/block descriptors to another principal.
The Kotlin oracle principal has no raw-image, raw-device, state, or reset access.

The broker durably records a bounded intent before asking the fixed custodian
service to run. The service authenticates that intent under the root lock;
active service or cgroup custody prevents a competing reset. An ordering-only
retention target keeps the completed service invocation and exit status
observable without activating or restarting it. Finalization requires the exact
successful invocation and an empty cgroup. The target stays active through
retained final evidence and disposal of the ephemeral hosted VM.

The transaction acquires the production cooperative mount lock, closes the old
generation gate, moves and unmounts only the authenticated mount, and formats
through the same pinned loop. The supported e2fsprogs package and its complete
installed tool closure are recorded. The fixed formatter arguments and config
require its exclusive block open before any discard, zero, or write; a hidden
namespace mount must cause an actual `EBUSY` refusal. No recursive walk of old
filesystem contents is used, so sparse logical size and directory depth do not
set cleanup work. A fresh UUID and generation path prevent stale evidence from
being admitted as the replacement filesystem.

Durable `MOUNT_INTENT` records the protected candidate location before mounting.
Recovery reconciles only the recorded block/UUID and owned location. The
`EXPOSURE_INTENT` transition is irreversible: once publication may have exposed
the candidate, recovery cannot reformat it or require it to be empty. An
unrecognized replacement, ambiguous start submission, changed boot, or missing
identity remains fenced and reserved. Safe refusal at an interrupted directory
creation/removal window is not claimed as successful convergence.

The service retains finite 10-second / 5-start rate semantics, a 60-second
manager runtime bound, and the existing 45-second internal action bound. The
hosted fixture separately persists at most 64 conservatively charged submission
attempts per session and paces each eligible submission at least 2.1 seconds
after the previous verified terminal/empty-cgroup observation. A rate-limit
refusal fails qualification; the fixture never clears service failure counters.
The durable formatter launch-attempt count is conservative bookkeeping, not an
assertion that every recorded attempt reached `execve`.

[`FullTreeDiskScratchResetMountedTest.kt`](../src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchResetMountedTest.kt)
contains 32 named hosted controls. They cover real unprivileged admission,
lease contention, killed workers, exhaustion, sparse/deep residue, held
filesystem descriptors, hidden namespace mounts, actual controller/custodian/
formatter deaths, durable cutpoints, replacement canaries, and irreversible
candidate exposure. The report gate requires each exact JUnit method once with
zero skips, actual raw syscall/service evidence, and the 13 committed source
identities including the service, retention target, fixture, and gate.
Unprivileged helper tests, compilation, and synthesized report mutation tests
supply no mounted-kernel qualification evidence.

The final fixture action refuses an alien mount replacement, then fences and
unmounts only the authenticated public scratch. Its result is
`RESERVED_UNMOUNTED`: the original image and bound loop, any explicitly reserved
qualification companion, and service/target installation remain owned until VM
disposal. Zero displayed availability is not capacity credit. This transaction
does not authorize worker START, operation absence, output acceptance, journal
terminal release, or aggregate active-plus-residue accounting. Those parent
contracts and their issue gates remain independent.
