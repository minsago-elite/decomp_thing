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

## Gates still unavailable or unresolved

The privileged integration cases require a trusted provisioner to publish
`DECOMP_TEST_ORACLE_EXT4_SCRATCH`. CI creates the fixed-size ext4 image and
mount with `rw,nodev,nosuid,noexec,noatime`, owner `0700`, and explicit byte and
inode counts, then runs with
`DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH=true`. On the current host that environment
variable is unset, `sudo` is unavailable, and no ext4 mount is present. Local
execution therefore cannot qualify capacity/inode exhaustion, concurrent
acquisition, mount/path ABA, privileged quarantine cutoffs, or cold lease
integration; those cases remain environment-gated skips rather than successes.

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
