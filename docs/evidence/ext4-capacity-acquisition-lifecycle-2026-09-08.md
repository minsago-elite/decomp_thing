# Ext4 capacity, acquisition and lifecycle qualification boundary

Issue #932, source acceptance criterion 8. Recorded 2026-09-08 from source
commit `bf2501568f39ab52b23492dfc37839bb81895587`. This is a bounded evidence
record of the current implementation and conditional fixtures. No privileged
test run is claimed here.

## Current implementation surface

The authority in
[`FullTreeDiskScratchAuthority.kt`](../../src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt)
opens a canonical descriptor, requires trusted ancestors and the exact root
mount, takes a nonblocking exclusive lock, reads descriptor-pinned byte and
inode capacity, and refuses read-only, over-capacity or under-available
filesystems. The mount check requires `ext4` with `rw,nodev,nosuid,noexec,
noatime`, a root mount, no nested mount, and no other visible mount or bind
alias for the device (lines 1348-1572 and 1679-1731).

Acquisition persists a self-hashed lease record and canonical evidence before
returning the live lease. Revalidation compares mount, capacity, operation,
request, shard, scope, lease-root and record identities. Clean release uses
the rename, parent-sync, record-unlink and final-removal ordering in the
quarantine helper (lines 1587-1645). The implementation comments and types
still describe cold inspection as read-only and say that quarantine residue
needs a separate recovery authority.

The source snapshot is pinned by these hashes:

| Artifact | SHA-256 |
| --- | --- |
| `src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt` | `eadc6c791d6848bf87999814e5b2af71b963277609351eba6df86c74cae18cde` |
| `src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthorityTest.kt` | `a6e47340eed9877e593616f43dee7be386cdcdf0f10c4329d9de8699f5c56606` |
| `src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchCrashProbe.kt` | `4d1d2925d8ba635290ae84bc6c4f771b4ed0779d6447533b2bf761bd6a1ef297` |
| `scripts/ci-prepare-oracle-ext4-scratch.sh` | `3de1723fe1702c468582873d64fe23840c7006bded70c7364c0289c14369b3a3` |
| `scripts/oracle-ext4-scratch-profile.sh` | `9eec7d0b1d16c550c0cb9471f72f71f4d36554b4c9966c18e47273812ce2f03f` |

The CI fixture provisions a loop-backed ext4 filesystem with a 64 MiB image,
4,096 inodes, `rw,nodev,nosuid,noexec,noatime`, and a user-owned mode-0700
mount. CI sets `DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH=true`; without the fixture,
the tests use JUnit assumptions and skip their privileged portions.

## Criterion-8 evidence status

The following status describes coverage present in the pinned tree. “Unverified”
means that this checkout contains no executed result for the criterion.

| Required behavior | Current evidence | Status |
| --- | --- | --- |
| Capacity and inode exhaustion | The provisioned-slot test calls the byte and inode exhaustion helpers, which require `ENOSPC`, check the bounded remaining capacity, and verify inode recovery (`FullTreeDiskScratchAuthorityTest.kt:259-431, 1360-1420`). | Conditional privileged execution unverified. |
| Concurrent acquisition | The provisioned-slot test attempts a second acquisition while the first lease holds the mount lock (`:312-316`); the production path uses `tryExclusiveLock` (`FullTreeDiskScratchAuthority.kt:1463`). | Same-process contention is covered in source; cross-process concurrent acquisition is unverified. |
| Mount/path ABA | The test replaces the operation run root at its original name and expects descriptor revalidation to refuse it (`FullTreeDiskScratchAuthorityTest.kt:344-424`). | Run-root ABA refusal is represented; privileged mount-root path and mount-identity ABA are unverified. |
| Wrong flags, type and capacity | Parser/evidence mutation tests reject altered flags/provider and the authority checks filesystem type, required flags, byte/inode maxima and availability (`FullTreeDiskScratchAuthorityTest.kt:67-233`; `FullTreeDiskScratchAuthority.kt:1695-1730`). | Refusal logic is present; privileged wrong-mount and wrong-capacity fixtures are unverified. |
| Nested mounts | The mountinfo fixture includes an ext4 root with a nested tmpfs and the authority rejects any nested mount (`FullTreeDiskScratchAuthorityTest.kt:31-64`; `FullTreeDiskScratchAuthority.kt:1702-1704`). | Synthetic parser coverage exists; privileged nested-mount refusal is unverified. |
| Clean release | The provisioned-slot test reaches `requireCleanAndRelease()` and requires an empty mount (`FullTreeDiskScratchAuthorityTest.kt:419-431`). Release fault cutoffs are also represented at `:437-777`. | Conditional privileged execution and production qualification are unverified. |
| Crash reset | `FullTreeDiskScratchCrashProbe` acquires a lease and exits with `Runtime.halt`; the test then cold-opens residue without mutation or release (`FullTreeDiskScratchAuthorityTest.kt:964-1205`). | Crash residue observation exists; trusted reset, cleanup bounds, and terminal crash convergence remain unverified and are outside this record. |

No result here establishes production qualification, durable post-reboot
recovery, whole-run active-plus-residue accounting, or authorization to release
arbitrary crash residue. Those gaps remain explicit for #932 and the dependent
tracker work in #138/#933.

## Validation

Tests were intentionally skipped for this documentation-only checkpoint. The
record was checked against the pinned paths, fixture values and source anchors;
only lightweight patch validation is reported with the commit.
