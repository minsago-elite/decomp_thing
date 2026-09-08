# Scratch lease and worker lifecycle evidence boundary

Issue #931, source acceptance criteria 5–7. Recorded 2026-09-08 from source
commit `bf2501568f39ab52b23492dfc37839bb81895587`. This is a bounded static
evidence record for the current Kotlin implementation and its fixtures. No
test execution, privileged qualification, or production release claim is made.

## Current implementation surface

`FullTreeDiskScratchLeaseRecord` and `FullTreeDiskScratchEvidence` retain the
operation ID, request digest, shard ID, scope digest, mount path and mount
identity, filesystem type and capacity, required policy, mount flags, and
lease-root identity in canonical self-hashed Kotlin JSON
([`FullTreeDiskScratchAuthority.kt`](../../src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt):180-470).
The operation binding is separately canonical and self-hashed in
[`FullTreeFunctionObservationOperationJournal.kt`](../../src/main/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationOperationJournal.kt):36-302.

The live lease revalidates trusted mount ancestors, descriptor-pinned mount
identity and capacity, the named lease root, the lease record bytes, bounded
membership, and the deterministic operation run at explicit stages
([`FullTreeDiskScratchAuthority.kt`](../../src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt):54-63, 607-674).
Run-root creation, opaque-token checks, callback-scoped descriptor borrows, and
before/after lifecycle validation are in the same authority
([`FullTreeDiskScratchAuthority.kt`](../../src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt):676-935).

The operation coordinator keeps journal history, disk evidence, the opaque run
root, and the lease together across LEASED, prepared, and attached states. Its
typed transitions revalidate the journal and lease before and after lifecycle
edges, while receipt matching remains a separate caller-owned worker proof
([`FullTreeFunctionObservationOperationCoordinator.kt`](../../src/main/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationOperationCoordinator.kt):204-827,
1654-1760).

The existing isolated runner is deliberately a fixture boundary. Its class
documentation says that its summed cleanup ceiling is not a live aggregate
quota and that its receipt must not enter release evidence
([`FullTreeFunctionObservationIsolatedRunner.kt`](../../src/main/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationIsolatedRunner.kt):2578-2595).
The truth generator likewise keeps `authoritativeReleaseEvidence` false until
the aggregate isolated lifecycle and a later release owner exist
([`FullTreeFunctionTruthSqlite.kt`](../../src/main/kotlin/decompengine/oracle/fulltree/FullTreeFunctionTruthSqlite.kt):80-105,
1154-1159).

The pinned source and fixture artifacts are:

| Artifact | SHA-256 |
| --- | --- |
| `src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt` | `eadc6c791d6848bf87999814e5b2af71b963277609351eba6df86c74cae18cde` |
| `src/main/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationOperationCoordinator.kt` | `1cb3bc72a2c3caaabdb6f6d08baed41863e2be72e6367a3771d478f9e99b6ca6` |
| `src/main/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationOperationJournal.kt` | `9e06f0c2dbbfebbb905b9fc1993e592b8a63880639b2132a535a58880551fc4d` |
| `src/main/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationIsolatedRunner.kt` | `7b52cd790575f0a1c356548ad159e827206937da34a4ef7ef3c2fc98b0f009fa` |
| `src/main/kotlin/decompengine/oracle/fulltree/FullTreeFunctionTruthSqlite.kt` | `b77c59ca23bc437fc52a86c3bbafe6d859f690f564a8f58fd48a3dea07341332` |
| `src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthorityTest.kt` | `a6e47340eed9877e593616f43dee7be386cdcdf0f10c4329d9de8699f5c56606` |
| `src/test/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationOperationCoordinatorTest.kt` | `b102d7550464b95386175a8b292fc5ca7811bdc958c3b76711d1498a25ae255a` |
| `src/test/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationOperationJournalTest.kt` | `12eb4c968c28bcb1fcfd4bcff2e6b2cda33bd8959e906752f5e6c70ab34bd07a` |
| `src/test/kotlin/decompengine/oracle/fulltree/FullTreeFunctionObservationIsolatedRunnerTest.kt` | `25f6d1c8df43717cb212b00a17da5b1c967e04f68f436960b0aed9e9e1afec3f` |
| `src/test/kotlin/decompengine/oracle/fulltree/FullTreeFunctionTruthSqliteTest.kt` | `274a646bcf261ec4d1d50b8a9373d47daebd2bfdddc0cbac8b3c0a84a8844ab2` |
| `src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchCrashProbe.kt` | `4d1d2925d8ba635290ae84bc6c4f771b4ed0779d6447533b2bf761bd6a1ef297` |
| `scripts/ci-prepare-oracle-ext4-scratch.sh` | `3de1723fe1702c468582873d64fe23840c7006bded70c7364c0289c14369b3a3` |
| `scripts/oracle-ext4-scratch-profile.sh` | `9eec7d0b1d16c550c0cb9471f72f71f4d36554b4c9966c18e47273812ce2f03f` |

## Criteria 5–7 evidence status

| Requirement | Current code and fixture evidence | Status in this record |
| --- | --- | --- |
| Bind mount identity, filesystem capacity, operation/request/shard/scope identities, lease-root identity, flags, and policy to canonical self-hashed Kotlin evidence. | The two scratch artifacts bind those fields; the journal binding fixes the worker operation identity; `FullTreeDiskScratchAuthorityTest` covers canonical/self-hash parsing and mutation refusal (`:67-233`); `FullTreeFunctionObservationOperationJournalTest` covers canonical operation binding and exact disk-evidence introduction (`:31-124, 559-611`). | Static source and fixture coverage is present. No test result is claimed here. |
| Revalidate the lease at explicit worker/publication lifecycle stages and fail closed on drift. | `requireCurrent` selects active-run membership by stage and rejects identity, record, membership, or run-root drift. The coordinator calls the typed checks before launch, after scope attachment, after cgroup absence, before publication, and during terminal cleanup (`FullTreeFunctionObservationOperationCoordinator.kt:453-515, 585-625, 1654-1735`). Coordinator fixtures cover run-root transfer, attached authority retention, replacement refusal, and exact residue (`FullTreeFunctionObservationOperationCoordinatorTest.kt:314-398, 1052-1140, 1361-1492, 1741-1815`). | The fail-closed paths are documented in current code and fixtures. Live worker/cgroup lifecycle execution is unverified. |
| Keep the existing isolated fixture API mechanically non-authoritative until durable operation recovery and whole-run accounting land. | The fixture runner explicitly excludes release evidence, while truth generation hard-codes `authoritativeReleaseEvidence = false`. Fixture tests cover bounded cleanup, unknown-member refusal, no recursion into runtime/scratch residue, and fixture publication after local cgroup exit (`FullTreeFunctionObservationIsolatedRunnerTest.kt:35-179, 2092-2195`). | Non-authoritative boundary is explicit. Durable recovery, whole-run accounting, and release authority remain absent. |

## Unverified criteria and limitations

This record does not claim:

- any executed focused or broad test result; tests are intentionally skipped for
  this documentation-only checkpoint;
- privileged ext4 provisioning, cross-process lease contention, mount-root or
  mount-identity ABA, real worker START, or a production publication run;
- durable operation recovery, power-loss or reboot recovery, trusted reset of
  crash residue, or whole-run active-plus-residue byte/inode accounting;
- authenticated worker/cgroup absence composed with scratch release, or a
  release owner for arbitrary residue; or
- production qualification, all-shard authority, or completion of issue #931 or
  its parent tracker #138.

The separate-JVM crash fixture can leave record-only or active-run residue for
read-only cold observation. Its teardown and the ordinary isolated fixture
cleanup are test-owned operations and do not supply production recovery or
release authority.

## Validation

Tests were intentionally skipped as requested. The record is limited to the
pinned current source, fixture paths, hashes, and static anchors above.
