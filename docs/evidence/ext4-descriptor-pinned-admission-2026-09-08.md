# Descriptor-pinned ext4 scratch admission evidence

Issue #930, source acceptance criteria 1–4. Recorded 2026-09-08 from source
commit `bf2501568f39ab52b23492dfc37839bb81895587`. This is a small source and
fixture record for the current checkout. Tests are intentionally skipped; no
privileged execution, merged-behavior qualification, or production qualification
is claimed.

## Exact current surface

| Artifact | SHA-256 | Relevant anchors |
| --- | --- | --- |
| `src/main/kotlin/decompengine/acp/LinuxFilesystemSyscalls.kt` | `0c17ccf5daba696f9358ec45a3be81d979e0b920` | `filesystemCapacity:145-185` |
| `src/main/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthority.kt` | `85ef34986dff47ea26cbb5f7f5694bb66ccc74db` | `acquireDedicatedFilesystem:1445-1539`; `requireMountCurrent:1678-1731`; policy constants: `2123-2138` |
| `src/test/kotlin/decompengine/acp/LinuxFilesystemSyscallsTest.kt` | `3f56a14067a625140efd384c0c1963865371296f` | pinned-capacity fixture: `17-31` |
| `src/test/kotlin/decompengine/oracle/fulltree/FullTreeDiskScratchAuthorityTest.kt` | `2caf501caa8486d755784aaab1e0b3e8e7b37384` | mount parser: `31-64`; ordinary-directory refusal: `234-256`; conditional ext4 fixture: `258-431` |
| `scripts/ci-prepare-oracle-ext4-scratch.sh` | `511e3572d24a4748c8865150778acea668651302` | ext4 image and mount setup: `49-70` |
| `scripts/oracle-ext4-scratch-profile.sh` | `e8629040ee46387e590433f271e0d3921dad3fab` | default `64M`/`4096` profile: `3-7` |

`filesystemCapacity` calls Linux `fstatvfs` on an already authenticated
directory descriptor, converts block counters to byte counters, and compares
the descriptor identity before and after the read. The authority canonicalizes
the absolute mount path, checks trusted ancestors, opens the root with
`O_DIRECTORY|O_NOFOLLOW`, takes a nonblocking exclusive lock, and admits only
the exact user-owned 0700 root of an ext4 mount. It requires `rw,nodev,nosuid,
noexec,noatime`, rejects nested mounts and another visible mount or bind alias
for the device, checks the file-store type, and rechecks descriptor/path
identity during admission.

The admission path rejects read-only filesystems and total byte/inode capacity
above policy maxima. On initial acquisition it also requires available bytes
and inodes at or above policy minima. The canonical evidence and lease record
retain the mount identity, flags, capacities, policy, and lease-root identity.

The checked CI fixture profile creates a 64 MiB ext4 image with 4,096 inodes,
mounts it with the required flags, removes `lost+found`, and changes the mount
root to the invoking user's mode-0700 directory. The provisioning script's GNU
`stat` check accepts its historical `ext2/ext3` label for ext4's shared magic.

## Criterion status

| Criterion | Current source/fixture evidence | Status in this record |
| --- | --- | --- |
| Read byte/inode capacity through a pinned directory descriptor | `filesystemCapacity` uses `fstatvfs` through the descriptor and checks identity around the read; the focused syscall fixture compares the returned counters with the local file-store observation. | Source and fixture are present; execution skipped. |
| Admit only canonical user-owned 0700 exact ext4 with a nonblocking exclusive lock | `acquireDedicatedFilesystem` canonicalizes and opens the path, calls `tryExclusiveLock`, then applies `requireMountCurrent`; the ordinary-directory fixture expects both acquisition and cold opening to fail. | Source refusal and ordinary-directory fixture are present; privileged ext4 execution skipped. |
| Require flags and reject unsafe identity/type/topology cases | The authority requires `rw,nodev,nosuid,noexec,noatime`, ext4, mount root `/`, and matching path/device identity; it rejects nested mount points and same-device visible aliases. The parser fixture includes a nested tmpfs and the admission fixture requires the exact ext4 environment. | Synthetic parser and source checks are present; live wrong-type, bind, symlink, nested-mount, and mount/path ABA fixtures are unverified. |
| Enforce total maxima and initial available minima for bytes/inodes | `requireMountCurrent` checks `totalBytes`/`totalInodes` maxima and acquisition-time `availableBytes`/`availableInodes` minima from descriptor-pinned counters. The policy and evidence constructors reject inconsistent bounds. | Source checks are present; exhaustion and boundary execution are unverified. |

The implementation is therefore recorded as current draft/source behavior. This
file does not turn source inspection or conditional fixtures into a merged
behavior result, and it does not authorize production use. The remaining gaps
are explicit: run the privileged ext4 fixture, exercise over/under-capacity
refusals and exhaustion, test cross-process lock contention, and qualify live
mount/path ABA, symlink, bind-subtree, nested-mount, and identity-drift cases.
Later lifecycle, crash-reset, whole-run residue accounting, and production
qualification remain outside this slice.

## Validation

Tests were skipped as requested. Only the evidence paths, source anchors and
hashes were checked for this documentation-only change; `git diff --check` is
the only validation claimed by the checkpoint.
