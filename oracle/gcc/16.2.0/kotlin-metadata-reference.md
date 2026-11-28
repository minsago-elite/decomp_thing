# Kotlin metadata reference capture

`decompengine.oracle.gcc.GccMetadataReferenceCli` selects the compiled
`gcc-metadata-v1` registration. It accepts no profile ID, replacement digest,
command, expected-output file, shell script, authority flag, or resource-budget
override. The profile root supplies the registered input files and original
driver/frontend archives; the adapter authenticates them before use.

The CLI has exactly two positional forms. Every path must be absolute, normalized
and non-root; filesystem admission also rejects symlink aliases.

```text
stage <profileRoot> <uncompressedOciLayout> <freshStagingRoot>
capture <profileRoot> <ociLayout> <provisionedRuntimeRoot> <deploymentJson> <journalRoot> <scratchMount>
```

The Gradle task is `gccMetadataReference`, with positional arguments passed using
`--args`. It builds/runs the CLI for development. A provisioned installation can
invoke the same class using its installed JVM and application classpath. Capture
still uses the separately provisioned, explicitly pinned worker classpath from
the deployment file; a development classpath does not confer worker authority.

## Staging and provisioning

`stage` decodes a local OCI layout without executing its tools. The supported
transport has uncompressed tar layers, for example an export produced by
`podman save --uncompressed --format oci-dir`. The image config and layer diffIDs
must match the registered image. Exporting or recompressing transport does not
approve another image. The staging parent must already exist and the staging
root must not exist. A staging failure can leave a partial tree; it is never
admitted by the staging command.

On success stdout is canonical `reference-native-runtime-stage-v1` JSON with
`executionAdmitted: false`, the staging root, projection identity and every
provisioning entry's relative path, kind, UID, GID and numeric Unix mode. Save
this stdout outside the staged tree. The tree is exact: placing a receipt or
other extra file inside it makes admission fail. A provisioner must separately
install the exact tree under trusted root-owned, non-group/world-writable
ancestry, preserving bytes, file names, symlink targets, hardlink relationships,
timestamps and entry-specific ownership/mode. Blanket `chown root:root` is wrong:
the image includes nonzero group identities. Staging runs unprivileged and does
not perform privileged provisioning.

For symlinks, preserve the literal target and use no-follow ownership/time
operations; do not chmod through the link. Linux supplies symlink mode 0777, so
the tar's link permission bits are not an installable permission requirement.
For regular files/directories, restore the declared mode after changing ownership
because chown can clear set-ID bits. Preserve mtimes and hardlink aliases.

`capture` independently reconstructs the expected projection from the OCI layout
and registered original artifacts, compares the provisioned namespace and bytes,
and admits root ownership and ancestry before launching a worker. It has no
fallback to running directly from the staging directory. A root-owned directory
under a user-owned checkout is insufficient; its ancestors remain untrusted.

The compiled registration authenticates `native-runtime-selection-v1.json`
(2,586 bytes, SHA-256
`5cfe8f249600c95e14577138881a6f509e848a0c8e3420ed3ea0bec8fdb62520`).
This fixed positive selection retains the complete `/usr`, `/lib`, `/lib64`,
`/bin` and `/sbin` trees and 697 of this image's 704 `/etc` nodes. Its 44 recursive
configuration roots and 59 exact nodes select configuration before filesystem
access. Every selected file must retain its original readable permissions and
every selected directory its original readable/traversable permissions; an
unreadable selected entry fails admission instead of being skipped.

The seven fixed omissions are `/etc/.pwd.lock`, `/etc/gshadow`, `/etc/gshadow-`,
`/etc/passwd-`, `/etc/shadow`, `/etc/security/opasswd` and the empty
`/etc/ssl/private` directory. Selection is independent of their current
readability. The full original OCI config, layer identities and merged namespace
remain authenticated, including those omitted entries. The projection-v2 record
binds the selection bytes/hash, full image identity and actual selected
configuration paths. Source bytes, modes and original driver/frontend pins are
unchanged. In this profile, the preserved literal `/usr/lib/ssl/private` symlink
is dangling because its empty target directory is omitted; this is a profile
observation, not a claim about other programs' runtime requirements.

Capture runs as an ordinary nonzero UID using that user's authenticated systemd
session and finite user-owned ext4 leases. Root installs the immutable runtime
and deployment but does not execute the capture controller. The shared security
boundary continues to reject caller-writable executable ancestors. Local
parser/unit tests do not establish production capture.

## Trusted deployment file

The deployment is canonical UTF-8 JSON as encoded by `OracleJson.canonicalBytes`:
sorted object keys, two-space indentation and a final newline. It is limited to
256 KiB, depth 8, 4096 nodes and 4096 bytes per string. Unknown, missing, duplicate
or mistyped fields fail. No default values are filled in. The production `open`
path requires a single-link root-owned regular file and root-owned ancestors,
all non-group/world-writable, then retains a stable descriptor while parsing and
rechecking its bytes. Syntax-only parsing is not deployment authentication.

Top-level fields are exactly:

| Field | Value |
| --- | --- |
| `schemaVersion` | `"reference-corpus-deployment-v1"` |
| `expectedCgroupParent` | Exact non-root cgroup path, e.g. `/user.slice/user-1000.slice/user@1000.service/app.slice` |
| `configuration` | Object with all fields below |

Configuration fields are exactly:

| Field | Required declaration |
| --- | --- |
| `javaExecutable` | Absolute path to the provisioned JVM executable, inside `javaRuntime.source` |
| `expectedJavaSha256` | Approved executable SHA-256 |
| `javaRuntime` | Runtime-mount object |
| `systemLibraryMounts` | 1–16 runtime-mount objects for the base isolation configuration; the coordinator replaces these with admitted image/artifact mounts for each batch |
| `bubblewrapExecutable` / `expectedBubblewrapSha256` | Absolute `bwrap` path and approved SHA-256 |
| `resourceLimiterExecutable` / `expectedResourceLimiterSha256` | Absolute `prlimit` path and approved SHA-256 |
| `scopeSupervisorExecutable` / `expectedScopeSupervisorSha256` | Absolute `systemd-run` path and approved SHA-256 |
| `scopeInspectorExecutable` / `expectedScopeInspectorSha256` | Absolute `systemctl` path and approved SHA-256 |
| `systemdBusControllerExecutable` / `expectedSystemdBusControllerSha256` | Absolute `busctl` path and approved SHA-256 |
| `systemdUserRuntimeDirectory` | Exact systemd session runtime path, e.g. `/run/user/1000` |
| `workerClassPath` | Ordered array of 1–512 distinct pinned regular-file classpath entries |

A runtime-mount object contains exactly `source`, `destination` and
`expectedManifestSha256`. Both paths must be absolute, normalized and non-root.
The manifest uses the existing root-owned full-tree runtime manifest format;
the trusted provisioner must calculate and approve it before deployment. Mount
destinations may not overlap, and mounts may not expose the systemd session
runtime. Each classpath entry contains exactly `path` and `expectedSha256`.
All SHA-256 values are exactly 64 lowercase hex digits. No executable is selected
from `PATH`, no executable arguments come from this JSON, and the parser never
hashes the current host to manufacture approval pins. The launcher authenticates
the declared executables/runtime/classpath before BOOT and privately snapshots
the pinned classpath files.

Both the JVM mount destination and its source-path alias must be disjoint from
the native projection's `/usr`, `/lib`, `/lib64`, `/etc`, `/bin` and `/sbin`
destinations. Provisioning the JVM under `/opt` with a disjoint guest path is one
supported layout shape. A host JDK inside `/usr` cannot simply be added to the
image's `/usr` mount. The launcher checks these mount relationships.

## Capture lifecycle and limits

The host must support the existing Linux systemd/cgroup-v2, bubblewrap and
descriptor-bound isolation owner. The native runtime, JVM and control binaries
require trusted provisioning; the journal and scratch roots must exist and be
disjoint. Scratch must satisfy the dedicated filesystem lease's byte/inode
enforcement and ownership checks. An ordinary temporary directory is not a
replacement. The coordinator fixes operation budgets and authenticated batch
membership; the CLI provides no switches to weaken them.

The operation wall limit is 600 seconds, including both batches; resident memory
is capped at 1 GiB, processes at 64, and individual file growth at 64 MiB. The
dedicated scratch filesystem must provide at least 128 MiB and 4,096 available
inodes, while its total capacity must not exceed 512 MiB or 32,768 inodes. The
registered profile additionally bounds individual streams/artifacts and combined
captured output across both batches. Failure to meet any admitted limit produces
no completed reference marker.

The coordinator retains intent, scratch lease, per-batch preparation,
attachment, START, execution and exact observation records. Only a completed
capture prints the resulting `reference-observations.json` path. A failed launch
that retains a cleanup owner receives one explicit absence-proof cleanup
attempt; failure is still reported even if cleanup succeeds. Journal and scratch
residue remain for trusted reset. Do not treat an incomplete journal as a
completed capture or implicitly resume it.

The retained launcher receipt's cgroup counters are its existing frozen sample
before teardown, while unit/cgroup/process absence is proved afterward. This
route preserves those meanings; it does not relabel the sample as terminal
memory/PID event evidence or supply another consumer's terminal lifecycle proof.

## Installed qualification and independent replay

`decompengine.oracle.gcc.GccMetadataReferenceQualificationCli` is the separate
installed qualification entrypoint. Capture requires an ordinary nonzero UID,
the exact ordered installed classpath, and its adjacent root-owned, single-link
classpath authority. Development classpath overrides are rejected. Its closed
forms are:

```text
provision <profileRoot> <ociLayout> <freshRuntimeRoot> <jdkRoot> <deploymentJson> <controllerUid>
qualify <profileRoot> <ociLayout> <runtimeRoot> <deploymentJson> <firstJournalRoot> <firstScratchMount> <replayJournalRoot> <replayScratchMount> <reportPath>
```

Provisioning runs as root, consumes the Kotlin materializer's typed entries,
restores their exact metadata, and independently admits the result before
publishing the trusted deployment. The canonical positive controller UID fixes
both `/run/user/<uid>` and `/user.slice/user-<uid>.slice/user@<uid>.service/app.slice`.
It does not consume a caller-written staging receipt as authority. Publication
starts privately at root-owned mode 0400 under mode 0700; the provisioner retains
descriptors, verifies identity and bytes, and finalizes the deployment at mode
0444 under mode 0755 for ordinary-controller access. Neither location becomes
writable by that controller. The installed controller and worker use the same
authenticated classpath closure and JVM.

Qualification derives its session from the actual process UID and rejects UID 0
or a deployment naming another user's bus or cgroup parent. Journal, scratch and
report directories must belong to that UID and have exact mode 0700. The existing
contained worker's user-namespace and capability policy is unchanged; the
qualification entrypoint introduces no root-worker mode or permission bypass.

Before either capture, the installed ordinary controller borrows the authenticated
profile and admitted runtime to validate the closed orchestration declaration.
The compiled registration additionally pins the exact v2 contract and its
independently captured reference. It publishes `orchestration-declaration.json`
under the private report root after validating all seven phase startup closures
against selected literal/resolved runtime paths. The file declares 14 reference
cases and four recorded produced-program invocations; it performs no phase,
reconstructed-candidate or produced-program execution. Recorded produced-output
ELF identities are not mounted. Historical policy/probe source hashes remain
provenance data; no Python source is executed.

The metadata qualification report is now schema/provider v2 and binds that exact
declaration file's path, byte count and hash. The collector retains it both in
the private archive and as a top-level artifact, including when a later metadata
capture fails. A declaration receipt does not establish candidate behavior or a
completed metadata capture. The earlier v1 qualification format and nine-input
registration remain valid only at their own recorded source; this implementation
uses eleven compiled input bindings without changing registration schema 2.

Qualification performs two fresh coordinator captures on distinct dedicated
filesystems. Both successful captures retain their journal, scratch lease and
absence-proof ownership while the qualifier independently checks all 19 cases,
the complete journal chain, worker reports and operation bindings. It compares
exact raw observations with the separately fixed metadata reference and checks
that both operations have identical stable case bytes. The frozen expected
observations are never mounted into the worker. Only these retained captures
can publish a report with `referenceQualified: true`; a supplied JSON report or
fixture comparison result cannot authorize publication.

The `GCC metadata reference qualification` Actions workflow selects an exact
source SHA. A maintainer can select an introducing PR with the closed
`qualify:gcc-metadata-reference` label; after the workflow is registered on the
default branch, manual dispatch requires the input SHA to equal the selected
workflow SHA. The lane records immutable source ancestry and the observed
master tip. It reuses the existing trusted application/JVM/controller
provisioners and the existing ext4 helper with two 512 MiB, 16,384-inode profiles.
New reports, transport data, logs and journals are under checkout `build/`;
installed runtime and scratch paths use the existing host infrastructure.

The lane retains both operations' journals and scratch records, the installed
classpath authority, deployment, source identity, exact qualification report
and artifact digests. Scratch release requires capture, evidence collection and
upload to succeed; runtime cleanup additionally requires both scratch releases.
Incomplete operations remain retained until the ephemeral runner is torn down.
The report keeps the distinction between the pre-teardown counter sample and
the later unit/cgroup/process absence proof.

A successful exact-source hosted run and its retained evidence are still
required before claiming qualification. Local staging, unit tests and the
optional pinned-image worker replay establish their narrower checks only.
Candidate comparison and release authority remain false. This route does not
change the existing Python diagnostic reference observations.
