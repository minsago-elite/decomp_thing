# Generated-C repair validation

Issue #236 owns the production validation provider for `generated-c-make-v1`.
`GeneratedCRepairRuntimeProvider` registers the concrete Linux snapshot/build/behavior
implementation. Its public availability check deliberately remains unavailable while the new
candidate-validation writable-mount closure awaits successful real-boundary qualification.
Pure policy tests and successful ACP tests do not qualify the generated-C compiler/full-corpus path.

## Authority and execution

The provider accepts one immutable `RepairCandidateValidationRequest`: exact source bytes,
source/profile/index digests, retained input corpus and digest, original executable input,
resource budget, cancellation and the enclosing monotonic deadline. Legacy split `compile`,
`rebuiltProgram` and `evaluateBehavior` calls cannot bind these inputs and fail closed.

The source snapshot contains only registered `Makefile`, `src/` and `include/` files. Files have
fixed read-only mode and recorded bytes/hash. Candidate links are excluded. The application creates
one `build` link from the read-only snapshot to a separate writable quota-backed directory;
its target and quota identity are retained in the receipt. The canonical project directory is
never the candidate build working directory.

The provider holds exclusive directory-descriptor locks on both dedicated tmpfs mounts, including
across JVMs, and takes bounded process-wide scheduler admission. Snapshot copying, runtime closure
authentication, launch, output collection and executable capture share cancellation and deadline.
Verified cleanup precedes any successful proof. Unverified cleanup retains staged authority,
mount leases and scheduler capacity instead of creating a fresh admission slot.

Each compiler or program scope uses the pinned `LinuxBubblewrapBoundary` and static pre-exec gate:
cleared environment, denied network, disabled nested user namespaces, exact pinned runtime binds,
whole-tree cgroup pids/memory/CPU/runtime controls, rlimits and verified cleanup. The generic
`CANDIDATE_VALIDATION` purpose additionally seals `/`, `/tmp`, `/dev`, `/dev/pts` and `/proc`
read-only. Final setup-waiter mount attestation rejects writable mounts outside exact quota-backed
grants, except fixed standard character devices checked by type and major/minor. The effective
mount set and quota grants contribute a retained launch digest. Issuing remount arguments alone
does not prove this layout.

Compiler, linker, assembler, shell, make, find and mkdir roles have exact authenticated file mounts.
Build-only headers/compiler internals and program runtime dependencies are separately declared.
Candidate build files cannot add host mounts, inherit host environment or select runtime authority.

Successful compilation captures a bounded regular ELF. Each retained input runs the captured
reference and candidate executable separately in a fresh contained scope and writable directory.
A program receives its executable file and declared program runtime, without its host sibling
directory or build tools. All IDs, arguments, stdin, exit statuses, stdout and stderr are retained.
The current `ProcessInput` schema declares no filesystem input/output artifacts; such artifacts are
not silently treated as part of this stdio corpus.

## Existing budget mapping

Source files plus both captured executables charge `maximumSourceBytes`. Each executable is capped
by the smaller of `maximumSourceFileBytes` and the operator sandbox file-size limit. Source entries
charge `maximumDiscoveryEntries`, with path depth bounded by `maximumDiscoveryDepth`.

Every writable build/program mount has finite capacity no larger than `maximumStagingBytes` and
`maximumStagingDirectories` inodes. Defaults are 2 MiB and 512 entries; larger builds need an
explicit larger allowed repair budget. Availability may use a larger finite bound, but each actual
request rechecks its own capacities before launch. An ordinary filesystem directory is not quota.

Build and full-corpus output share `maximumBehaviorOutputBytes`, with per-scope stdout/stderr caps.
Behavior scopes also obey `maximumBehaviorExecutionMillis` and the remaining enclosing deadline.
Compiler scopes use the remaining deadline and operator process/memory/CPU/file limits. Receipts
are capped by `maximumIndexEvidenceBytes` and the strict JSON hard limit of 64 MiB. Truncation cannot
produce an accepted full-corpus proof. The existing repair budget/recovery schema is unchanged.

The current JDK process result cannot distinguish a high explicit exit code from the conventional
signal encoding. Validation therefore rejects exit statuses outside 0–127 as a resource/termination
failure, rather than accepting two matching limit-killed programs. Exact terminal cgroup OOM/pids
event evidence and qualification for intentionally high exit codes remain incomplete #236 work.

## Explicit production provisioning

`GENERATED_C_REPAIR_CONFIG_FILE` names a bounded root-owned configuration file. The file and its
ancestors must be canonical, without links or group/world write access. It is independent of
`ACP_CONFIG_FILE` and `DECOMP_TEST_*`. The provider does not discover compiler tools, download a
runtime, resolve agent secrets or accept an implementation/command/assurance switch.

Schema version 1 has these exact fields:

| Field | Required value |
| --- | --- |
| `schemaVersion` | `1` |
| `profileId` | `generated-c-make-v1` |
| `sandboxConfigurationFile` | Absolute canonical root-owned containment configuration path |
| `tools` | Exact make, compiler, linker, assembler, shell, find, mkdir records |
| `buildRuntimeMounts` | Bounded array of exact compiler/header/internal runtime records |
| `programRuntimeMounts` | Bounded array of exact executable runtime records |
| `sourceTmpfs` | Absolute canonical dedicated source mount |
| `outputTmpfs` | Absolute canonical independent writable-output mount |

Each mount/tool record has exactly `source`, `destination`, `sha256`. Digests are 64 lowercase hex
characters supplied by the trusted provisioner. Tools map to `/decomp-generated-c-tools/` filenames
`make`, `cc`, `ld`, `as`, `sh`, `find`, `mkdir`, respectively. Runtime sources are root-owned and
non-writable through their ancestry. Broad host directories including `/usr`, `/usr/bin`, `/lib`
and `/usr/lib` are rejected. Destinations are unique; shared build/program runtime entries must
bind identical sources and expected manifests. Both file and directory mounts use the audited
runtime manifest format produced by `calculateAcpRuntimeManifestSha256`; these are distinct from
plain executable content hashes retained separately in the receipt.

The sandbox file contains the established ACP schema-version-2 document. Only its strict containment
policy is parsed from one bounded byte snapshot, whose canonical hash joins the runtime binding.
Agent secrets and transports are not resolved. Launcher executables and the static gate helper
still require their audited pins.

The source/output locations must be otherwise-empty, current-user-owned mode-0700 dedicated tmpfs
mounts with finite `size` and `nr_inodes`. The provider leases them; it does not create mounts or
request privileges. Production mounts must not be replaced with the CI quota fixture.

## Evidence and qualification

`<label>.validation.json` binds source/profile/index/corpus, runtime configuration, source records,
the application-owned output link, executable hashes, every input and per-scope output plus complete
canonical sandbox evidence fields. Its proof hashes exact canonical receipt bytes after verified
cleanup. Graph acceptance consumes those identities instead of promoting an arbitrary rebuilt path.

`CandidateValidationMountPolicyTest` has a harmless static probe that writes one ordinary file in
an explicitly supplied finite test tmpfs. Its hosted result qualifies only the shared namespace
seal and final mount attestation. Production public-factory qualification separately needs both
production-style test mounts, root-owned tool/runtime configuration, a benign generated project,
the full retained corpus, failure outcomes and fresh-process reopen. Until those results exist,
#236 stays open and public production availability remains closed.

The guarded checkpoint passed main/test compilation and 28 selected tests locally; one real mount
topology test skipped because this host has no explicitly provisioned dedicated tmpfs. The selected
suites were `CandidateValidationMountPolicyTest`, `GeneratedCRepairValidationProviderTest`,
`AcpSandboxPolicyTest` and `AcpHarnessFactoryTest`. This is boundary-policy/configuration evidence,
not a successful compiler/full-corpus production run.

Runtime manifest reconciliation is also pending under #236. In `LinuxBubblewrapBoundary.kt`,
`calculateAcpRuntimeManifestSha256` calls `buildRuntimeManifest` with an empty forbidden-executable
set. Launch-time `buildRuntimeManifest` hashes otherwise immutable root-owned file contents when
their sizes match a forbidden security executable; those additional hashes contribute to the
manifest. A legitimate same-sized runtime file can therefore yield different provisioning and
launch manifests. This fails closed but can prevent an otherwise valid compiler/header/runtime
closure from launching. Positive production qualification must wait for a consistent authenticated
manifest definition and corresponding benign regression coverage.
