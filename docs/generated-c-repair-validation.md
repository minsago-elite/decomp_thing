# Generated-C repair validation

Issue #236 owns the production validation provider for `generated-c-make-v1`.
`GeneratedCRepairRuntimeProvider` registers the concrete Linux snapshot/build/behavior
implementation. Its public availability check deliberately remains unavailable while the complete
compiler/full-corpus path awaits separate public-factory qualification.
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

Hosted run `33947259314` at `7cb96ab` passed all six `CandidateValidationMountPolicyTest` cases,
including the real static probe and final writable-mount attestation, within 185 passing ACP tests
and 21 suites without skips. Artifact `9963769697` has SHA-256
`d3eac2c3f060154ee35a17d1ca644365020e703f7c56f1cd092323fad2739182`.
This qualifies the shared mount topology, separately from the production provider.

Runtime manifest reconciliation now keeps immutable root-owned manifests independent of the
forbidden-executable screening set in `LinuxBubblewrapBoundary.kt`'s `buildRuntimeManifest`.
Screening still hashes matching-size files and rejects forbidden content; its extra screening
hash does not change the provisioning commitment. User-owned snapshots still commit file contents.
Two benign `AcpRuntimeManifestConsistencyTest` cases verify both properties. The focused local
rerun passed ten tests with the one unprovisioned live mount case skipped. Source snapshot manifests
also use the same bounded canonical JSON encoding as the retained receipt and archive verifier.

## Hosted public-factory qualification procedure

`scripts/qualify-generated-c-validation.sh` assembles a separate disposable operator-style host.
It requires an explicit GitHub Actions run identity and noninteractive operator sudo. The helper
`ci-prepare-generated-c-validation.py` refuses existing targets, copies a bounded trusted GNU
compiler/tool closure into root-owned link-free files under
`/opt/decomp-generated-c-validation-ci`, and provisions distinct finite 64 MiB/4096-inode tmpfs
mounts under `/var/lib/decomp-generated-c-validation-ci`. These are independent of the ACP quota
test fixture. The source mount allows execution because captured ELF file binds inherit mount
flags; the writable output mount is `noexec`. Both deny device/setuid authority.

The fixture closure contains the system headers required by its fixed benign stdio program and
the declared compiler internals, startup objects and dynamic libraries. It does not claim support
for arbitrary headers, languages or operator installations. The reference binary is compiled from
the script's fixed trusted fixture before any candidate validation; that operation is fixture
construction. The production validation path has no host compiler fallback.

`generatedCRepairQualification` runs a test-source CLI that first writes only data: audited runtime
manifests, raw security-tool pins and the strict configuration document. The script installs the
runtime/sandbox documents as root-owned immutable configuration, while the ACP factory document
remains private to the application user. The CLI then calls `SecureRepairRuntime.open` and
`runRepair` through the registered production provider. It checks all retained stdin/argument
cases, stderr, an ordinary nonzero exit and complete acceptance, then starts a separate process
to reopen the graph and validate again while preserving the first receipt. It has no private
factory, test validation strategy, or availability/assurance override.

The orchestration always attempts ordinary verified unmount and removes only its own marked
fixture roots. Evidence remains in `build/generated-c-public-qualification`. At this checkpoint
the public provider guard remains active, so the full procedure cannot yet claim success. This
procedure covers benign baseline validation and reopening; agent candidate promotion, adversarial
input rejection, resource/cancellation outcomes and release archive qualification remain distinct
required evidence. No skipped or incomplete run may be reported as production qualification.

The current guard also covers a concrete terminal-observation gap. `SystemdScopeController`
verifies configured controllers before launch, while `AcpSandboxedProcess` starts cleanup on exit
and the collected scope can disappear before `runContained` captures its receipt. A later pathname
read cannot prove final pids/memory events; a low exit status does not prove no handled limit event
occurred. Before availability can open, a reviewed lifecycle must pin the exact observation
authority before execution, retain it until the entire candidate tree is quiescent, and capture
bounded final counters and exact supported terminal status before cgroup removal. Missing or
inconsistent observations must fail closed and their evidence must survive run/archive binding.
This checkpoint does not introduce a native supervisor change or a polling approximation.

## Supplemental failure diagnostic

When the provider has retained its existing failure receipt, it also attempts to retain
`<label>.validation-failure.json`. The legacy schema-version-1 producer diagnostic binds the exact
validation receipt SHA-256 and its source/profile/index/corpus/runtime commitments. The existing
version-2 receipt, registered proof, acceptance rules and archive verification are unchanged.
Before validation, the same atomic publisher replaces any prior supplement for that label with
zero bytes. A reset failure aborts before validation starts. Success, a withheld diagnostic, or a
later publication failure leaves unavailable diagnostic data instead of a previous reason with
an accidentally identical receipt digest. An empty supplement is not a valid schema1 record.
Diagnostic publication failure is suppressed on the original failure; it cannot replace that
failure, retry validation, or remove the primary receipt.
The primary receipt and retained supplement copies together must fit the existing retained-receipt byte ceiling;
the supplement is withheld with a suppressed budget failure when that ceiling has no capacity.
An absent supplement is unavailable diagnostic data, not a successful or skipped execution.

The existing primary failure classification retains its cleanup/cancellation priority. A separate
closed reason distinguishes an enclosing deadline or typed agent timeout from other resource
exhaustion. Unknown I/O failure remains validation failure. No exception message, command, host
path, peer text, input ID or input bytes enter this record. Its canonical encoding is limited to
4,096 bytes with fixed string, node and number bounds.

The phase records the enclosing producer operation at entry, including preparation, build,
original/rebuilt operation and finalization. It does not identify a native actor or prove that a
child started, stopped, or caused the failure. A case operation may record its zero-based position
in the exact bound receipt's input array; other phases use an explicit null position. The recorded
input count describes the corpus, not completed, successful or skipped executions. Existing
completed scopes, cleanup evidence and observation commitments must be interpreted separately.
If snapshot closure itself throws during unwinding, the phase becomes snapshot finalization and
the earlier case position is cleared. Successful closure preserves the original operation phase.
The original cleanup throwable and prior failure remain linked even if diagnostic notification fails.

### Selected invocation and canonical retention

The repair graph supplies a distinct `validation_<32 lowercase hex digits>` identity for each
baseline or candidate assessment. The typed request binds that identity to its run, candidate
revision, source, profile, index and corpus. With this request, the supplemental document uses
schema2 and includes the exact invocation. Identical primary receipts cannot identify a later call.
Requests without this context retain legacy schema1 diagnostics and cannot obtain a bound view.

The provider attaches a publication descriptor only after the bounded supplemental write returns.
The primary marker is attached first and survives any auxiliary failure. Already attached
exceptions are not duplicated, and an auxiliary provider marker is retained as a
wrapped cause rather than a competing top-level provider. The original status classifier therefore
continues to see its single original marker. Before canonical storage,
the caller checks both paths against its exact request, and the graph authenticates both reported
byte commitments through descriptor-pinned stable reads. It retains the primary as
`reports/<validation identity>.validation.json` and the supplement as
`reports/<validation identity>.validation-failure.json`, independently of the supported `--reports`
directory. Absolute external directories, relative directories and other project directories use
the same canonical pair. Both files use the existing descriptor-pinned atomic no-replace publisher:
existing identical bytes are idempotent; different bytes are refused.

New canonical bindings use schema2 with these fixed portable names. The operator-selected pair and
its canonical copies count as `2 * (primary bytes + diagnostic bytes)` against the configured
`maximumIndexEvidenceBytes`; the canonical pair also fits within the existing 64 MiB inspection
allowance. This does not increase either configured limit. Schema1 bindings preserve their original
encoding and retention accounting. A copy or verification failure leaves no committed binding.

Only after both immutable copies are retained and checked does the graph commit its portable descriptor
to the owning run using run schema3. Legacy run schemas1/2 preserve their previous encoding and
have no invented descriptor. Run, candidate, source/profile/index/corpus associations and unique
invocation identities are checked in canonical, read-only history and release archive readers.
Rollback and interruption preserve this correlation; it never supplies acceptance or release proof.
Uncommitted orphan files are not selected by the history capture.

### Read-only run diagnostic selection

The recorded history view exposes opaque artifact references and commitments, without provider
paths or private summary text. `historyRunEvidence=<recorded run reference>` requires the captured
`historyGraph` digest and selects a run on the current bounded history page. It cannot be combined
with `historyEvidence`, and it does not require a candidate attempt for a baseline failure.
Default history pages do not read run diagnostic payloads.

For durable web jobs, the canonical capture also contributes both explicitly selected run diagnostic
paths to the bounded artifact listing beneath `source-tree`. This includes baseline failures with no
candidate attempt. Unselected run diagnostics and missing capture mappings add no paths; a page from
another snapshot is refused before the listing can use it.

The existing checked selected-report namespace and duplicate-target refusal apply before reads.
Primary and diagnostic bytes share the existing 64 MiB request-wide byte/call allowance. An explicit
bound receipt reserves its admitted byte count instead of the generic 16 MiB presentation limit;
its parser uses that same admitted size, capped at 64 MiB. Typed run references bypass the generic
artifact pass, so that pass cannot cache a failed smaller read before the bound read. Byte capture
may be cached by path, while integrity is checked separately for each selected invocation. The reader
checks both exact byte commitments, schema2 invocation commitment, source/profile/index/corpus/runtime,
primary outcome/cleanup, input count and any case position before exposing closed reason/phase labels.
Missing or empty data is unavailable; changed, unbound, malformed or cross-paired data is withheld.
Neither private receipt content nor exception/peer text is projected into these labels.

This selection does not start validation. It does not establish a native actor, current source,
successful case, acceptance or release qualification. Full stable case IDs, normalized accessible
text/binary comparisons, validated source navigation and the live case adapter remain separate work.
The new schema and reader data controls await their own normal Actions; this follow-up adds no
actual native process, provider, controller or browser test context.
