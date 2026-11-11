# ACP changes and workflow acceptance

ACP changes use the shared `AgentFileChange` contract. A change report describes
observed bytes; the requesting workflow decides whether those bytes are an
acceptable revision after its policy and validation checks.

The former standalone `AcpChangeSetValidator` and its snapshot/change types had no
production or test callers. They have been removed. That helper supplied a
separate profile/allowlist policy, inferred moves from equal hashes, and did not
match the validation paths used by reconstruction or repair. Removing it changes
no production permission, supported operation, or acceptance decision. New code
must use the execution contract and the workflow boundaries described here rather
than recreate an independent validator that is not connected to acceptance.

## Execution observations

For an ordinary workspace invocation, `AcpAgentHarness` takes initial and final
regular-file snapshots for the request's declared path rules. It hashes file
contents incrementally and checks the request's cancellation and wall deadline.
Each snapshot has fixed implementation caps of 8,192 visited entries, 4,096 unique
regular files, 8 MiB per file and 64 MiB of total hashed content. Directory entries
and repeated rule traversal consume the entry budget; overlapping rules retain and
hash a regular file once. Declared sizes are checked before opening content, and
streamed bytes are charged before hashing so file growth cannot evade the byte
caps. A read may consume at most one fixed hash buffer beyond the remaining budget
before rejecting it. Initial and final snapshots have separate budgets. Either
limit failure returns RESOURCE_EXHAUSTED with the snapshot phase and limit category,
never a partial change list. Final-component symlinks are not followed when opening
content. Hashing uses the shared Linux descriptor boundary: open and retain each
directory component, authorize the regular file relative to its parent, then
stream the still-owned file through its kernel descriptor with a 64 KiB buffer.
Before returning a digest, recheck file key/size/modification time and descriptor
identity, and reopen the named directory/file chain to verify its bindings.
Unavailable or changed bindings fail with a bounded workspace-violation reason.
Discovery also uses directory-relative entry opens and directory listings through
owned handles. Workspace roots stay pinned through the scan, hashes must match
the discovered file identity, and each named root is revalidated before returning.
At most 64 roots and 64 relative path components are admitted, bounding retained
root and traversal handles in addition to the entry/file/byte limits. Non-default
filesystem providers are rejected before native path resolution. Parent
components consume entry budget too. An absent parent of an explicit authorized
target preserves the existing creation behavior. These checks do not make the
multi-file observation atomic or establish a complete concurrent-mutation matrix.
Encountered symlinks (including dangling links) and special files are rejected
instead of being omitted by a regular-file filter. A directory entry that
disappears or cannot be inspected also fails the scan. These failures become
WORKSPACE_VIOLATION with a bounded phase/reason diagnostic and no partial changes.
A missing explicitly authorized target remains eligible for later creation;
ordinary directory entries are counted and recursive rules traverse them.
The final snapshot is collected after process and sandbox cleanup. Its private
`WorkspaceSnapshot.diff` reports created, modified, or deleted files in canonical
root/path order and checks the corresponding `CREATE_FILE`, `WRITE_FILE`, or
`DELETE_FILE` operation against the exact `AgentAccessPolicy`.

There is no special evidence-path exemption in this diff. A profile role does
not grant permission by itself. A rename is not an independently authorized move:
the observed source deletion and destination creation require their respective
permissions. Filesystem callbacks and terminal operations remain subject to their
own contained execution boundaries before this final observation is made.
The snapshot retains each regular file's mode, owner, group and link count as well
as its digest and size. If an existing file changes any of those metadata fields,
diffing fails with WORKSPACE_VIOLATION rather than reporting no change or treating
WRITE_FILE as metadata authority. The current contract exposes no metadata-edit
operation. Replacing a file atomically with the same bytes and metadata remains
unchanged even though its inode differs. Regular files carrying extended attributes
are explicitly unsupported by ordinary snapshots, consistent with the text-write
bridge's existing rejection policy. Attribute-name presence is checked through the
owned descriptor before and after hashing; values are not read, removed or exposed.
Even a zero-length attribute is rejected with a bounded reason. This conservative
default does not implement a profile-specific allowlist for attributes. Creation-role
metadata, timestamps, directory metadata and any supported attribute policy still
need their complete shared profile contract and qualification.

The final report is attached to the invocation-bound execution receipt. A
successful prompt stop reason does not remove failures in cleanup, final snapshot
collection, or the caller's later source/build/behavior validation.
Focused harness tests cover oversized initial input before process launch and
host-injected text-file growth at a post-cleanup final-snapshot checkpoint after a
benign completed turn. The latter must fail final snapshotting with verified
process/sandbox cleanup and without complete execution evidence or a returned
partial change list. This is deterministic fault injection, not a claim that an
agent bypassed the independent filesystem or protocol-frame limits.

### Turn correlation

Workflow callers that record progress create one host-owned `AgentTurnIdentity`
before dispatch. Its UUID, task identity and request commitment are passed to the
progress projection and execution receipt, including captured repair dispatch.
Invocation receipt schema 3 persists the UUID, task identity and request digest as
an exact binding; schema-2 receipts remain readable as historical evidence and do
not receive synthetic turn IDs. Repair schema-7 graphs and reconstruction
schema-7 checkpoints require the serialized identity to match the separately
persisted pre-dispatch intent before reuse, recovery, or archive verification.
ACP session journals write schema 2 when a correlated turn starts and retain that
turn UUID with a cleanup-verified completed turn. Schema-1 journals remain
readable; their historical records are not assigned synthetic turn IDs.

This is correlation metadata, not durable workflow intent or an acceptance
decision. Progress remains display-only. A turn UUID, completed receipt or
provider stop reason does not prove a complete change observation, authorize a
candidate, establish validation, or commit publication. Durable intent and
workflow-assessment records bound to publication recovery remain the separate
#733 acceptance boundary.

Before dispatching any new captured repair turn, the workflow upgrades an
existing non-pending schema-4, -5, or -6 repair graph to schema 7. Existing
revision and invocation records retain null turn/assessment references and
remain historical; the upgrade does not synthesize provenance or change their
acceptance authority. A turn admitted after the upgrade must persist and bind
its own intent, receipt, and assessment. A graph with pending recovery is not
upgraded for a new dispatch.

Schema-7 accepted decisions retain those provenance bindings in the committed
node. Startup authenticates the bound intent, receipt, and validated assessment
before exchanging any candidate source bytes; missing, cross-paired, or
corrupt evidence leaves the durable decision and source tree untouched.

## Captured repair

`CapturedRepairStagingAuthority` freezes the selected readable source bytes and
exact writable paths and checks its file, directory, and staging-byte budgets.
The ACP process sees an empty namespace anchor at
`/decomp-acp-captured/project`; this is not a mount of the canonical source tree.

`AcpCapturedRepairFilesystem` serves the captured source through text callbacks.
It permits replacement of existing staged files under exact read/write rules.
Each write reaches `BoundedRepairOutput` before becoming visible to a later read,
so source-file, patch-file, aggregate-patch, and logical-workspace limits apply
during the operation. After the session closes, its change report is derived from
the initial and final captured bytes. The ACP bridge exposes no create, delete,
move, or terminal capability in this workflow.

`TraceGuidedRepairLoop` independently reconciles the returned receipt and change
report with captured files. It requires a completed result and, for the production
path, release-complete ACP invocation evidence; canonical unique reported paths;
the exact staged file set; agreement between actual and reported changes; and
only authorized `MODIFIED` records with matching before/after hashes and byte
sizes. A removed captured file is rejected even though the lower-level mutation
sink can represent a deletion for other adapters.

`ModuleRevisionGraph.installCandidate` then checks the pending attempt's allowed
paths, current head, source/patch budgets, and preimages before storing candidate
blobs and installing the revision. Build and retained-regression assessment are
later workflow steps. The public generated-C production validation provider is
still unavailable; current tests using a host compiler are explicitly
`TEST_ONLY_NON_RELEASE`. Intermediate repair progress and fully accepted-head
semantics also remain separate open work under #65 and #49.

## Module reconstruction

The harness-backed module reconstructor in `SourceTree.kt` derives read-only
context files and one writable implementation path from the planned module. Its
request permits reading, creating, or modifying that target, not deleting it.
After the invocation, it requires exactly that reported path, the expected
created/modified kind, matching preimage and output hashes, and a consistent
reported size when supplied. A failed or interrupted invocation restores the
previous target bytes, or removes a newly created target.

`SourceTreeGenerator` applies the module/profile checks and compiler gate before
publishing an accepted checkpoint. It records invocation and compiler evidence
and restores the previous accepted checkpoint when a replacement is rejected.
For ACP-produced source, publication preserves the exact staged bytes so the
assessment's after hash remains the hash observed in the invocation receipt;
non-agent generators retain the existing host newline normalization.
The current module compiler receipt is local validation evidence, not a contained
production full-project build or complete behavioral-equivalence proof. Those
limits remain tracked by #64, #84 and the archive/release issues.

## Durable output publication boundary (#732)

The reconstruction output journal makes the four publishable members
(`source-tree`, `source-tree.zip`, `reconstruction.json`, and
`.decomp-agent-sessions`) recoverable across process interruption. Before the
durable decision, recovery aborts the staged generation; after the decision, it
rolls the selected generation forward. A retained journal, input-switch marker,
or private transaction residue makes cooperating readers refuse the workspace
until recovery completes.

CLI repair holds the same workspace's exclusive lease and writes a durable
in-progress marker before it can mutate the published tree. If the process exits
before the repair runtime returns a terminal graph outcome with no unresolved
rollback, the marker keeps cooperating readers and reconstruction activation
unavailable. A normal return alone is insufficient: an unresolved rollback
keeps the marker. The next repair runtime may reopen the graph to complete its
pending recovery before a verified outcome can retire the marker. This is
fail-closed recovery gating, not automatic rollback by a source reader. Marker
publication uses a synced private temporary followed by a no-replace rename;
abandoned temporary markers keep readers unavailable until an exclusive repair
lease or workspace activation removes them. Workspace activation does this only
before repair begins; a published final marker still blocks activation.

Regular-file atime is part of the reconstruction member commitment and
commitment reads use `O_NOATIME`. Directory atime is intentionally excluded:
directory enumeration can update it as part of ordinary observation, so it is
not a stable publication property. Directory mode, ownership, identity, size,
mtime, xattr policy, and the framed child commitments remain bound.

The member renames are sequential. This is **not** an unrestricted atomic
filesystem swap: readers must hold the reconstruction publication lease for
the entire read or copy. The contract is crash-recoverable publication with
generation visibility serialized for cooperating readers on one local
filesystem. Direct path readers that bypass the lease, other hosts, and network
filesystems are outside this guarantee. CLI repair holds the same workspace's
exclusive lease while it mutates a published source tree; web repair works on a
private per-attempt copy. Repair graph rollback and the reconstruction output
journal remain separate transaction records.

The reconstruction journal does not include `analysis`, progress reports, or
compiler feedback in its four-member rollback set. Those records can contain
attempt diagnostics even when accepted source publication is rejected. The
current workflows also have deliberately narrow operations: module
reconstruction accepts one declared target creation or modification, while
captured repair accepts modifications of selected existing files. General
delete and move installation, complete parent-directory metadata restoration,
and a cross-host publication protocol are not established by this boundary.

The durability controls exercise process interruption and journal recovery.
They do not emulate power loss or qualify storage-controller write ordering.
Those claims require a separate VM or block-device power-cut qualification.
Similarly, scripted ACP and local validator tests establish fixture behavior,
not production-provider acceptance or full-project release qualification.

Acceptance authority controls include the scripted
`SourceTreeTest.confident completion prose and completed tool status cannot
accept a missing reconstruction change` case and the ACP repair
`TraceGuidedRepairAcpIntegrationTest.confident completed ACP claim without
filesystem changes is rejected` case. They show fixture-level that a completed
stop, positive prose, or a completed tool status cannot substitute for an
observed change and the workflow's acceptance checks. The repair graph recovery
suite also halts a child JVM after `.restore` is renamed to `.restore.cleanup`
and verifies that reopening restores the original source inode and removes the
quarantined candidate. These tests do not qualify live ACP providers or replace
the exact-source hosted gates.

Exact rollback fixtures compare source bytes and descriptor-bound file metadata,
including identity, mode, ownership, link count, atime, mtime, and ctime, plus
the witnessed ancestor-directory metadata. Coverage includes
`ModuleRevisionGraphTest.pre-candidate rejection preserves source identity
metadata and bytes`, `ModuleRevisionGraphTest.rejected detached candidate leaves
source inode and ancestor metadata unchanged`, and repair-loop rejection cases
for compile failure, retained regression, no-write completion claims, and
scripted terminal failures. Reconstruction publication refusal compares each
published member's complete commitment in
`ReconstructionOutputPublicationTest.every accepted member rolls back together
on agent validator and cancellation refusal`. The public archival workflow test
`ArchivalReconstructionTest.workflow build failure preserves the published
generation metadata` also compares all four published member commitments after
a compiler failure. Directory atime remains excluded from reconstruction tree
commitments as documented above. These are local fixture checks; they do not
establish live-provider or power-loss behavior.

Schema-6 staging persists each unlinked candidate inode identity before creating
its private name. `ModuleRevisionGraphTest.child crash after partial private
staging recovers undecided schema six without touching source` covers recovery
after linking; `ModuleRevisionGraphTest.undecided schema six recovery accepts a
registered stage inode that was never linked` covers the graph-write/link gap;
and `ModuleRevisionGraphTest.undecided schema six recovery refuses a staged inode
replacement before cleanup` proves same-bytes inode substitution is preserved as
unresolved evidence without changing the source or decision. These are local
process-crash controls, not power-loss or hostile same-UID qualification.

Schema-6 decided-publication recovery also authenticates every ACP receipt
referenced by retained graph nodes and the pending attempt, checks the bounded
receipt-file inventory, and derives the accepted node's changed and invalidated
module sets from a candidate-backed recovery index before the first source
exchange. The fixture controls
`ModuleRevisionGraphTest.schema six recovery authenticates its ACP receipt before
source exchange`, `ModuleRevisionGraphTest.schema six recovery authenticates
provisional ancestor receipts before promotion`, and `ModuleRevisionGraphTest.schema
six validates the complete committed graph before source publication` reject
missing, malformed, or semantically inconsistent decision evidence without
changing source inodes or rewriting the durable decision. This is local process
recovery evidence only; it does not establish hosted qualification or power-loss
durability.

For durable web reconstruction and repair, the committed publication journal is
retained until the matching workflow attempt records a candidate and terminal
outcome derived from the published source tree. Startup recovery performs the
same reconciliation after verifying a decided generation and before removing
its journal. If candidate verification or attempt persistence fails, recovery
leaves the journal in place and keeps output unavailable; an installed
generation is never silently reported as a failed, candidate-less attempt after
successful reconciliation. Repair publication first persists a receipt binding
the staged candidate, terminal classification, completion time, and measured
usage. The durable decision follows that receipt; startup verifies it against
the recovered source tree and commits those exact values atomically with the
terminal attempt. A receipt left by an aborted pre-decision publication is
cleared only after startup has recovered that run's journal.

### Repair preimage and publication decision

Schema-1–5 repair records use the historical rollback contract. Their retained
preimage metadata may bind file identity and timestamps, but the hard-link and
per-file replacement protocol can itself change ctime and parent-directory
metadata. Recovery of those records must remain explicitly legacy; it must not
infer an exact witness from current filesystem state or upgrade a pending
attempt into a schema-6 decision.

The schema-6 contract is stronger. Before its durable acceptance decision, the
transaction must not create, remove, link, rename, or otherwise mutate an entry
in any witnessed source file or ancestor directory. It records exact file
identity, ownership, mode, link count, size, supported attribute policy, and
nanosecond atime/mtime/ctime, plus each ancestor directory's identity,
metadata, timestamps, and entry inventory. File reads and directory
enumeration used to capture or check that witness must be metadata-neutral
(`O_NOATIME`); inability to do so refuses before publication. Rejection or
failure before the decision verifies the witness and removes only authenticated
private staging state. After final canonical-source and witness validation, the
run cancellation and aggregate-deadline check is repeated immediately before
the durable decision write. Once that decision is durable, cancellation cannot
turn acceptance into rollback; recovery only rolls the committed publication
forward.

Before a staged replacement inode is linked to its transaction-bound private
name, schema 6 persists its device, inode, mount, mode, owner, candidate digest,
and size in the pending graph. Startup recovery checks that exact inode binding,
owner, link count, size, and content before removing a linked pre-decision stage;
an absent stage is safe because no source entry was changed. An unexpected name
or inode leaves the graph unavailable and preserves the entry as unresolved
evidence. The later acceptance decision records the complete staged-file and
target-parent bindings used by roll-forward.

An undecided detached schema-6 attempt is recoverable only when its durable
install marker proves that candidate installation did not begin. Recovery checks
the full source witness before discarding transaction-bound stages.

The pending record also carries a compact digest over the metadata-neutral
observation of the complete accepted source inventory. This covers unchanged
source files outside the current attempt's writable paths, so content-index
validation alone cannot miss metadata-only drift elsewhere in the accepted
revision.

After the complete decision is durable, recovery is roll-forward only. It
authenticates target and staged identities at every exchange boundary and
retains an unavailable marker while publication is partial or ambiguous. It
must never restore preimages or report ordinary usable-source success after
that point. Legacy schema-1–5 recovery remains separate and cannot claim this
exactness. These are acceptance requirements, not evidence that schema-6
recovery or hosted qualification is complete. Immutable pending graph fixtures
from the historical schema-1–4 writers now exercise current-reader rejection,
preimage restoration where the old writer installed a candidate, and migration
to schema 5. Each fixture records its producer revision under
`src/test/resources/repair/legacy-schema*-writer-pending/PROVENANCE.md`. The
test preserves the historical profile identity while delegating layout
resolution to the current generated-C profile; it does not establish admission
through the production profile registry. Schema 3's detached candidate leaves
live source unchanged. The capture can be reproduced with
`python3 scripts/verify-legacy-repair-graph-fixtures.py`; per-fixture
`SHA256SUMS` files bind the checked-in payload, and the verifier compares
recaptured output to it. Schema 3's writer-generated run start/deadline
timestamps are the only fields normalized during reproduction. These fixtures
do not establish archive admission, hosted checks, or production qualification.

Decision-write failure boundaries have local process-crash controls in
`ModuleRevisionGraphTest.exception after schema six decision exchange leaves an
undecided attempt recoverable`, `ModuleRevisionGraphTest.child crash before the
schema six decision exchange recovers exact undecided source`, and `ModuleRevisionGraphTest.child
crash after the schema six decision exchange rolls forward exact staged
identities`. They check the complete indexed source inventory with metadata-
neutral reads, including file inode and timestamps; the pre-decision controls
also check ancestor directory metadata and staging cleanup, while roll-forward
checks the accepted staged inode bindings and unchanged source files. These
process-crash tests do not establish power-loss ordering or hostile same-UID
race resistance.

## Remaining scope of #63

## Durable invocation provenance checkpoint for #733

The captured repair workflow and the generated-C reconstruction workflow now
have implementation paths for host-authored turn intents and workflow
assessments. Each writes a canonical intent before provider dispatch, then binds
the receipt to that intent and the unique turn UUID. Each writes an immutable
assessment after its available policy and validation checks. Repair schema-7
graph records and schema-4 history records carry content-addressed references;
reconstruction agent checkpoints use schema 7 and embed the referenced intent
and assessment. Legacy repair schema-6 records and reconstruction checkpoint
schemas 4–6 remain unassessed; no turn IDs or verdicts are synthesized for
historical evidence.

The assessment distinguishes observation completeness, observed stop reason,
change-set digest, policy verdict, validation proof references, and workflow
eligibility. Eligibility is not a publication decision: the existing durable
repair publication transaction remains the only source of committed revision
authority. Intent-only or receipt-only attempts do not claim acceptance.

Reconstruction stores the append-only sidecars in the leased output root under
`.agent-turn-evidence/<input-sha256>/<module>/<turn-uuid>/`, outside the staged
`source-tree` and the four-member #732 publication set. This preserves
pre-dispatch and rejected/interrupted evidence when a source generation is
rolled back. The accepted checkpoint embeds the exact canonical intent and
assessment bytes and names their output-root paths. Checkpoint reuse and the
archive verifier reject malformed, duplicate-field, digest-mismatched,
cross-paired, request/policy/session/change/update-mismatched records. Accepted
schema-7 checkpoints also bind the assessment's validation proof digest to the
exact compiler evidence. Interruption reports reference any persisted intent
and assessment; an intent without a receipt remains unknown, and an assessment
without completed validation remains ineligible. These records do not extend
#732's rollback set, establish a publication decision, or authorize readers to
bypass its recovery lease.

If repair recovery finds a schema-7 intent and receipt but no assessment, it
first persists and authenticates a conservative `INTERRUPTED` assessment before
terminalizing the attempt. If that write or its readback fails, graph opening
fails closed and retains the pending recovery state. A focused workflow test
injects a graph-binding failure after the immutable rejected-assessment sidecar
is written, then verifies startup reconciles that exact assessment and retains
the original source bytes. A graph-level control also verifies that a
receipt-bound schema-7 attempt cannot be rejected without a bound assessment.
These are deterministic failure-injection checks, not process-death
qualification of the entire repair workflow.

After a `PROVISIONAL` or `VALIDATED_FOR_PUBLICATION` assessment is durable, an
exception before the graph disposition also leaves the attempt pending. The
immutable assessment cannot be rewritten as an ordinary rejection; startup
recovery performs the verified rollback or roll-forward and records the
terminal disposition.

The current ACP adapter exposes its normalized stop reason in the invocation
receipt, but does not expose the raw protocol stop code. Reconstruction
assessments therefore leave `protocolStopCode` null instead of deriving or
inventing a wire-level value.

The repair implementation checkpoint at `6cd76bd30d1bec7fad81fcad6617f51248333af3`
passed local compilation and 242 focused tests: the assessment codec (2),
repair graph (199), repair history reader (35), and ACP repair integration (6).
These tests cover repair intent/receipt/assessment binding, graph recovery,
archive/history consistency, and canonical assessment parsing. They are local
evidence only; no hosted run or independent crash-after-each-evidence-write
campaign has qualified this commit.

At the original reconstruction checkpoint, the implementation passed local
compilation and 133 focused tests across
`ReconstructionAcpEvidenceArchiveVerifierTest` (20),
`ReconstructionTurnEvidenceStoreTest` (3), `AcpChangeAssessmentTest` (2),
`WebProductionWorkflowsTest` (45), and `SourceTreeTest` (63). Coverage includes
pre-dispatch intent persistence, private immutable sidecars,
interrupted/unknown assessments, schema-7 archive binding, tamper refusal, and
legacy checkpoint compatibility. These are local tests against the current
implementation at that checkpoint, not hosted qualification. The repair checkpoint at
`6cd76bd30d1bec7fad81fcad6617f51248333af3` separately passed its 242 focused
tests; that result predates the reconstruction changes and is not exact-head
verification of the combined implementation.

The current combined local source passed a focused Gradle run of 236 tests:
`ReconstructionTurnEvidenceStoreTest` (6),
`ReconstructionAcpEvidenceArchiveVerifierTest` (21), and
`ModuleRevisionGraphTest` (209). This includes receipt admission rejection
without consuming the immutable slot, reconstruction receipt/intent
cross-pairing refusal, and recovery that writes an interrupted assessment
before terminalizing a schema-7 receipt-only attempt. The run compiled the
current implementation and tests; it is local evidence, not hosted or
production qualification.

This remains an implementation checkpoint, not full #733 qualification or
closure evidence. The process-death matrix below covers repair evidence writes
and graph binding, but does not qualify production-provider acceptance.
Production repair acceptance is also blocked on the qualified validator under
#236. #733, #63, #236, and #732 remain open; do not use these source changes to
claim production repair or reconstruction acceptance.

This cleanup removes an unused competing policy path; it does not complete #63.
The actual workflow contracts still need the requested shared profile-driven
acceptance coverage, including an explicit supported-operation matrix and
consistent treatment of immutable evidence and source roles across entry points.

Ordinary workspace snapshotting currently visits regular files selected by the
path rules. It is not a complete independent inventory of every filesystem entry
or an authenticated descriptor snapshot of all workspace state. The snapshot's
entry/file/byte caps bound this observation, not aggregate writable storage, inode
allocation, all concurrent workflows or entries outside the declared rules.
The separate filesystem/terminal containment
controls must not be presented as proof that these snapshot requirements are
complete. Any consolidation must retain the stricter captured-repair behavior
and preserve exact path, operation, revision, and evidence authority.

Creation, deletion, and move support in a general profile must be specified and
validated at the relevant acceptance boundary before a workflow exposes it.
Current module reconstruction and captured ACP repair deliberately have narrower
operation sets. Ordinary valid-edit checks at those existing boundaries remain
the relevant regression tests for removal of the unused helper.

Final ordinary snapshot diff failures retain the ACP session reference and the `final-workspace-snapshot` phase for both metadata-policy and path-operation rejection. A benign completed text-edit test injects a permission change at the final observation boundary and verifies `WORKSPACE_VIOLATION`, session correlation, verified cleanup and absent complete execution evidence. This is host fault injection; it does not establish agent metadata access or workflow rollback.

## Reconstruction turn-evidence process-death matrix — 2026-11-11

`ReconstructionTurnEvidenceStoreTest.hard process death during each turn evidence write leaves a restartable prefix` passed locally. It launches 12 child JVMs: intent, receipt, and assessment publication each halt with `Runtime.halt(86)` at all four store checkpoints (directory opened, before temporary link, immediately after final-name publication, and before readback). The parent reopens the same workspace and verifies either that the target document is absent and can be written, or that the exact canonical bytes are visible and a second immutable write refuses. Prerequisite intent bytes are also checked for receipt and assessment attempts. The test terminates each child without running `finally` or orderly descriptor cleanup.

This is process-death evidence for the reconstruction evidence store only. It does not prove power-loss durability, every end-to-end workflow crash boundary, repair graph recovery, or crashes around the #732 publication decision. Exact-head hosted qualification, those remaining decision/recovery cases, and production-validator evidence from #236 are still required.

At implementation commit `42d58a55aaf49b43b0ac9305e6071f5a92083fb0`,
`ReconstructionTurnEvidenceStoreTest.turn evidence directory substitution
never writes through the replacement symlink` additionally checks cleanup after
the publication directory is detached. Cleanup quarantines the final-name entry
before authenticating its file identity, preserves an entry that is not the
current write's inode, and includes a throwing post-rename hook in the cleanup
guard. These writer races are serialized for operations using the same
workspace publication capability; they do not establish protection from a
hostile same-UID process that bypasses that capability.

At the same exact commit, one local Gradle run passed four focused suites with
no failures, errors, or skips: `ReconstructionTurnEvidenceStoreTest` (6),
`ReconstructionAcpEvidenceArchiveVerifierTest` (21),
`ModuleRevisionGraphTest` (209), and `TraceGuidedRepairTest` (40), for 276
tests total. The command selected only these suites and excluded frontend
toolchain/build/install tasks. This is exact-source local evidence; hosted
qualification, production-provider acceptance, power-loss behavior, and
hostile same-UID interference remain unqualified.

At exact source commit `d9dbe56577105521b7bd082180ee605c344341a2`, the following
six focused regression tests also passed locally, with no failures, errors, or
skips: markerless historical repair input remains readable without activating
it; repair admission remains
interruptible under its enclosing deadline; the job page stays responsive
while publication withholds report evidence; output metering preserves source
directory atimes; archival reconstruction rejects mismatched workspace paths
before analysis; and CLI repair configuration preflight failure creates no
repair-in-progress marker. These tests verify the current #732 review fixes in
the #733 stack. They do not establish production-provider or hosted acceptance.

## Active repair mutation refusal checkpoint — 2026-11-11

`TraceGuidedRepairTest.active repair path rejects create and delete mutations
outside its replacement contract` passes through the repair loop's captured
staging and acceptance path. Its benign fixtures attempt an unauthorized new
source, attempt to delete the authorized target, and report canonical
`CREATED`/`DELETED` changes after replacing an existing target. Each refusal
retains the validator reason, leaves the accepted source byte-identical,
creates no extra source, and leaves no pending graph attempt. This confirms
that the active repair path applies its modification-only contract rather than
relying only on standalone policy helpers.

At implementation commit `7767e6074ce31d7b6680a18e797f481c212b7cfd`, a focused
Gradle run passed 35 tests with no failures, errors, or skips:
`WorkspaceSnapshotLimitsTest` (31), three selected `AcpAgentHarnessTest` cases,
and the new `TraceGuidedRepairTest` case. The ACP cases include public Make and
Ninja reconstruction through role enforcement and verified rebuild, captured
repair writes through ACP, and oversized captured-write refusal with bounded
retry. The snapshot suite covers create/modify/delete observations, move
source/destination authorization, text/binary content policy, filesystem entry
rejection, and per-snapshot entry/file/byte limits. The repair test proves the
active repair path refuses create/delete operations and claims. This remains
local fixture evidence: it does not qualify a live provider, every public
resource-exhaustion outcome, production validation, or the complete #734
mutation matrix. #734 remains open and dependent on #729–#733.

## Public ACP reconstruction mutation-grant and limit checkpoint — 2026-11-11

Commit `7d363753b` adds
`AcpAgentHarnessTest.public ACP reconstruction enforces mutation grants and
preserves publication on limit outcomes`, a real scripted ACP-process exercise
through `ArchivalReconstructionService.reconstructWithWorkspace` and the
production filesystem broker. The Make-profile fixture lowers the declared
implementation file ceiling to 256 KiB, verifies an out-of-role sibling
creation and an oversized implementation write are denied, then verifies the
bounded target creation succeeds, is packaged, and builds. The recorded
receipt contains the exact target path, `CREATED` kind and observed byte size;
the broker audit contains all nine expected read/write decisions.

The same public workflow then receives `LIMIT_EXHAUSTED` after a candidate
write, and a separate attempt exceeds the protocol frame limit after a write.
Both refuse publication; the second retains a typed `RESOURCE_EXHAUSTED`
receipt and confirms process cleanup. After each failure, descriptor-bound
source, archive, report and session-member commitments match the previously
published output, with no publication marker, staging or previous tree left
behind. The existing focused repair mutation test, public Make/Ninja role
rebuild test and bytecode guard also passed in the same local run: four tests
total, zero failures/errors/skips. The run used
`DECOMP_REQUIRE_LIVE_ACP_CONTRACT=1` and the repository's pinned Node/npm
toolchain.

This is local scripted-provider evidence for one reconstruction profile. It
does not qualify a live provider, production validation under #236, every
resource-exhaustion mode, or hosted exact-head CI. Reconstruction exposes no
ACP delete operation and this request has no terminal mutation policy, so
delete/move enforcement is not reachable in this path; repair delete refusal
is covered separately. Aggregate stdout/stderr, wall-clock, idle and snapshot
inventory limit outcomes remain separate #734 gaps. Keep #734 and #63 open.

## Repair turn-evidence process-death matrix — 2026-11-11

`ModuleRevisionGraphTest.process death at every turn evidence write and graph bind recovers authenticated prefixes` passed locally with the existing schema-7 recovery authentication test. It launches 26 child JVMs and uses `Runtime.halt(86)` to exercise intent, receipt, and assessment publication at the temporary-file sync, final-name exchange, final-directory sync, and the three following graph-binding write points. Each synthetic candidate changes two source files. For each prefix, the parent checks exact document bytes and temporary/final-name state before reopening, then checks recovered binding hashes and paths, source bytes and metadata, and temporary/staging cleanup. A predecision-stage crash confirms the undecided candidate is rejected and its stage discarded without source changes. Decision recovery is interrupted after the first source exchange, then interrupted again in a second process after the second exchange; a third open completes roll-forward and accepts the exact two-file candidate. Additional process deaths cover the already-committed graph head and recovery's accepted-graph persistence boundary. A tampered assessment after the durable decision is refused before source exchange, with graph and staging recovery state retained.

These are process-death tests on the local filesystem, not power-loss tests. They cover the schema-7 repair graph and its evidence sidecars, not the end-to-end repair workflow with a live provider, every rollback/cleanup failure, the independent #732 reconstruction publication journal, or production validation under #236. The decision cases include one two-file partial roll-forward and one repeated recovery interruption; they do not establish every possible interruption point or filesystem/architecture combination. The prior local repair result at `6cd76bd30d1bec7fad81fcad6617f51248333af3` predates this matrix and is not exact-head hosted evidence.
