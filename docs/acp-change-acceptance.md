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

Commit `d48118758` extends
`TraceGuidedRepairTest.ordinary ACP terminal outcomes persist immutable
receipts before rejected repair history` with a failed
`RESOURCE_EXHAUSTED` receipt. The active repair loop persists the receipt and
assessment, terminalizes the candidate as rejected, retains the typed
`resource-exhausted` outcome in the receipt and history, and does not mark it
release-complete. The focused test passed locally at this commit: one test
method, zero failures, errors or skips. This is an active-workflow integration
control using a scripted failure receipt; it does not itself cause an ACP
process to exceed an output budget. The separate live ACP reconstruction and
captured-repair controls exercise actual process/filesystem limits. Production
provider and complete #734 qualification remain outstanding.

Commit `e287eb0e2` adds
`TraceGuidedRepairTest.active ACP repair retains resource-limited write refusal
without changing accepted source`. This drives a real scripted ACP process
through the active generated-C repair loop. Its oversized write reaches the
filesystem broker and is refused with `RESOURCE_LIMIT`; the agent then ends
with `NO_CHANGES`. The repair graph retains the invocation-bound receipt and
rejection assessment, including the denied-write audit and verified process
and sandbox cleanup. The test reopens the graph, verifies the terminal outcome
is not release-complete, and confirms the accepted source bytes are unchanged.
The focused live-sandbox Gradle test passed locally at this commit: one test
method, zero failures, errors or skips. This exercises the active repair
workflow's file-write limit, not ACP stream-output exhaustion, a live provider,
production validation under #236, or hosted exact-head qualification.

Commit `0a20206ec` adds
`TraceGuidedRepairTest.active ACP repair retains real stream output exhaustion
and rejects the candidate`. The scripted ACP child sends valid, bounded
message frames until it exceeds the active request's 64 KiB aggregate output
limit. The active repair loop retains a rejected, non-release-complete
`RESOURCE_EXHAUSTED` receipt; its process evidence records the exceeded limit,
zero surviving processes, and verified sandbox cleanup. The test reopens the
repair graph and confirms the accepted source bytes are unchanged. Both active
repair resource-limit tests passed together locally: two test methods, zero
failures, errors or skips. This is scripted local ACP evidence, not production
provider qualification, #236 validation, or hosted exact-head evidence.

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
is covered separately. Wall-clock, idle and snapshot inventory limit outcomes
remain separate #734 gaps. Keep #734 and #63 open.

Commit `6ec4967d4` extends that same public-workflow test with aggregate output
limits after a valid candidate write. One fixture emits 9 MiB on stderr; a
separate fixture emits 300 bounded 30,000-character protocol updates on stdout,
exceeding the default 8 MiB combined execution-output allowance without
exceeding the per-frame limit. Both return typed `RESOURCE_EXHAUSTED` receipts
with incomplete execution evidence, confirm sandbox/process cleanup, refuse
publication, and preserve the prior descriptor-bound output commitments. The
focused test passed locally at this commit: one test method, zero failures,
errors or skips. This covers aggregate stream output only; wall-clock, idle,
snapshot inventory and other limits remain unqualified.

Commit `314566269` adds a cross-stream control: 5 MiB of stderr followed by
4.2 MB of stdout text. Each stream stays below 8 MiB independently, but their
combined output exceeds the shared allowance and must still fail with
`RESOURCE_EXHAUSTED`. The same focused test passed at this commit with the
cross-stream scenario included. This does not qualify wall-clock, idle or
snapshot inventory limits.

Commit `3f7932107` adds a separate configured ACP request-timeout case. The
fake agent completes the authorized source write, then withholds the terminal
prompt response until a 3-second `session/prompt` deadline expires. The test
checks the completed write audit, typed `TIMEOUT` receipt, incomplete terminal
evidence, process and sandbox cleanup, publication refusal, and unchanged
previous output. The focused public reconstruction test passed at this
commit. This is request-phase timeout evidence; it does not exercise the
reconstruction request's 20-minute wall or 2-minute idle budgets. Those and
snapshot inventory limits remain unqualified.

Commit `609175b54` extends the same public reconstruction test with separate
wall-clock and idle deadline controls. Its first test-only harness decorator
changed request limits after reconstruction created the turn identity. Exact
review identified that receipt-correlation defect; that earlier test pass did
not qualify the reconstruction workflow result. Commit `5f37ab05e` moves the
test-only limits seam into `BoundedLlmModuleReconstructor`, before it creates
the bound request and turn identity, and includes overridden limits in its
test cache identity. The test requires the workflow progress callback to
deliver the receipt and compares its request digest with both the request
captured at task start and the receipt turn identity.

The corrected test passes through the real ACP harness. The wall case uses a
12-second wall budget with a 20-second idle budget; the idle case uses a
20-second wall budget with a 12-second idle budget. In both cases the scripted
agent completes the authorized candidate write and then withholds its terminal
prompt response. Assertions require a typed `TIMEOUT`, incomplete execution
evidence, the completed write audit, verified process and sandbox cleanup,
refusal of the candidate, and unchanged prior publication metadata. The
focused live-sandbox test passed locally after the correction: one test method,
zero failures, errors or skips (38.3 seconds). These injected limits exercise
the active reconstruction path; they do not wait for or measure the production
20-minute wall or 2-minute idle defaults. Snapshot inventory limits and other
resource limits remain unqualified.

Commit `c7839780e` adds a reachable initial-snapshot inventory refusal to the
same public ACP reconstruction test. With the snapshot entry budget set to 2,
the real request reaches `RESOURCE_EXHAUSTED` with
`phase=initial-workspace-snapshot` and `limit=entry-count`. The receipt reports
`WORKSPACE_SNAPSHOT` and `NOT_REQUIRED` cleanup, with no process diagnostics,
sandbox evidence, filesystem audit, or complete execution evidence. The test
also verifies the target implementation file is absent when the request is
dispatched, the accepted output metadata remains identical, and no publication
residue is left behind.

Commit `a39dfd350` extends this control to the final snapshot. The same
public-path request now runs an authorized scripted write, then separately
exceeds the final snapshot's `file-bytes` and `total-bytes` budgets. Both
receipts report `RESOURCE_EXHAUSTED` at
`phase=final-workspace-snapshot`; their provider evidence reaches
`FINAL_WORKSPACE_SNAPSHOT`, confirms process and sandbox cleanup, and omits
complete execution evidence. The final snapshot cases also require an allowed
target-write audit, unchanged prior output metadata, and no publication
residue. The focused live-sandbox test passed locally at `a39dfd350`: one test
method, zero failures, errors or skips.

Together these cases exercise initial entry-count and final file-byte/total-byte
limits through the public reconstruction workflow. The single declared file
means the snapshot file-count ceiling is not reachable in this path, and the
target is absent before dispatch so initial file-byte/total-byte ceilings are
not reachable there. This does not qualify every snapshot limit, every
resource ceiling, production validation under #236, live-provider behavior, or
hosted exact-head CI. #734 and #63 remain open.

## Reconstruction change-claim consistency checkpoint — 2026-11-11

Commit `6a195ace9` adds
`SourceTreeTest.reconstruction rejects agent change claims that disagree with
observed target bytes`. Its seven fake-harness cases report a wrong path,
multiple paths, a false deletion, the wrong change kind, a wrong before hash,
a wrong after hash, or a wrong size after writing candidate bytes. Each
dispatches through `BoundedLlmModuleReconstructor` and `SourceTreeGenerator`;
the resulting module remains unresolved, its checkpoint is unaccepted, and
the untrusted candidate bytes are absent from the generated source.

The focused offline Gradle test passed: one test method, seven claim variants,
zero failures, errors or skips. This exercises the reconstruction validator's
claim checks with a scripted in-process harness; it is not a real ACP-process
or public workflow test. The preceding public ACP checkpoint covers the real
filesystem broker and publication refusal path. Neither checkpoint covers all
resource ceilings or proves production validation, live-provider behavior, or
hosted exact-head CI. #734 and #63 remain open.

## Active repair change-claim validation checkpoint — 2026-11-11

`TraceGuidedRepairTest.active repair path rejects change claims that disagree
with captured bytes` passed locally with 11 malformed-claim variants. It drives
the active `TraceGuidedRepairLoop` through `CapturedRepairStagingAuthority` and
checks duplicate relative paths, non-canonical ordering, foreign and read-only
paths, omitted and phantom claims, a write reverted to its original bytes,
incorrect before/after digests, and incorrect or missing size. Every refusal
leaves the accepted source bytes and graph head unchanged. Before reopening the
graph, the test reads its persisted state and requires no pending attempt, a
`candidate-error` rejected node, and `recoveredAfterCrash=false`; the existing
`repair loop can patch compile errors` case is the valid-change control.

These are fake captured-adapter results at the active loop boundary. Production
ACP adapters derive change claims from host-observed snapshots, so a peer cannot
directly forge these fields; the test protects the loop's adapter contract and
defense in depth. It does not qualify the live ACP process, production
validation under #236, all resource limits, or hosted exact-head behavior.
#734 and #63 remain open.

## Active captured-repair staging-byte budget checkpoint — 2026-11-11

`TraceGuidedRepairTest.active repair path records staging directory admission
refusal as resource exhaustion` stages a source under three nested directories
with a three-directory limit. The staging authority counts the virtual root
and all nested directories before invoking the adapter; the limit is refused
as `RESOURCE_EXHAUSTED`, the adapter is not dispatched, the accepted source
and head remain unchanged, and the run reopens with a rejected attempt and no
pending state. File-count and directory-count admission now use the same typed
budget failure.

`TraceGuidedRepairTest.active repair path rejects candidate growth beyond the
staging byte budget` starts with an indexed source tree below a 4,096-byte
staging limit, then has the captured adapter propose an 8 KiB replacement.
The bounded sink refuses the candidate before it can become staged output. The
active loop records a rejected node with `RESOURCE_EXHAUSTED`, ends the run as
resource-exhausted, leaves the accepted source and head unchanged, and reopens
the graph with no pending attempt. This exposed and corrected a classification
gap: captured staging budget exceptions had been recorded as
`INVALID_REQUEST`.

`TraceGuidedRepairTest.active repair path classifies per-file output limit as
resource exhaustion` exercises a 4,097-byte replacement against a 4,096-byte
per-file ceiling while the original source fits. The size check now runs before
the shared mutation-policy size refusal and before copying the oversized
candidate, so this case remains a typed resource exhaustion rather than an
invalid request. The active loop leaves source bytes and accepted head intact,
and persists a rejected node and resource-exhausted run.

`TraceGuidedRepairTest.active repair path rejects a candidate over the patch
file count` uses a two-file declarative profile and a one-file patch budget.
The captured adapter replaces the first file, then the bounded sink refuses
the second. The active loop persists a rejected resource-exhausted node and
run state, leaves both accepted files and the head unchanged, and reopens with
no pending attempt. Its validator fails if candidate rejection reaches
compilation or behavior checks.

`TraceGuidedRepairTest.active repair path enforces aggregate patch bytes and
permits the exact boundary` is covered by commit
`cbea368d55c4b09214c974495140b926e4072480`. Two individually admissible
2,048-byte replacements exceed the aggregate 4,096-byte patch ceiling by one
byte; the second replacement is refused before validation. A 2,048+2,048-byte
control reaches validation, where a sentinel exception verifies that capture
accepted the exact boundary; rollback then retains the original source and
head. The focused local run at that commit passed this test with the directory-
admission, per-file, staging-byte and patch-file active-limit cases: five
methods, zero failures, errors or skips. The direct file/directory-count
admission control passed in an earlier focused run.

An earlier selected run passed the active repair mutation and claim-validation,
ACP write-denial, and ACP stream-output exhaustion controls: five methods,
zero failures, errors or skips. The per-file, staging-growth, and patch-file
cases use the test-only captured adapter and do not produce a release-complete
provider receipt. They qualify active repair-loop enforcement and refusal
classification, not production ACP provider behavior, #236 validation, every
resource limit, or hosted exact-head CI. The aggregate-byte case also uses a
test-only captured adapter. #734 and #63 remain open.

`TraceGuidedRepairTest.active repair production policy rejects malformed UTF-8
before candidate installation` passed locally at commit
`af2b18515a34605645945662a6d268f8360f65f7`. It opens the active repair loop
with test-only validation disabled and verifies the generated-C declared-role
policy, attempt owner, profile digest, editable declaration, UTF-8 grant, and
write-only operation at the dispatched request. The sink accepts a bounded
multibyte UTF-8 replacement and refuses malformed bytes with the declared
authority error; accepted source and graph head remain unchanged, and the
rejected attempt has no pending state. The scripted captured harness provides
no schema-v2 ACP provider evidence, so outer workflow rejection follows the
missing-provider-evidence guard. This qualifies policy selection and sink
enforcement through active repair dispatch only; it does not qualify receipt-
backed ACP refusal, real provider behavior, candidate validation, or #236.
The accumulated six-case local run at
`af2b18515a34605645945662a6d268f8360f65f7` passed the aggregate-boundary,
UTF-8 policy, staging-growth, per-file, patch-count, and directory-admission
controls with zero failures, errors, or skips.

`TraceGuidedRepairTest.active ACP repair persists declared-role denials and a
no-change receipt` passed locally at
`875bd07530f34e3bc40fd47ebba9ff45e3142044`. The test launches the scripted ACP
process through the active repair loop with test-only validation disabled. It
checks the dispatched generated-C declared-role grant against the attempt,
profile, declared target, write-only UTF-8 role, and effective size ceiling.
The peer's sibling-file creation and `Makefile` replacement are denied by the
live filesystem broker; two allowed target writes then restore the original
bytes, yielding `NO_CHANGES`. The loop retains the schema-v3 receipt and a
correlated rejected assessment, including the four audited policy outcomes,
while preserving the source bytes, graph head, and empty sibling path. The
receipt is deliberately not release-complete for this `NO_CHANGES` outcome.
This proves receipt-backed scripted ACP policy refusal and no-change handling;
it does not exercise candidate validation, a production provider, #236
validation, or hosted exact-head qualification.

The accumulated focused active-repair run at `875bd07530f34e3bc40fd47ebba9ff45e3142044`
passed seven methods with zero failures, errors, or skips: directory admission,
per-file output, staging growth, patch-file count, aggregate patch bytes,
malformed UTF-8 declared-role enforcement, and the new receipt-backed ACP
no-change case. These selected cases do not exhaust the resource-limit matrix
or prove that a validated candidate reaches the production validator. #734 and
#63 remain open.

`TraceGuidedRepairTest.active ACP repair passes a receipt-backed candidate to
the validation strategy` adds the complementary active-path handoff control at
`d64d1bc479007b32a2bf4b35012e554e8f0c16a9`. A real scripted ACP process makes
one allowed declared-role source edit and returns a completed, release-complete
execution receipt. The active repair loop passes the full immutable candidate
snapshot and matching source digest to the injected validation strategy. The
test correlates the validation invocation's candidate and run identities with
the durable rejected node, and correlates the receipt change digest with the
rejection assessment. A sentinel validation exception then verifies rejection
is persisted before return, with no pending attempt, no recovery-derived
terminal state, no suppressed cleanup error, and unchanged accepted source and
head. Eight selected active-repair methods passed locally at this commit with
zero failures, errors, or skips.

The validator here is an injected test strategy with strict-assurance labeling;
it is not the registered production validator, and the test deliberately does
not claim compilation, behavior validation, or successful publication. This
proves active-path candidate handoff and failure rollback around the validator
seam only. Production validation under #236, live-provider behavior, complete
resource coverage, and hosted exact-head CI remain unqualified. #734 and #63
remain open.

## Active repair wall and idle timeout checkpoint — 2026-11-11

Commit `4383b5f3d` adds
`TraceGuidedRepairTest.active ACP repair deadlines retain timeout receipts
after an acknowledged write`. It drives the active repair loop through the
real scripted ACP process in two separate cases: a 12-second wall deadline
with a longer idle allowance, and a 12-second idle deadline with a longer
wall allowance. In both cases the process completes and receives acknowledgement
for the authorized target write, then withholds its terminal prompt response.

The test verifies that the distinct deadline produces a typed `TIMEOUT`, the
request and host turn identity remain correlated, and the graph retains the
receipt and rejected assessment with no pending attempt or recovery-derived
terminalization. The receipt records the acknowledged write, the prompt
dispatch phase, zero remaining processes and verified sandbox cleanup. The
accepted source and `Makefile` remain byte-identical, and the injected
validation strategy is never called. The focused timeout test passed locally;
the combined `TraceGuidedRepairTest.active*` selection passed 13 methods with
zero failures, errors or skips.

These are injected 12-second deadline controls using a scripted local ACP
provider. They establish active-workflow wall and idle timeout handling after
a real brokered write; they do not measure the production timeout defaults,
qualify a live provider, exercise production validation under #236, or
complete the #734 resource and mutation matrix. Hosted exact-head
qualification remains separate. #734 and #63 remain open.

## Active repair protocol frame-count checkpoint — 2026-11-11

Commit `119cb9b6a` adds
`TraceGuidedRepairTest.active ACP repair frame-count exhaustion retains
completed write receipt and rejects the candidate`. The scripted ACP process
first writes and receives acknowledgement for the authorized generated-C
target, then sends bounded JSON-RPC notifications beyond a configured
16-frame ceiling. Follow-up commit `1a777f8d3` uses the valid
`contract/unknown_notification` method shape from the harness-level frame
flood fixture. The active repair loop retains a typed
`RESOURCE_EXHAUSTED` receipt and rejected assessment, verifies zero remaining
processes and sandbox cleanup, and leaves the accepted source, `Makefile`,
head and pending-attempt state unchanged.

The focused frame-count test passed locally before and after the fixture
correction; the combined active-repair selection passed 14 methods with zero
failures, errors or skips at `119cb9b6a`. This is scripted local ACP evidence
for protocol frame-count exhaustion after an acknowledged candidate write; it
does not qualify all ACP frame shapes,
provider behavior, production validation under #236, or hosted exact-head CI.
The complete #734 mutation and resource matrix remains open.

## Active repair protocol frame-size checkpoint — 2026-11-11

Commit `b69c1a6cc` adds
`TraceGuidedRepairTest.active ACP repair frame-size exhaustion retains
completed write receipt and rejects the candidate`. The real scripted ACP
process waits for acknowledgement of an authorized target write, then sends
one JSON-RPC notification whose encoded frame exceeds the test harness's
16 KiB ceiling while remaining below the aggregate output allowance. The
active loop requires the specific frame-byte `RESOURCE_EXHAUSTED` failure,
retains the rejected receipt, confirms process and sandbox cleanup, and
verifies unchanged accepted source bytes, `Makefile`, graph head, and no
pending attempt.

The focused frame-size test passed locally, and the combined active-repair
selection passed 15 methods with zero failures, errors or skips. Together
with the frame-count control above, this covers two distinct ACP protocol
ceilings after an acknowledged brokered write. It does not qualify other
provider/protocol failures, production validation under #236, or hosted
exact-head CI. #734 and #63 remain open.

## Active repair immediate tool-call limit checkpoint — 2026-11-11

Commit `ccf63dd21` adds an active repair control for the exact host tool-call
boundary and fixes completion-order handling in `AcpAgentHarness.runPrompt`.
The harness now checks an already-recorded tool-call limit failure before
accepting a completed prompt response, and checks again after awaiting or
draining that response. This prevents an immediate `end_turn` response from
overriding a tool-call limit already observed by the event translator.

`TraceGuidedRepairTest.active ACP repair preserves tool-call exhaustion when
prompt completes immediately` runs the scripted ACP process through active
repair with a one-call limit. After an acknowledged authorized source write,
the peer waits for the host prompt loop, then sends two distinct tool-call
events and the `end_turn` response in one flushed protocol burst. The receipt
records two calls and `LIMIT_EXHAUSTED`; the workflow
rejects the candidate, retains its interrupted assessment, reopens with no
pending attempt, and preserves the accepted source and graph head. The test
also verifies process termination and sandbox cleanup.

`TraceGuidedRepairTest.active ACP repair permits exact tool-call limit through
candidate validation` sets the limit to two. The same two-call response reaches
the candidate-validation seam with a completed receipt. An injected sentinel
then refuses validation, allowing the test to verify that the exact boundary
was admitted without claiming successful compilation or publication.

Follow-up commit `0fbd34761` adds a one-shot test barrier in
`AcpAgentHarness.runPrompt`. The ordering regression test joins the completed
prompt job before the host begins terminal polling; thus the tool updates and
terminal response have both been processed before the limit decision. The
two-call/one-call-limit case now tests that exhaustion cannot be hidden by an
already completed response, while the two-call/two-call-limit case still
reaches candidate validation. This removes the earlier scheduling-dependent
50 ms timing claim.

The same commit adds `TraceGuidedRepairTest.active ACP repair cancellation
after acknowledged write preserves accepted state`. The fixture waits for the
host's successful write acknowledgement, emits a correlated ready event, and
then waits for `session/cancel`. The active repair callback requests caller
cancellation only after that event. The test checks a returned `CANCELLED`
receipt, an interrupted assessment, no validator entry, exact preservation of
accepted source and Makefile bytes and graph head, no pending attempt, and
verified process and sandbox cleanup. It is scripted cooperative cancellation;
it does not establish uncooperative-peer cleanup or production-provider
behavior.

The accumulated `TraceGuidedRepairTest.active*` selection passed 19 methods at
`0fbd347615e8049a6198523209b08a576b94b734`, with zero failures, errors, or
skips. Command:

```text
./gradlew --offline test --console=plain -x verifyFrontendToolchain -x frontendInstall -x frontendBuild --tests 'decompengine.repair.TraceGuidedRepairTest.active*'
```

All active-test fixture roots touched by this slice are under repository-local
`build/test-tmp`. This remains local scripted ACP evidence. It does not qualify
other token/provider budgets, live-provider behavior, production validation
under #236, or hosted exact-head CI. #734 and #63 remain open.

## Active repair reported token-ceiling checkpoint — 2026-11-11

Commit `baf60dd6b` adds active repair coverage for configured ACP input and
output token ceilings. The scripted peer acknowledges an authorized source
write, then returns a completed prompt with input usage 11, output usage 7,
and cached input usage 3. Independent cases configure an input ceiling of 10
or an output ceiling of 6. Both are classified as `LIMIT_EXHAUSTED`, persist
`RESOURCE_EXHAUSTED` repair runs and interrupted assessments, retain the
receipt's reported usage, and leave the accepted source and graph head intact
with no pending attempt. Process termination and sandbox cleanup are verified.

The equality control configures ceilings of 11 input and 7 output tokens. It
reaches the active candidate-validation seam with a completed receipt and the
same reported usage; an injected sentinel then rejects validation so the test
does not claim compilation or publication. The existing harness comparison is
strictly greater-than, so equality is admitted.

The focused token-ceiling case and accumulated
`TraceGuidedRepairTest.active*` selection passed locally at `baf60dd6b`: 18
methods, zero failures, errors or skips. These scripted ACP cases qualify
post-response enforcement of provider-reported token usage in the active
repair path. They do not establish independent token metering, preemptive
interruption, live-provider behavior, production validation under #236, or
hosted exact-head CI. #734 and #63 remain open.

## Active public reconstruction tool and token limits — 2026-11-11

Commit `de6709862` extends
`AcpAgentHarnessTest.public ACP reconstruction enforces mutation grants and
preserves publication on limit outcomes` through the public
`ArchivalReconstructionService` path. Following a successful accepted
publication, a scripted agent writes the owned implementation and reports
three tool-call events. With a two-call cap, reconstruction returns
`LIMIT_EXHAUSTED`, retains the invocation receipt, refuses publication, and
preserves the accepted publication metadata. A separate input-cap case rejects
reported usage 11 against a limit of 10; an output-cap case rejects usage 7
against a limit of 6. Both verify the authorized write occurred, the typed
interruption reached the public workflow, the process and sandbox were
cleaned up, and the prior publication remained unchanged.

The equality case configures three tool calls, 11 input tokens, and 7 output
tokens. It verifies all three reported values at equality, reaches a successful
build and archival bundle, extracts and verifies that bundle, then rebuilds
the extracted project. The test-only per-turn limits override leaves the
reconstructor implementation identity unchanged; each attempt uses a distinct
model fingerprint and the invocation request digest binds the effective
limits. This is local fixture evidence for post-response accounting of
provider-reported usage. It does not establish independent token metering or
preemptive enforcement.

The focused command passed one JUnit method with zero failures, errors, or
skips at `de67098628c3b55c9c9f9668cf40f48fac6ea25a`:

```text
./gradlew --offline test --console=plain -x verifyFrontendToolchain -x frontendInstall -x frontendBuild --tests 'decompengine.acp.AcpAgentHarnessTest.public ACP reconstruction enforces mutation grants and preserves publication on limit outcomes'
```

This extends only scripted Make reconstruction coverage. It does not qualify
the production repair validator under #236, live-provider behavior, every
resource limit, or hosted exact-head CI. #734 and #63 remain open.

## Public reconstruction invalid-usage refusal checkpoint — 2026-11-11

Commit `a9c8cc1b7` adds two cases to the same public reconstruction workflow
test. Each scripted ACP agent first completes the authorized implementation
write, then returns either no token usage despite configured input and output
ceilings, or a negative input-token count. The workflow must retain a failed
`PROTOCOL` receipt, refuse publication, verify process and sandbox cleanup,
preserve all previously accepted publication metadata, and leave no
transaction residue. The test also checks that the receipt belongs to the
dispatched request and does not claim complete execution evidence.

The focused command passed one JUnit method with zero failures, errors, or
skips at this commit:

```text
./gradlew --offline test --console=plain -x verifyFrontendToolchain -x frontendInstall -x frontendBuild --tests 'decompengine.acp.AcpAgentHarnessTest.public ACP reconstruction enforces mutation grants and preserves publication on limit outcomes'
```

This is scripted public-path evidence that configured ceilings reject missing
or malformed provider-reported usage after a staged write. It does not
establish independent token metering, preemptive interruption, live-provider
behavior, production validation under #236, or the complete #734 matrix.
#734 and #63 remain open.

## Repair turn-evidence process-death matrix — 2026-11-11

`ModuleRevisionGraphTest.process death at every turn evidence write and graph bind recovers authenticated prefixes` passed locally with the existing schema-7 recovery authentication test. It launches 26 child JVMs and uses `Runtime.halt(86)` to exercise intent, receipt, and assessment publication at the temporary-file sync, final-name exchange, final-directory sync, and the three following graph-binding write points. Each synthetic candidate changes two source files. For each prefix, the parent checks exact document bytes and temporary/final-name state before reopening, then checks recovered binding hashes and paths, source bytes and metadata, and temporary/staging cleanup. A predecision-stage crash confirms the undecided candidate is rejected and its stage discarded without source changes. Decision recovery is interrupted after the first source exchange, then interrupted again in a second process after the second exchange; a third open completes roll-forward and accepts the exact two-file candidate. Additional process deaths cover the already-committed graph head and recovery's accepted-graph persistence boundary. A tampered assessment after the durable decision is refused before source exchange, with graph and staging recovery state retained.

These are process-death tests on the local filesystem, not power-loss tests. They cover the schema-7 repair graph and its evidence sidecars, not the end-to-end repair workflow with a live provider, every rollback/cleanup failure, the independent #732 reconstruction publication journal, or production validation under #236. The decision cases include one two-file partial roll-forward and one repeated recovery interruption; they do not establish every possible interruption point or filesystem/architecture combination. The prior local repair result at `6cd76bd30d1bec7fad81fcad6617f51248333af3` predates this matrix and is not exact-head hosted evidence.
