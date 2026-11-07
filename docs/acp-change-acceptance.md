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
