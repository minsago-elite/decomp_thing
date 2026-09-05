# Raw-derived Kotlin call-truth composition

`FullTreeCallTruthSqlite` composes the Kotlin raw function and call observation paths into
deterministic, bounded call-truth shards and an index. It is an internal migration boundary,
not an authoritative release entrypoint or an ACP capability.

## Inputs and policy

Both `generateAndPublish` and `loadAndValidate` require the rich and stripped ELF artifacts,
authenticated scope and inventory, ELF function index, complete function-observation run and
its expected index artifact digest, function-truth candidate, and complete policy-v3
call-observation run and its expected index artifact digest. Function truth is independently
reconciled from raw artifacts before its private projection is consumed. Candidate function
truth supplies comparison bytes, not expected facts. Every call-observation shard is likewise
rederived from the authenticated rich ELF/DWARF before composition.

The composer uses a distinct policy-v3 configuration and records its raw call-observation
configuration and input digests in `oracle`. The existing call-truth shard and index schema-v1
shapes remain unchanged. The historical policy-v2 assessment and its configuration are not
silently upgraded, and historical Python usage/execution files are not manufactured or accepted
as Kotlin runtime evidence.

## Graph semantics

Caller identity and caller-local return offset remain separate from absolute return RVA.
Internal caller and target identities resolve through the raw-reconciled function namespace,
including cross-shard ownership. Aliases and undefined ELF external names have separate indexed
namespaces. Physical thunk targets remain visible even when the semantic target is unresolved;
this does not claim normalized thunk recovery. Independently proven singleton targets remain
distinct from unresolved indirect and virtual observations.

Compatible duplicate observations collapse deterministically, while contradictory observations,
dangling identities, incomplete shard populations and bounded target-set overflows fail closed.
Addressless and unproven virtual observations retain their explicit unobservable reasons rather
than acquiring invented targets. An undefined dynamic-symbol name is not by itself evidence of
a particular relocation-bound PLT call or a recovered virtual slot.

## Bounds and publication

SQLite indexes hold the complete namespaces, observation groups and merged edges. Input and
output streams materialize only bounded entities or bounded duplicate groups, not a whole
function/call tree. Database pages, page cache, entity bytes/nodes, group rows/bytes, alias fanout,
output bytes and scratch reservations have independent ceilings beneath the authenticated scope.
The parent operation deadline spans nested raw validation and composition; nested call validation
cannot restart that deadline. Worker counts are declared upper bounds, not proof of parallel work.

Publication uses a private staging tree, immutable single-link leaves and an atomic no-replace
directory rename. Existing destinations are preserved. Independent validation derives a fresh
tree from raw inputs and compares exact membership and bytes; it never repairs the candidate.
Ordinary failure cleans up owned private staging and scratch without overwriting supplied inputs.

`complete: true` in the index means the authenticated inventory's shard population is represented.
It does not mean release completeness. Receipts explicitly fix `candidateLeaseRetained`,
`downstreamScoringAuthorized` and `authoritativeReleaseEvidence` to false. Their raw-rederivation
and candidate-comparison fields describe only the completed boundary, not authority to consume
mutable paths later.

Filesystem owners remain cooperating same-UID principals. Read-only modes and terminal identity
checks do not revoke previously opened write descriptors or exclude swap-and-restore attacks.
Cooperative runtime checks and scratch accounting are not a contained process-tree runtime or
an ext4 quota lease. Production all-shard containment/recovery evidence, source/build provenance,
relocation and normalized thunk/virtual evidence, recovered-model scoring and release composition
remain separate requirements under issues #128, #136 and #138. ACP may consume resulting evidence
read-only; it does not supply oracle facts, validation decisions, scores or release authority.
