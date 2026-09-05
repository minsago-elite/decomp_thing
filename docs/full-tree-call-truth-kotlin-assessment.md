# Bounded Kotlin call-semantics assessment

`FullTreeCallTruthAssessmentVerifier` is a raw-path-only Kotlin migration checkpoint for the
historical full-tree call composer. It is deliberately a fixture-scale diagnostic, not full-tree
call truth, oracle evidence, a completeness assertion, a score, or release authority.

The verifier authenticates canonical scope, source-lock, manifest, inventory, historical function
truth, ELF function index, and the complete bounded call-observation tree. For the embedded Python
observation-run format it requires exact root, `control/`, and `usage/` membership; reconciles every
usage record and the execution-evidence self-hash against the bounded-shard run; and repeats terminal
membership and byte checks. It then derives cross-shard caller/target ownership and retains separate
classifications for direct internal calls, exact undefined-ELF external/PLT names, proven indirect
sets, unresolved indirect calls, and unresolved virtual calls. Duplicate observations, dangling
caller/direct/proven identities, unsigned address overflow, contradictory target matrices, missing
shards, and count/digest substitutions fail closed.

Only per-shard diagnostics are serialized. Each shard is mechanically validated against the
existing `full-tree-call-truth` schema and additional closed semantic invariants before its bytes are
exposed. There is no output path, publication method, `complete: true`, or release-eligible result.
The domain-separated assessment digest binds the five raw input identities and the validated shard
digests. `historicalCallTruthConfigurationSha256` identifies the historical per-shard truth format;
it is not a schema/configuration identity for an assessment wrapper.

The raw call-observation migration now has a Kotlin/JVM producer over authenticated ELF/DWARF. Its
policy-v3 identity classifies only subprogram origins as direct/virtual candidates; formal-parameter,
member, and variable origins remain indirect, and incompatible abstract/specification chains fail
closed. The historical assessment continues to authenticate the frozen policy-v2 configuration and
input hashes, so corrected v3 semantics never reuse a legacy producer identity. The new producer's
structural envelope validator does not rederive facts and cannot confer authority by itself.

`FullTreeCallObservationProducer.generateShardTo` now connects that same raw scan to a private
SQLite sink. The sink holds one bounded canonical call at a time, indexes stable call IDs and
unsigned DIE offsets, rejects duplicate DIEs even when their call IDs differ, and projects calls in
indexed canonical order. Page count, page cache, record bytes, entity count, scanned DIEs, and output
bytes have independent limits; raw generation also caps them against the authenticated scope and
accounts for the sink in its resident-memory model. SQLite journaling and memory mapping are disabled,
and projection rejects temporary sorting. Every ordinary success or failure closes the connection
and removes its private scratch, with identity, permission, membership, and link-count rechecks.
The raw path also checks thread interruption and the authenticated wall deadline throughout scanning
and projection, preserves interrupt status, and caps byte ceilings before arithmetic expansion.
These cooperative checks do not replace the separately required contained-process runtime.

This path preserves the policy-v3 configuration and exact diagnostic bytes. Tests exercise raw
ELF parity across commit intervals, reversed arrival order, empty shards, duplicate and contradictory
records, poisoned terminal states, cancellation, failing output, and each resource bound. A synthetic
4,500-call projection exceeds the old 64 MiB envelope ceiling while using a 64 KiB SQLite page cache;
its streamed digest is independently checked without materializing the output in memory.

The stream result explicitly fixes `authoritativeReleaseEvidence=false`. Output is caller-owned
staging, may be partial on failure, and is not atomically published by this API. Scratch owners remain
cooperating same-UID principals; checkpoint checks do not exclude transient same-inode mutations.
This is a storage migration slice, not a contained all-shard run or a call-truth publication receipt.

`FullTreeCallObservationShardPublisher` supplies the companion raw-path publication and validation
boundary. Publication streams to a private descriptor-retained stage, independently repeats the raw
ELF/DWARF derivation and compares every byte, checks the generated digest, changes the output to mode
0400, and uses descriptor-relative `RENAME_NOREPLACE` plus file/directory synchronization. Input
guards remain open through both derivations and the final publication checks. One scope-bound
cooperative deadline covers both scans and publication, so rederivation cannot reset the operation's
wall budget. Ordinary failure revokes only the still-matching stage or uncommitted output; existing
destination files are retained.
Validation independently regenerates candidate bytes, rejects writable, linked, truncated, extended,
or schema-valid forged candidates, and never repairs the supplied file. Tests cover all fixture
shards, stable checkpoint variations, provenance drift, output collisions, and cleanup after limits.

The primitive publication/validation receipt fixes both `authoritativeReleaseEvidence` and
`candidateLeaseRetained` to false. It is point-in-time migration evidence, not a capability. As with
the existing function publisher, the output-parent owner must cooperate: the mode change does not
revoke a previously opened same-UID write descriptor, and metadata checks do not exclude transient
name replacement between a cleanup check and unlink. A contained whole-operation lease, hostile
interruption/restart proof, and all-shard release orchestration remain separate requirements.

`FullTreeCallObservationRunPublisher` composes the raw publisher with the generic bounded-shard
format. It derives the exact shard population and input hashes from the authenticated inventory,
generates every shard from ELF/DWARF, and independently rederives the generic publisher's private
staged copies. Its `loadAndValidate` entrypoint authenticates the complete indexed tree and repeats
raw derivation of every shard; a self-consistent run with omitted, added, or forged observations is
not sufficient evidence. Inputs stay pinned through final publication checks, existing targets are
never overwritten, and the complete mode-0500 tree is published by a same-parent atomic no-replace
rename. Leaves remain single-link mode-0400 files. Ordinary failure removes private staging and
scratch under the cooperating-owner model.

The run uses sequential execution. `maximumWorkers` is a declared upper bound, not an observed
parallelism claim. Worker-bound changes may alter run/index metadata, but not raw observation leaves.
One whole-run cooperative deadline spans generation, staged rederivation, copy/hash verification,
and final publication; each shard also retains its original child deadline through revalidation,
including time waiting for other shards. Scope declarations are admitted against implementation
ceilings before generation, and a conservative scratch reservation accounts for the DWARF worker,
SQLite database, accumulated prepared outputs, publication copies, and controls. This is not an
ext4 quota or a contained process-tree resource guarantee.

Run receipts fix `authoritativeReleaseEvidence`, `candidateLeaseRetained`, and
`downstreamScoringAuthorized` to false. The generic run deliberately does not manufacture historical
Python usage/execution artifacts or enter the historical policy-v2 assessment loader. Complete
inventory coverage is not call-truth reconciliation, exact/partial scoring, or release completeness.

The historical assessment cannot operate on the known full-tree scale: the prior call-truth tree is
about 899 MiB, function truth about 2.5 GiB, and call observations about 1.1 GiB, while this bounded
in-memory diagnostic intentionally caps its combined diagnostic output bytes at 64 MiB. Full authority
still requires all of the following:

- production integration of the Kotlin-owned raw function/call producers with the call composer;
- a Kotlin-owned contained whole-process-tree runtime and durable absence receipt for that scan;
- isolated integration of the SQLite call sink plus sharded Kotlin call-truth publication protocol;
- real full-tree parity and hostile interruption/restart evidence for those authorities.

The separate [raw-derived Kotlin call composer](full-tree-call-truth-kotlin.md) now provides the
bounded SQLite migration path and independent raw candidate comparison. It has a new policy-v3
configuration rather than widening this historical assessment. Its publication receipt remains
non-authoritative; the containment, complete target evidence, scoring and release requirements
above are not discharged by producing a complete shard index.

The Python producer remains migration/differential compatibility input only. Its usage and execution
records are integrity-checked, but they cannot authorize Kotlin truth or release. ACP may read the
resulting non-authoritative diagnostic for planning; ACP does not supply observations, identities,
targets, truth, scores, or publication decisions.

As elsewhere in the JVM control plane, Java NIO cannot prove an open descriptor still names the same
pathname. Regular-file and directory owners are therefore cooperating same-UID trust principals and
must not perform swap-and-restore attacks during an assessment. Terminal rechecks reduce visible
substitution windows but do not turn that same-UID caveat into operating-system containment.
