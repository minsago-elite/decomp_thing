# Retained LLVM comparison and annotation ledger v1

`LlvmBehaviorMismatchLedgerV1Store` persists the mismatch population produced by
the existing sealed `LlvmBehaviorCandidateAssessment`. It retains the original
canonical comparison-v1 bytes, their digest and all original comparison counts.
The comparison-v1 format and its output bytes are unchanged.

This ledger is an **integrity-only** record of historical comparison bytes and
annotations. It always reports `releaseEligible: false`, `scoringAuthority: false`
and `annotationAuthority: "untrusted-metadata-only"`. The current comparator uses
caller-supplied observations. Saving those bytes does not authenticate a live
candidate execution, source/build lineage, oracle result or fidelity decision.
An integrity reload never recreates a sealed comparison capability.

## Events and annotations

`append` requires a sealed current comparison result and, for an extension, a
previous integrity-verified ledger. It accepts no caller-supplied assessment JSON,
summary, mismatch population or comparison verdict. Every event preserves the
comparison's exact canonical bytes as canonical base64 and independently hashes
the decoded bytes. The complete reference tuple and ownership identity remain
constant throughout a lineage.

Each event has exactly one annotation for every comparison mismatch. Callers may
provide `accepted` or `unresolved` plus a nonblank UTF-8 rationale of at most
4,096 bytes. These are annotations, not policy approvals. Omitted annotations are
explicitly `unresolved`, with origin `generated-unresolved` and rationale
`No adjudication was supplied; this mismatch remains unresolved.` Caller entries
have origin `caller-annotation`. Duplicate or unknown mismatch IDs, unsupported
dispositions and invalid rationales are rejected.

Event identity hashes a domain-separated canonical object containing the original
assessment digest and the complete sorted annotation list, including origin and
rationale. An exact event already present anywhere in history is idempotent.
Changing annotations adds an immutable event and retains every earlier decision.
This is annotation history; identical comparison bytes do not count as a fresh
independent execution or repetition. A later comparison with no mismatches retains
all earlier failures. Failure codes stay in each original comparison occurrence:
one stable execution-mismatch ID may span not-run and infrastructure failure
reasons across candidate revisions.

Each snapshot retains the full preceding event prefix and binds its previous
snapshot SHA-256. Verification reconstructs each prefix digest, mismatch ID and
count relationship, annotation population, event ordering and cumulative summary.
The summary counts annotation events, distinct retained assessments and candidate
executables, mismatch occurrences and annotation dispositions. It never replaces
or alters the behavior counts inside the original comparison bytes.

## Publication and reload

Create an otherwise empty owner-only directory before calling `publish`. The
store creates no directory and starts no process. It pins the directory, takes
its nonblocking exclusive flock and holds it through predecessor validation,
append and publication. Snapshot names are fixed: `ledger-0001.json`,
`ledger-0002.json`, and so on. The store rejects holes, alien names, conflicting
temporaries, stale predecessor snapshots and competing descendants. Its existing
descriptor-bound manifest publication primitive uses no-replace atomic rename,
owner-read-only files and file/directory synchronization. Retry accepts only the
exact requested temporary or published bytes. Unrecognized residue is retained
and rejected. The directory owner must exclude unrelated same-UID name mutation.

`verify(path, expectedLedgerSha256)` requires an externally retained digest of the
snapshot. The filename and embedded digests cannot supply this pin. Strict bounded
canonical parsing and schema/semantic validation establish integrity of the
retained snapshot; raw reference/candidate execution is not replayed. Consumers
must preserve this distinction when combining ledger data with future qualified
execution and source provenance.

## Bounds and scope

The comparison-v1 contract allows 16 MiB of canonical assessment bytes and 50,400
mismatch slots. Ledger minimum budgets admit that entire population with generated
unresolved annotations, including base64 expansion: 40 MiB output, 16 MiB retained
assessment bytes, 50,400 occurrences and 4 MiB of rationale. The default output
ceiling is the existing 64 MiB manifest ceiling. Defaults also bound history to
64 events, 32 MiB cumulative decoded assessment bytes and 16 MiB cumulative
rationale bytes. Node, depth, string, occurrence and canonical output limits apply
independently. Actual growth that exceeds a limit fails the whole operation before
publication; history and findings are never truncated to fit. Larger caller
rationales consume the declared cumulative budgets.

This implements persistence groundwork for #838. Fresh native-v2 captured
reference observations under #139, authenticated candidate/build lineage under
#140/#115, authoritative Kotlin execution under #136 and the combined release
manifest under #112 remain separate open requirements. Neither authored fixtures
nor annotations qualify production behavior or close A15.
