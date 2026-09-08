# #676 module acceptance and archive evidence record

This record captures the repository-backed evidence available at commit
`bf250156` for one accepted generated-C module revision. It documents the
contract exercised by `SourceTreeGenerator` and `ArchivalProjectAuditor`; it is
not a production qualification result.

The revision join is exact: module identity is joined to the normalized source
SHA-256, input-binary SHA-256, model schema, profile SHA-256, input fingerprint,
and checkpoint SHA-256. A current accepted checkpoint is schema 6, has no
issues, owns exactly the planned function/global IDs, and contains successful
compiler evidence whose source hash and profile-selected command match the
current module source. `reports/confidence.json` repeats these bindings under
each module's `revisionEvidence`.

Behavior is kept separate from structural and compile evidence. The current
module record reports `behavior.status: "unknown"`, null coverage and output
agreement, and `unobservedBehavior: "unknown"` when no revision-bound module
measurement exists. The confidence report labels its score a structural
recovery heuristic, not measured behavioral confidence. The archive audit
reports project behavior separately, leaves module execution coverage as
`not-observed`, and preserves unresolved behavior findings.

Archive validation recomputes manifest and source hashes, checks module roles and
ownership, and verifies the accepted checkpoint, compiler record, source hash,
and profile command. Missing, stale, foreign, malformed, or cross-paired
compiler evidence is placed in `moduleCompilationEvidenceProblems`; the module
is omitted from `moduleCompilationEvidence` and its entities remain unresolved.
The focused contracts are covered by `SourceTreeTest` and
`ArchivalAuditProvenanceTest`.

Production gap: these facts are local filesystem and host-compiler observations.
They do not authenticate the compiler executable, runtime or headers, prove a
contained production build, provide revision-bound module behavior coverage, or
calibrate recovery confidence. Independent ACP-agent qualification and the
production compiler/runtime/input closure remain open under #64 and #67; the
measured accuracy and equivalence contract remains open under #42. No Ghidra,
oracle, or unresolved-state boundary is widened by this record.
