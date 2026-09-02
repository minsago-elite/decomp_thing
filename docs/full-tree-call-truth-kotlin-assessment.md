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

This checkpoint cannot operate on the known historical full-tree scale: the prior call-truth tree is
about 899 MiB, function truth about 2.5 GiB, and call observations about 1.1 GiB, while this bounded
in-memory diagnostic intentionally caps its combined diagnostic output bytes at 64 MiB. Full authority
still requires all of the following:

- production integration of the Kotlin-owned raw function/call producers with the call composer;
- a Kotlin-owned contained whole-process-tree runtime and durable absence receipt for that scan;
- a scalable SQLite-backed call-observation sink plus sharded Kotlin call-truth publication protocol;
- real full-tree parity and hostile interruption/restart evidence for those authorities.

The Python producer remains migration/differential compatibility input only. Its usage and execution
records are integrity-checked, but they cannot authorize Kotlin truth or release. ACP may read the
resulting non-authoritative diagnostic for planning; ACP does not supply observations, identities,
targets, truth, scores, or publication decisions.

As elsewhere in the JVM control plane, Java NIO cannot prove an open descriptor still names the same
pathname. Regular-file and directory owners are therefore cooperating same-UID trust principals and
must not perform swap-and-restore attacks during an assessment. Terminal rechecks reduce visible
substitution windows but do not turn that same-UID caveat into operating-system containment.
