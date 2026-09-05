# Resumable Ghidra program-model export

Whole-program export is staged through durable records under
`analysis/reports/program_model.json.export/`. Full recovery forces each accepted function to disk atomically only
after its referenced global and type records are durable. Metadata-only planning amortizes that durability cost across
fixed 512-function batches under `planning-batches/`. Each batch has separately bounded function, global, type, and
failure-diagnostic fragments, followed by one forced checkpoint that binds every fragment's exact identities, byte
count, SHA-256, and recovery-status counts. The checkpoint also binds the exporter state and complete function
inventory, and global/type identities have exactly one batch owner. The final `program_model.json` is assembled in
address order by streaming function fragments and a bounded merge of globally ordered global/type identities. Every
fragment's byte count and SHA-256 is rechecked while it is copied, so a post-checkpoint substitution cannot reach the
published model. The Ghidra script never retains all decompiled C bodies in memory.

Planning-state schema 2 also binds a schema-1 whole-program semantic fingerprint before any batch can be reused. The
preflight runs the exact read-only planning traversal over every function, including functions in completed, current,
and future batches. It streams strictly address-ordered function records and retains the deterministic first-owner
record for each referenced global and type, plus one record for each function failure. Later references to an already
owned identity are excluded exactly as they are from durable planning batches; contradictory records presented within
the fingerprint boundary are rejected as ambiguous. Function names and prototypes, calls, strings,
referenced-global sets, global names/types/initializers, and exported type declarations therefore all participate in
the binding. The same pass commits the exact bounded function/global/type/failure fragment bytes for every production
batch. A completed checkpoint must match its freshly recomputed batch commitment before it counts as reused; a new
batch must match before checkpoint publication and again after durable readback. Semantic drift between preflight and
the export traversal therefore cannot be published under the preflight state identity.

`analysis/reports/program_model.json.progress.json` reports the current phase, completed and total function counts,
recovered, partial, and failed counts, the number of checkpoints reused by this invocation, and the current function. A failed or
timed-out function becomes a normal model record with `status: failed`; its bounded diagnostic is retained separately
under `program_model.json.export/failures/`, so one bad function cannot abort the remaining export.

## Resume procedure and bounds

Run the same reconstruction command again with the same binary and output directory. The checkpoint identity binds the
records to the input SHA-256, exact exporter SHA-256 and version, recovery mode, Ghidra language, and compiler
specification. Accepted function records or a contiguous prefix of authenticated planning batches are reused. A crash
before a planning checkpoint can leave fragments or deterministic `.pending` files only for the first incomplete
batch; those incomplete artifacts are regenerated, while missing, extra, reordered, stale, cross-inventory, or
cross-mode checkpoints are rejected. A mismatched binary or exporter is rejected instead of mixing evidence; start a
new output directory when intentionally changing either. Legacy schema-1 state has no whole-program semantic binding
and is deliberately not migrated into reusable schema-2 state.

The reference GCC-driver budget is one 10-minute invocation and 4 GiB peak RSS. The Kotlin process adapter enforces the
10-minute wall-clock ceiling and leaves completed records resumable on timeout. A benchmark profile supplies the exact
analyzer identity and resource envelope instead of relying on a workstation default. The A10 cc1/lto1 profile binds
NSA's Ghidra 12.1.3 release archive (569,445,154 bytes; SHA-256
`93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54`) and allows 30 minutes and 16 GiB for
authenticated export plus ownership planning. The bundled direct-API worker caps its Java heap at 2 GiB independently;
the Kotlin monitor measures the JVM and its complete descendant process tree against the profile ceiling.
Each full function decompilation has a 60-second timeout, and full export is deliberately single-function staged so its
live C body memory is bounded by the largest individual function rather than the complete program. Planning batches
contain no decompiled C: fragments are bounded to 64 MiB, evidence records to 1 MiB, and fan-in to 256 batches
(131,072 functions). Assembly precomputes the exact model size and enforces the same 512 MiB limit through a counting
output stream before atomic publication. Semantic preflight canonical bytes are capped at 1 GiB, with unique retained
global/type/failure evidence capped at 512 MiB. The preflight repeats planning-visible analysis traversal but performs
no decompilation and writes no export state before the complete binding is available.

The JVM consumer reads the completed model through a stable regular-file snapshot capped at 512 MiB, then requires the
exact canonical UTF-8 fields, entity order, set order, whitespace, and bytes before planning. A merely parseable JSON
variant is not accepted as oracle input.

To test crash recovery, terminate the reconstruction container during the decompilation phase, retain the output
volume, and rerun the identical command. The `reused` progress count must be nonzero, the completed total must be
monotonic, and the final model must be byte-identical to an uninterrupted export of the same binary.

The A10 diagnostic entry point is deliberately agent-free and JVM-owned. Its planning-mode exporter recovers bounded
function identities, prototypes, call edges, strings, globals, and types without paying the separate cost of producing
full decompiled C bodies; those bodies belong to the later reconstruction phase:

```bash
llm_bin_patch gcc-engine-plan cc1 /path/to/gcc-cc1.stripped \
  --profile oracle/gcc/16.2.0/compiler-engines.json \
  --ghidra-archive /path/to/ghidra_12.1.3_PUBLIC_20260817.zip \
  --output /path/to/cc1-plan
```

The command authenticates the profile and all of its source/build/toolchain and ELF-manifest bindings, authenticates
the exact stripped binary and Ghidra archive, proves every installed Ghidra file byte and tree member against that
archive using the application's bundled release (no separately installed home), runs the directly linked worker and bundled exporter, and assigns functions, globals, and types exactly once with the deterministic
planner. It writes a self-hashed `compiler_engine_plan_assessment.json` whose schema version is 2 and whose fixed
fields are `authority=non-authoritative-caller-supplied-analyzer-v1`, `complete=false`, and
`releaseEligible=false`. The former schema-1 `complete=true` document is incompatible and cannot be treated as this
assessment or enter release. An output directory retaining the legacy
`planning/compiler_engine_plan_evidence.json` fails before analysis instead of mixing old completion evidence with
the schema-2 diagnostic. Descendant-JVM sampling is not cgroup resource evidence. ACP may later consume a
separately authenticated plan read-only, but cannot author, validate, score, or certify it.
