# Recovered call-site candidates v1

Issue [#128](https://github.com/minsago-elite/decomp_thing/issues/128) needs actual
candidate call locations before recovered-model scoring can compare individual
edges. The existing program-model schema-v1 `calls` set contains called-function
IDs: repeated calls collapse and instruction/return locations are absent. That
format, its canonical bytes, and its existing exporter remain unchanged.

`GhidraHeadlessProgramModelAnalyzer.analyzeWithCallSites(binary, workDir)` runs
the existing exporter followed by `ExportRecoveredCallSites.java` in the same
headless analysis. It returns the schema-v1 program model and a validated receipt
for the separate `reports/program_model_calls.json` candidate. Ordinary `analyze`
does not request this extra artifact. An occupied sidecar destination is rejected
rather than replacing or implicitly reusing a previous candidate.
The sidecar intentionally retains thunk callers even though the original model
exporter omits thunk functions. The model hash binds the paired snapshot, not an
identical caller population. A scorer must reconcile the sidecar's address-based
callers against the raw function index, not silently discard callers missing from
the older reconstruction model.

## Candidate contract

The new schema is bundled at `project/recovered-call-sites-v1.schema.json`, outside
the oracle schema catalog. Its root binds the imported executable SHA-256, exact
program-model bytes, call-site exporter bytes, configured analysis-tool digest,
and image-base address. These are candidate bindings, not independent proof of
the tool, binary, recovered semantics or execution containment. In particular,
the existing all-zero unconfigured analysis-tool identity is not upgraded into
authenticated provenance.

Each record retains the caller entry RVA, instruction RVA and bytes, physical
encoded target when present, and separately recovered flow-reference targets.
The stable caller key is `function-rva-<canonical RVA>`. Records use unsigned
caller/instruction ordering; duplicate keys are rejected rather than granting
extra credit. Repeated calls to one callee remain separate records. A site before
its caller entry has no nonnegative caller-local offset rather than wrapping.

The exporter is deliberately x86-64 little-endian only. It distinguishes direct
calls, indirect calls, direct tail-call candidates, and unresolved indirect jumps.
An indirect jump is **not** asserted to be a virtual call or a tail call. Direct
tail candidates require an unconditional prototype jump to a different known
function outside the caller body. Conditional and internal direct branches are
not exported as calls. Missing disassembly or function recovery still means
missing candidate coverage, not proof that no call exists.

Instruction classification uses the underlying
[Ghidra instruction prototype](https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/InstructionPrototype.html),
not analysis flow overrides that may label a tail jump as a call-return. Encoded
targets use default instruction flows; inferred targets remain separate Ghidra
flow-reference claims. Neither recovered names nor inferred references establish
an oracle-proven target set, external identity or normalized thunk destination.

Calls carry an actual return PC at the end of their recorded 1–15 instruction
bytes. Tail calls and indirect jumps have no return PC. This distinction must
survive scoring: historical call truth currently folds `DW_AT_call_pc` into a
return-PC-shaped field when `DW_AT_call_return_pc` is absent. A future scorer
must recover that source-coordinate distinction; blindly matching either
instruction or return address can grant incorrect or duplicate credit.

## Streaming, bounds and publication

`RecoveredCallSites.read` requires expected artifact and binding digests. It uses
the existing strict canonical streaming parser, retaining at most one 4 KiB
record rather than materializing the complete edge list. It rejects duplicate
JSON fields, noncanonical bytes, unknown fields/versions, unordered or oversized
target sets, contradictory physical/return fields, and address overflow. Defaults
allow at most 4 GiB, ten million sites, 16 targets per site, and five minutes of
reading; callers can lower those limits. Interruption remains set. The Ghidra
export also caps instruction scanning at 100 million visits and observes its
parent analysis cancellation and resource monitor.

Callbacks are **speculative until the read returns successfully**: final canonical
hash and envelope binding checks occur after streaming. A scorer must ingest into
discardable private scratch and publish nothing on a failed read. Returned data
or receipts are not capabilities. They explicitly claim neither oracle authority
nor recovered-model scoring. The parser retains the existing cooperative same-UID
filesystem assumption; metadata checks are not a hostile-writer exclusion lease.

The exporter streams to a same-directory temporary file, checks the model hash
again, makes the candidate read-only, and links it into an absent destination
without replacement. It removes the temporary link afterward. This is candidate
publication, not durable release evidence or aggregate disk/containment authority.
Export plus adapter validation retains the original analysis wall-clock deadline.

## Verification and remaining integration

```bash
RUN_REAL_GHIDRA_CALL_SITES=true GHIDRA_HOME=/path/to/ghidra \
  ./gradlew test --tests decompengine.project.RecoveredCallSitesTest \
    --tests decompengine.project.ProgramModelTest \
    --tests decompengine.project.GhidraProgramModelExporterTest
```

The opt-in real test compiles a supplied assembly fixture and statically analyzes
it twice with Ghidra. It never executes the fixture binary. It checks byte-identical
models and sidecars, repeated direct calls, indirect calls, physical targets,
tail-call return-PC absence, input binding, and occupied-destination rejection.
Without the explicit environment, this real-tool test is reported as skipped.
Other tests cover closed grammar, canonical bytes, bindings, counts, target bounds,
unsigned addresses, deadline/interruption behavior and speculative callbacks.

This adds usable location-bearing candidate input, not the completed #128 scorer.
Remaining work includes raw coordinate reconciliation, cross-shard candidate/truth
joins, exact/partial/missing/fabricated reports, relocation-bound external/PLT
identity, virtual-slot evidence, normalized thunk semantics, production full-tree
scale, CLI/archive integration and authoritative release composition.
